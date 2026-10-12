from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
import ssl
import sys
import threading
import time
from urllib.error import HTTPError

import pytest

from app import kubernetes_health_client as client


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import nct_kubernetes_health_adapter as adapter  # noqa: E402


LABELS = {
    "app.kubernetes.io/name": "nct-analysis",
    "app.kubernetes.io/component": "analysis",
}


def deployment() -> dict:
    return {
        "metadata": {
            "name": "nct-analysis",
            "namespace": "nct",
            "uid": "deployment-uid-12345678",
            "labels": LABELS,
        },
        "spec": {"replicas": 1},
    }


def replica_set(*, owner_uid: str = "deployment-uid-12345678") -> dict:
    return {
        "metadata": {
            "name": "nct-analysis-abcdef",
            "uid": "replicaset-uid-12345678",
            "labels": LABELS,
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": "nct-analysis",
                "uid": owner_uid,
                "controller": True,
            }],
        }
    }


def pod(*, owner_uid: str = "replicaset-uid-12345678", ready: bool = True, name: str = "nct-analysis-abcdef-12345") -> dict:
    return {
        "metadata": {
            "name": name,
            "uid": "pod-uid-12345678",
            "labels": LABELS,
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "name": "nct-analysis-abcdef",
                "uid": owner_uid,
                "controller": True,
            }],
        },
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
        },
    }


def metrics() -> dict:
    return {
        "metadata": {"name": "nct-analysis-abcdef-12345"},
        "containers": [{"name": "nct", "usage": {"cpu": "125m", "memory": "64Mi"}}],
    }


class FakeApi:
    def __init__(self, *, rs: list[dict] | None = None, pods: list[dict] | None = None, metric_error: str | None = None, metric_items: list[dict] | None = None):
        self.rs = [replica_set()] if rs is None else rs
        self.pods = [pod()] if pods is None else pods
        self.metric_error = metric_error
        self.metric_items = [metrics()] if metric_items is None else metric_items
        self.paths: list[str] = []

    def get(self, path: str, _budget, *, list_response: bool) -> dict:
        self.paths.append(path)
        if "/deployments/" in path:
            return deployment()
        if "/replicasets?" in path:
            return {"metadata": {}, "items": self.rs}
        if "/metrics.k8s.io/" in path:
            if self.metric_error:
                raise adapter.AdapterError(self.metric_error)
            return {"metadata": {}, "items": self.metric_items}
        if "/pods?" in path:
            return {"metadata": {}, "items": self.pods}
        raise AssertionError(path)


def test_snapshot_follows_ownership_and_returns_only_coarse_aggregate() -> None:
    api = FakeApi()

    result = adapter._snapshot(api, "nct-analysis", "nct", True)

    assert result["status"] == "available"
    assert result["deployment"] == {
        "status": "available",
        "expected_instances": 1,
        "instances_found": 1,
        "ready_instances": 1,
        "starting_or_not_ready": 0,
        "ending": 0,
    }
    assert result["metrics"] == {
        "status": "available",
        "reported_instances": 1,
        "observed_instances": 1,
        "cpu_millicores": 125,
        "memory_bytes": 64 * 1024**2,
    }
    encoded = json.dumps(result)
    for secret_detail in ("nct-analysis-abcdef", "deployment-uid", "pod-uid", "nodeName", "image"):
        assert secret_detail not in encoded
    assert all("labelSelector=" in path for path in api.paths if "?" in path)


@pytest.mark.parametrize(
    "api",
    (
        FakeApi(rs=[replica_set(owner_uid="other-deployment")]),
        FakeApi(pods=[pod(owner_uid="other-replicaset")]),
        FakeApi(rs=[]),
    ),
)
def test_spoofed_or_unowned_objects_fail_closed(api: FakeApi) -> None:
    with pytest.raises(adapter.AdapterError, match="invalid_response"):
        adapter._snapshot(api, "nct-analysis", "nct", False)


@pytest.mark.parametrize("reason", ("access_denied", "api_unavailable", "timeout"))
def test_missing_metrics_is_partial_without_erasing_deployment(reason: str) -> None:
    result = adapter._snapshot(FakeApi(metric_error=reason), "nct-analysis", "nct", True)
    assert result["status"] == "partial"
    assert result["deployment"]["ready_instances"] == 1
    assert result["metrics"] == {"status": "unavailable"}


def test_metrics_are_separate_and_disabled_by_default() -> None:
    api = FakeApi()
    result = adapter._snapshot(api, "nct-analysis", "nct", False)
    assert result["status"] == "partial"
    assert result["metrics"] == {"status": "unavailable"}
    assert not any("metrics.k8s.io" in path for path in api.paths)


def test_incomplete_metric_coverage_withholds_zero_and_partial_aggregates() -> None:
    api = FakeApi(
        pods=[pod(), pod(name="nct-analysis-abcdef-67890")],
        metric_items=[metrics()],
    )
    result = adapter._snapshot(api, "nct-analysis", "nct", True)
    assert result["status"] == "partial"
    assert result["deployment"]["instances_found"] == 2
    assert result["metrics"] == {"status": "unavailable"}


def test_ready_condition_requires_running_phase() -> None:
    completed = pod()
    completed["status"]["phase"] = "Succeeded"
    result = adapter._snapshot(FakeApi(pods=[completed]), "nct-analysis", "nct", False)
    assert result["deployment"]["ready_instances"] == 0
    assert result["deployment"]["starting_or_not_ready"] == 1


def test_tiny_nonzero_cpu_quantity_does_not_render_as_zero() -> None:
    assert adapter._quantity("1n", cpu=True) == 1


def test_client_rejects_inconsistent_or_oversized_values() -> None:
    valid = {
        "schema_version": 1,
        "status": "available",
        "sampled_at": "2026-10-12T12:00:00+00:00",
        "deployment": {
            "status": "available",
            "expected_instances": 1,
            "instances_found": 1,
            "ready_instances": 1,
            "starting_or_not_ready": 0,
            "ending": 0,
        },
        "metrics": {
            "status": "available",
            "reported_instances": 1,
            "observed_instances": 1,
            "cpu_millicores": 125,
            "memory_bytes": 64 * 1024**2,
        },
    }
    result = client._validate_snapshot(valid)
    assert result["last_successful_sampled_at"] == valid["sampled_at"]
    invalid = json.loads(json.dumps(valid))
    invalid["deployment"]["ready_instances"] = 2
    with pytest.raises(ValueError, match="inconsistent"):
        client._validate_snapshot(invalid)
    invalid = json.loads(json.dumps(valid))
    invalid["metrics"]["memory_bytes"] = 2**63
    with pytest.raises(ValueError, match="metric"):
        client._validate_snapshot(invalid)


def test_disabled_client_does_not_start_a_cluster_request(monkeypatch) -> None:
    monkeypatch.delenv("NCT_KUBERNETES_HEALTH_ENABLED", raising=False)
    called = False

    def fail(*_args):
        nonlocal called
        called = True
        raise AssertionError("cluster request should not run")

    monkeypatch.setattr(client, "_read_adapter", fail)
    result = client.KubernetesHealthClient().snapshot()
    assert result["status"] == "not_configured"
    assert called is False


def test_api_budget_rejects_pagination_and_excess_items() -> None:
    budget = adapter._Budget()
    with pytest.raises(adapter.AdapterError, match="too_many_items"):
        budget.account(1, adapter.LIST_LIMIT * 3 + 2)


class FakeResponse:
    def __init__(self, value: object, *, headers: dict | None = None):
        self.status = 200
        self.payload = json.dumps(value).encode()
        self.headers = headers or {"Content-Length": str(len(self.payload))}
        self.position = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def getheader(self, name: str):
        return self.headers.get(name)

    def read(self, limit: int) -> bytes:
        chunk = self.payload[self.position:self.position + limit]
        self.position += len(chunk)
        return chunk

    def read1(self, limit: int) -> bytes:
        return self.read(limit)


class FakeOpener:
    def __init__(self, response=None, error: Exception | None = None):
        self.response = response
        self.error = error

    def open(self, request, timeout):
        if self.error:
            raise self.error
        return self.response


@pytest.mark.parametrize(
    "value",
    (
        {"metadata": {"continue": "next-page"}, "items": []},
        {"metadata": {}, "items": [{}] * (adapter.LIST_LIMIT + 1)},
        {"metadata": {}, "items": "not-a-list"},
    ),
)
def test_api_rejects_pagination_item_overflow_and_malformed_lists(value: object) -> None:
    api = adapter._Api("127.0.0.1", 443, "token", ssl.create_default_context())
    api.opener = FakeOpener(FakeResponse(value))
    with pytest.raises(adapter.AdapterError):
        api.get("/fixed", adapter._Budget(), list_response=True)


def test_api_maps_denial_timeout_and_oversize_without_raw_details() -> None:
    api = adapter._Api("127.0.0.1", 443, "token", ssl.create_default_context())
    api.opener = FakeOpener(error=HTTPError("https://fixed", 403, "secret detail", {}, BytesIO()))
    with pytest.raises(adapter.AdapterError, match="access_denied"):
        api.get("/fixed", adapter._Budget(), list_response=True)
    api.opener = FakeOpener(error=TimeoutError("internal destination"))
    with pytest.raises(adapter.AdapterError, match="timeout"):
        api.get("/fixed", adapter._Budget(), list_response=True)
    api.opener = FakeOpener(FakeResponse({"metadata": {}, "items": []}, headers={"Content-Length": str(adapter.MAX_RESPONSE_BYTES + 1)}))
    with pytest.raises(adapter.AdapterError, match="too_many_items"):
        api.get("/fixed", adapter._Budget(), list_response=True)


def test_api_streaming_read_enforces_total_deadline(monkeypatch) -> None:
    moments = iter((0.0, 0.1, 0.2, 0.3, 3.0))
    monkeypatch.setattr(adapter.time, "monotonic", lambda: next(moments))
    budget = adapter._Budget()
    api = adapter._Api("127.0.0.1", 443, "token", ssl.create_default_context())
    api.opener = FakeOpener(FakeResponse({"metadata": {}, "items": []}))
    with pytest.raises(adapter.AdapterError, match="timeout"):
        api.get("/fixed", budget, list_response=True)


def test_provider_single_flights_concurrent_requests(monkeypatch) -> None:
    provider = adapter.Provider()
    calls = 0
    started = threading.Event()
    release = threading.Event()

    def fake_api():
        return object(), "nct-analysis", "nct", False

    def fake_snapshot(*_args):
        nonlocal calls
        calls += 1
        started.set()
        release.wait(1)
        return {
            "schema_version": 1,
            "status": "partial",
            "sampled_at": "2026-10-12T12:00:00+00:00",
            "deployment": {"status": "available"},
            "metrics": {"status": "unavailable"},
        }

    monkeypatch.setattr(provider, "_api", fake_api)
    monkeypatch.setattr(adapter, "_snapshot", fake_snapshot)
    results: list[dict] = []
    first = threading.Thread(target=lambda: results.append(provider.snapshot()))
    second = threading.Thread(target=lambda: results.append(provider.snapshot()))
    first.start()
    assert started.wait(1)
    second.start()
    time.sleep(0.02)
    release.set()
    first.join(1)
    second.join(1)
    assert calls == 1
    assert len(results) == 2
    assert all(result["status"] == "partial" for result in results)


def test_expired_waiter_never_receives_stale_available_as_current(monkeypatch) -> None:
    provider = adapter.Provider()
    provider._cached = {
        "schema_version": 1,
        "status": "available",
        "sampled_at": "2026-10-12T12:00:00+00:00",
        "deployment": {"status": "available"},
        "metrics": {"status": "available"},
    }
    provider._cached_at = 1.0
    provider._sampling = True
    monkeypatch.setattr(adapter.time, "monotonic", lambda: adapter.CACHE_SECONDS + 2.0)
    monkeypatch.setattr(provider._condition, "wait", lambda timeout: False)

    result = provider.snapshot()

    assert result["status"] == "unavailable"
    assert result["reason"] == "timeout"


def test_client_retains_last_success_time_when_adapter_later_fails(monkeypatch) -> None:
    values = iter([
        {
            "provider": "kubernetes",
            "status": "partial",
            "sampled_at": "2026-10-12T12:00:00+00:00",
            "last_successful_sampled_at": "2026-10-12T12:00:00+00:00",
            "deployment": {"status": "available"},
            "metrics": {"status": "unavailable"},
        },
        OSError("adapter stopped"),
    ])

    def read(*_args):
        value = next(values)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(client, "_read_adapter", read)
    health = client.KubernetesHealthClient()
    first = health._sample_once("nct-analysis", "nct")
    second = health._sample_once("nct-analysis", "nct")
    assert first["status"] == "partial"
    assert second["status"] == "unavailable"
    assert second["last_successful_sampled_at"] == "2026-10-12T12:00:00+00:00"


def test_nct_client_streaming_read_enforces_total_deadline(monkeypatch) -> None:
    valid = {
        "schema_version": 1,
        "status": "partial",
        "sampled_at": "2026-10-12T12:00:00+00:00",
        "deployment": {
            "status": "available", "expected_instances": 1, "instances_found": 1,
            "ready_instances": 1, "starting_or_not_ready": 0, "ending": 0,
        },
        "metrics": {"status": "unavailable"},
    }
    response = FakeResponse(valid)

    class Sock:
        def settimeout(self, _value):
            pass

    class Connection:
        def __init__(self, *_args, **_kwargs):
            self.sock = Sock()

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return response

        def close(self):
            pass

    moments = iter((0.0, 0.1, 0.2, 0.3, 2.0))
    monkeypatch.setattr(client.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(client.http.client, "HTTPConnection", Connection)
    with pytest.raises(TimeoutError):
        client._read_adapter("nct-analysis", "nct")

