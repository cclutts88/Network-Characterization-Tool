"""Non-blocking client for the optional, isolated Kubernetes status adapter."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import http.client
import json
import os
import re
import socket
import threading
import time


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_MAX_RESPONSE_BYTES = 65_536
_REQUEST_TIMEOUT_SECONDS = 1.0
_REFRESH_SECONDS = 15.0
_ALLOWED_REASONS = {
    "access_denied",
    "api_unavailable",
    "invalid_response",
    "missing_workload",
    "timeout",
    "too_many_items",
}


def _enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes"}


def _unavailable(reason: str = "api_unavailable") -> dict:
    return {
        "provider": "kubernetes",
        "status": "unavailable",
        "sampled_at": None,
        "last_successful_sampled_at": None,
        "reason": reason if reason in _ALLOWED_REASONS else "api_unavailable",
        "deployment": {"status": "unavailable"},
        "metrics": {"status": "unavailable"},
    }


def _not_configured() -> dict:
    return {
        "provider": "kubernetes",
        "status": "not_configured",
        "sampled_at": None,
        "last_successful_sampled_at": None,
        "deployment": {"status": "not_configured"},
        "metrics": {"status": "not_configured"},
    }


def _bounded_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10_000 else None


def _bounded_metric(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63 - 1 else None


def _valid_timestamp(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if parsed.tzinfo is not None else None


def _validate_snapshot(value: object) -> dict:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("invalid adapter response")
    status = value.get("status")
    if status not in {"available", "partial", "unavailable"}:
        raise ValueError("invalid adapter status")
    sampled_at = _valid_timestamp(value.get("sampled_at"))
    if sampled_at is None:
        raise ValueError("invalid adapter sample time")
    deployment = value.get("deployment")
    metrics = value.get("metrics")
    if not isinstance(deployment, dict) or not isinstance(metrics, dict):
        raise ValueError("invalid adapter sections")
    if status == "unavailable":
        reason = value.get("reason")
        if reason not in _ALLOWED_REASONS or deployment.get("status") != "unavailable":
            raise ValueError("invalid unavailable adapter response")
        return {
            **_unavailable(reason),
            "sampled_at": sampled_at,
        }
    if deployment.get("status") != "available":
        raise ValueError("deployment status is not available")
    deployment_result = {"status": "available"}
    for key in (
        "expected_instances", "instances_found", "ready_instances",
        "starting_or_not_ready", "ending",
    ):
        parsed = _bounded_int(deployment.get(key))
        if parsed is None:
            raise ValueError("invalid deployment count")
        deployment_result[key] = parsed
    found = deployment_result["instances_found"]
    if (
        deployment_result["ready_instances"]
        + deployment_result["starting_or_not_ready"]
        + deployment_result["ending"]
        != found
    ):
        raise ValueError("inconsistent deployment counts")
    metrics_status = metrics.get("status")
    if status == "available" and metrics_status != "available":
        raise ValueError("available adapter omitted metrics")
    if status == "partial" and metrics_status != "unavailable":
        raise ValueError("partial adapter must mark metrics unavailable")
    if metrics_status == "available":
        metrics_result = {"status": "available"}
        for key in ("reported_instances", "observed_instances"):
            parsed = _bounded_int(metrics.get(key))
            if parsed is None:
                raise ValueError("invalid metric value")
            metrics_result[key] = parsed
        for key in ("cpu_millicores", "memory_bytes"):
            parsed = _bounded_metric(metrics.get(key))
            if parsed is None:
                raise ValueError("invalid metric value")
            metrics_result[key] = parsed
        if metrics_result["reported_instances"] > metrics_result["observed_instances"]:
            raise ValueError("inconsistent metric coverage")
        if metrics_result["observed_instances"] != found:
            raise ValueError("metric coverage does not match deployment")
    elif metrics_status == "unavailable":
        metrics_result = {"status": "unavailable"}
    else:
        raise ValueError("invalid metrics status")
    return {
        "provider": "kubernetes",
        "status": status,
        "sampled_at": sampled_at,
        "last_successful_sampled_at": sampled_at,
        "deployment": deployment_result,
        "metrics": metrics_result,
    }


def _read_adapter(name: str, namespace: str) -> dict:
    suffix = "health-adapter"
    service_name = f"{name[: 63 - len(suffix) - 1].rstrip('-')}-{suffix}"
    host = f"{service_name}.{namespace}.svc"
    connection = http.client.HTTPConnection(host, 8090, timeout=_REQUEST_TIMEOUT_SECONDS)
    deadline = time.monotonic() + _REQUEST_TIMEOUT_SECONDS

    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise socket.timeout("adapter deadline exceeded")
        return value

    try:
        connection.request("GET", "/snapshot", headers={"Accept": "application/json"})
        if connection.sock is not None:
            connection.sock.settimeout(remaining())
        response = connection.getresponse()
        remaining()
        if response.status != 200:
            raise ValueError("adapter request failed")
        declared = response.getheader("Content-Length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError as exc:
                raise ValueError("invalid response length") from exc
            if declared_size < 0 or declared_size > _MAX_RESPONSE_BYTES:
                raise ValueError("adapter response is too large")
        chunks: list[bytes] = []
        payload_size = 0
        while True:
            if connection.sock is not None:
                connection.sock.settimeout(remaining())
            reader = getattr(response, "read1", None)
            chunk = reader(8192) if reader is not None else response.read(1)
            remaining()
            if not chunk:
                break
            payload_size += len(chunk)
            if payload_size > _MAX_RESPONSE_BYTES:
                raise ValueError("adapter response is too large")
            chunks.append(chunk)
        payload = b"".join(chunks)
        return _validate_snapshot(json.loads(payload.decode("utf-8")))
    finally:
        connection.close()


class KubernetesHealthClient:
    """Caches adapter status and samples it on one background thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_success: str | None = None
        self._value = _not_configured()

    @staticmethod
    def _configuration() -> tuple[bool, str | None, str | None]:
        if not _enabled(os.getenv("NCT_KUBERNETES_HEALTH_ENABLED")):
            return False, None, None
        name = (os.getenv("NCT_KUBERNETES_NAME") or "").strip()
        namespace = (os.getenv("NCT_KUBERNETES_NAMESPACE") or "").strip()
        if not _DNS_LABEL.fullmatch(name) or not _DNS_LABEL.fullmatch(namespace):
            return True, None, None
        return True, name, namespace

    def _sample_once(self, name: str, namespace: str) -> dict:
        try:
            result = _read_adapter(name, namespace)
        except socket.timeout:
            result = _unavailable("timeout")
        except (ConnectionError, OSError, UnicodeError, ValueError, json.JSONDecodeError):
            result = _unavailable("api_unavailable")
        if result["status"] in {"available", "partial"}:
            self._last_success = result["sampled_at"]
        elif self._last_success:
            result["last_successful_sampled_at"] = self._last_success
        return result

    def _run(self, name: str, namespace: str) -> None:
        while True:
            result = self._sample_once(name, namespace)
            with self._lock:
                self._value = result
            self._wake.wait(_REFRESH_SECONDS)
            self._wake.clear()

    def snapshot(self) -> dict:
        enabled, name, namespace = self._configuration()
        if not enabled:
            return _not_configured()
        if name is None or namespace is None:
            return _unavailable("invalid_response")
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._value = _unavailable("api_unavailable")
                self._thread = threading.Thread(
                    target=self._run,
                    args=(name, namespace),
                    name="nct-kubernetes-health",
                    daemon=True,
                )
                self._thread.start()
            return deepcopy(self._value)


_CLIENT = KubernetesHealthClient()


def kubernetes_health_snapshot() -> dict:
    return _CLIENT.snapshot()
