#!/usr/bin/env python3
"""Serve bounded, sanitized, read-only Kubernetes status for NCT System Health."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request


SCHEMA_VERSION = 1
LIST_LIMIT = 32
MAX_REQUESTS = 4
MAX_RESPONSE_BYTES = 262_144
MAX_TOTAL_BYTES = 524_288
MAX_OWNER_REFERENCES = 8
MAX_CONTAINERS = 32
TOTAL_TIMEOUT_SECONDS = 2.5
REQUEST_TIMEOUT_SECONDS = 1.0
CACHE_SECONDS = 15.0
TOKEN_MAX_BYTES = 16_384
FIELD_MAX_CHARS = 253
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
DNS_NAME = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$"
)
QUANTITY = re.compile(r"^(?P<number>[0-9]+(?:\.[0-9]+)?)(?P<suffix>[numkKMGTPE]i?)?$")
TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
NAMESPACE_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")


class AdapterError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes"}


def _fixed_text(path: Path, limit: int) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            value = handle.read(limit + 1)
    except (OSError, UnicodeError) as exc:
        raise AdapterError("api_unavailable") from exc
    if not value or len(value) > limit:
        raise AdapterError("invalid_response")
    return value.strip()


def _api_host() -> str:
    value = (os.getenv("KUBERNETES_SERVICE_HOST") or "").strip()
    if not value or len(value) > FIELD_MAX_CHARS or any(char in value for char in "/?#@"):
        raise AdapterError("invalid_response")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not DNS_NAME.fullmatch(value.lower()):
            raise AdapterError("invalid_response")
    return value


def _configuration() -> tuple[str, str, int, bool]:
    name = (os.getenv("NCT_KUBERNETES_NAME") or "").strip()
    configured_namespace = (os.getenv("NCT_KUBERNETES_NAMESPACE") or "").strip()
    mounted_namespace = _fixed_text(NAMESPACE_PATH, 63)
    if not DNS_LABEL.fullmatch(name):
        raise AdapterError("invalid_response")
    if not DNS_LABEL.fullmatch(configured_namespace) or configured_namespace != mounted_namespace:
        raise AdapterError("invalid_response")
    port_text = (os.getenv("KUBERNETES_SERVICE_PORT_HTTPS") or "443").strip()
    if not port_text.isdigit() or not (1 <= int(port_text) <= 65535):
        raise AdapterError("invalid_response")
    return name, configured_namespace, int(port_text), _enabled(os.getenv("NCT_KUBERNETES_METRICS_ENABLED"))


def _bounded_text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > FIELD_MAX_CHARS:
        raise AdapterError("invalid_response")
    return value


def _nonnegative_int(value: object, default: int = 0) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10_000:
        raise AdapterError("invalid_response")
    return value


def _labels(metadata: dict, name: str) -> None:
    labels = metadata.get("labels")
    if not isinstance(labels, dict):
        raise AdapterError("invalid_response")
    if labels.get("app.kubernetes.io/name") != name or labels.get("app.kubernetes.io/component") != "analysis":
        raise AdapterError("invalid_response")


def _owner(metadata: dict, *, kind: str, uid: str, name: str | None = None) -> None:
    owners = metadata.get("ownerReferences")
    if not isinstance(owners, list) or not owners or len(owners) > MAX_OWNER_REFERENCES:
        raise AdapterError("invalid_response")
    matching = [
        item for item in owners
        if isinstance(item, dict)
        and item.get("apiVersion") == "apps/v1"
        and item.get("kind") == kind
        and item.get("uid") == uid
        and item.get("controller") is True
        and (name is None or item.get("name") == name)
    ]
    if len(matching) != 1:
        raise AdapterError("invalid_response")


class _Budget:
    def __init__(self) -> None:
        self.deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
        self.requests = 0
        self.bytes = 0
        self.objects = 0

    def timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise AdapterError("timeout")
        return min(REQUEST_TIMEOUT_SECONDS, remaining)

    def check(self) -> None:
        if time.monotonic() > self.deadline:
            raise AdapterError("timeout")

    def account(self, payload_size: int, objects: int) -> None:
        self.requests += 1
        self.bytes += payload_size
        self.objects += objects
        if self.requests > MAX_REQUESTS or self.bytes > MAX_TOTAL_BYTES or self.objects > LIST_LIMIT * 3 + 1:
            raise AdapterError("too_many_items")


class _Api:
    def __init__(self, host: str, port: int, token: str, context: ssl.SSLContext) -> None:
        self.base = f"https://{f'[{host}]' if ':' in host else host}:{port}"
        self.token = token
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())

    def get(self, path: str, budget: _Budget, *, list_response: bool) -> dict:
        request = Request(
            self.base + path,
            headers={"Accept": "application/json", "Authorization": f"Bearer {self.token}"},
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=budget.timeout()) as response:
                budget.check()
                if response.status != 200:
                    raise AdapterError("api_unavailable")
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    try:
                        declared_size = int(declared)
                    except ValueError as exc:
                        raise AdapterError("invalid_response") from exc
                    if declared_size < 0 or declared_size > MAX_RESPONSE_BYTES:
                        raise AdapterError("too_many_items")
                chunks: list[bytes] = []
                payload_size = 0
                while True:
                    timeout = budget.timeout()
                    raw = getattr(getattr(response, "fp", None), "raw", None)
                    sock = getattr(raw, "_sock", None)
                    if sock is not None:
                        sock.settimeout(timeout)
                    reader = getattr(response, "read1", None)
                    chunk = reader(8192) if reader is not None else response.read(1)
                    budget.check()
                    if not chunk:
                        break
                    payload_size += len(chunk)
                    if payload_size > MAX_RESPONSE_BYTES:
                        raise AdapterError("too_many_items")
                    chunks.append(chunk)
                payload = b"".join(chunks)
        except HTTPError as exc:
            raise AdapterError("access_denied" if exc.code in {401, 403} else "api_unavailable") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise AdapterError("timeout") from exc
        except (OSError, URLError) as exc:
            raise AdapterError("api_unavailable") from exc
        if len(payload) > MAX_RESPONSE_BYTES:
            raise AdapterError("too_many_items")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AdapterError("invalid_response") from exc
        if not isinstance(value, dict):
            raise AdapterError("invalid_response")
        objects = 1
        if list_response:
            items = value.get("items")
            metadata = value.get("metadata")
            if not isinstance(items, list) or len(items) > LIST_LIMIT or not isinstance(metadata, dict):
                raise AdapterError("too_many_items" if isinstance(items, list) else "invalid_response")
            if metadata.get("continue") not in {None, ""}:
                raise AdapterError("too_many_items")
            objects = len(items)
        budget.account(len(payload), objects)
        return value


def _ready(metadata: dict, status: dict) -> bool:
    if metadata.get("deletionTimestamp") is not None:
        return False
    if status.get("phase") != "Running":
        return False
    conditions = status.get("conditions")
    if not isinstance(conditions, list) or len(conditions) > 32:
        raise AdapterError("invalid_response")
    return any(
        isinstance(item, dict)
        and item.get("type") == "Ready"
        and item.get("status") == "True"
        for item in conditions
    )


def _quantity(value: object, *, cpu: bool) -> int:
    if not isinstance(value, str) or len(value) > 32:
        raise AdapterError("invalid_response")
    match = QUANTITY.fullmatch(value)
    if match is None:
        raise AdapterError("invalid_response")
    try:
        number = Decimal(match.group("number"))
    except InvalidOperation as exc:
        raise AdapterError("invalid_response") from exc
    suffix = match.group("suffix") or ""
    if cpu:
        factors = {"": Decimal(1000), "m": Decimal(1), "u": Decimal("0.001"), "n": Decimal("0.000001")}
    else:
        factors = {
            "": Decimal(1), "k": Decimal(1000), "K": Decimal(1000), "M": Decimal(1000**2),
            "G": Decimal(1000**3), "T": Decimal(1000**4), "P": Decimal(1000**5),
            "E": Decimal(1000**6), "Ki": Decimal(1024), "Mi": Decimal(1024**2),
            "Gi": Decimal(1024**3), "Ti": Decimal(1024**4), "Pi": Decimal(1024**5),
            "Ei": Decimal(1024**6),
        }
    factor = factors.get(suffix)
    if factor is None:
        raise AdapterError("invalid_response")
    measured = number * factor
    result = int(measured.to_integral_value(rounding=ROUND_CEILING))
    if result < 0 or result > 2**63 - 1:
        raise AdapterError("invalid_response")
    return result


def _snapshot(api: _Api, name: str, namespace: str, metrics_enabled: bool) -> dict:
    budget = _Budget()
    selector = quote(f"app.kubernetes.io/name={name},app.kubernetes.io/component=analysis", safe="")
    prefix = f"/apis/apps/v1/namespaces/{namespace}"
    deployment = api.get(f"{prefix}/deployments/{name}", budget, list_response=False)
    metadata = deployment.get("metadata")
    spec = deployment.get("spec")
    if not isinstance(metadata, dict) or not isinstance(spec, dict):
        raise AdapterError("invalid_response")
    _labels(metadata, name)
    if metadata.get("name") != name or metadata.get("namespace") != namespace:
        raise AdapterError("invalid_response")
    deployment_uid = _bounded_text(metadata.get("uid"))
    expected = _nonnegative_int(spec.get("replicas"))

    replica_response = api.get(
        f"{prefix}/replicasets?labelSelector={selector}&limit={LIST_LIMIT}", budget, list_response=True,
    )
    replica_uids: set[str] = set()
    for item in replica_response["items"]:
        if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict):
            raise AdapterError("invalid_response")
        item_metadata = item["metadata"]
        _labels(item_metadata, name)
        _owner(item_metadata, kind="Deployment", uid=deployment_uid, name=name)
        uid = _bounded_text(item_metadata.get("uid"))
        if uid in replica_uids:
            raise AdapterError("invalid_response")
        replica_uids.add(uid)

    pod_response = api.get(
        f"/api/v1/namespaces/{namespace}/pods?labelSelector={selector}&limit={LIST_LIMIT}",
        budget,
        list_response=True,
    )
    pod_names: set[str] = set()
    ready = 0
    ending = 0
    for item in pod_response["items"]:
        if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict) or not isinstance(item.get("status"), dict):
            raise AdapterError("invalid_response")
        item_metadata = item["metadata"]
        _labels(item_metadata, name)
        if not replica_uids:
            raise AdapterError("invalid_response")
        owners = item_metadata.get("ownerReferences")
        if not isinstance(owners, list) or len(owners) > MAX_OWNER_REFERENCES:
            raise AdapterError("invalid_response")
        owned = [
            owner for owner in owners
            if isinstance(owner, dict)
            and owner.get("apiVersion") == "apps/v1"
            and owner.get("kind") == "ReplicaSet"
            and owner.get("uid") in replica_uids
            and owner.get("controller") is True
        ]
        if len(owned) != 1:
            raise AdapterError("invalid_response")
        pod_name = _bounded_text(item_metadata.get("name"))
        if pod_name in pod_names:
            raise AdapterError("invalid_response")
        pod_names.add(pod_name)
        if item_metadata.get("deletionTimestamp") is not None:
            ending += 1
        elif _ready(item_metadata, item["status"]):
            ready += 1
    found = len(pod_names)
    deployment_result = {
        "status": "available",
        "expected_instances": expected,
        "instances_found": found,
        "ready_instances": ready,
        "starting_or_not_ready": found - ready - ending,
        "ending": ending,
    }

    if not metrics_enabled:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "partial",
            "sampled_at": _utc_now(),
            "deployment": deployment_result,
            "metrics": {"status": "unavailable"},
        }
    try:
        metric_response = api.get(
            f"/apis/metrics.k8s.io/v1beta1/namespaces/{namespace}/pods?labelSelector={selector}&limit={LIST_LIMIT}",
            budget,
            list_response=True,
        )
        metric_names: set[str] = set()
        cpu_total = 0
        memory_total = 0
        for item in metric_response["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict):
                raise AdapterError("invalid_response")
            pod_name = _bounded_text(item["metadata"].get("name"))
            if pod_name not in pod_names or pod_name in metric_names:
                raise AdapterError("invalid_response")
            metric_names.add(pod_name)
            containers = item.get("containers")
            if not isinstance(containers, list) or len(containers) > MAX_CONTAINERS:
                raise AdapterError("invalid_response")
            for container in containers:
                usage = container.get("usage") if isinstance(container, dict) else None
                if not isinstance(usage, dict):
                    raise AdapterError("invalid_response")
                cpu_total += _quantity(usage.get("cpu"), cpu=True)
                memory_total += _quantity(usage.get("memory"), cpu=False)
        if not pod_names or metric_names != pod_names:
            metrics = {"status": "unavailable"}
            status = "partial"
        else:
            metrics = {
                "status": "available",
                "reported_instances": len(metric_names),
                "observed_instances": found,
                "cpu_millicores": cpu_total,
                "memory_bytes": memory_total,
            }
            status = "available"
    except AdapterError as exc:
        if exc.reason not in {"access_denied", "api_unavailable", "timeout"}:
            raise
        metrics = {"status": "unavailable"}
        status = "partial"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "sampled_at": _utc_now(),
        "deployment": deployment_result,
        "metrics": metrics,
    }


class Provider:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._sampling = False
        self._cached: dict | None = None
        self._cached_at = 0.0

    def _api(self) -> tuple[_Api, str, str, bool]:
        name, namespace, port, metrics_enabled = _configuration()
        token = _fixed_text(TOKEN_PATH, TOKEN_MAX_BYTES)
        try:
            context = ssl.create_default_context(cafile=str(CA_PATH))
        except (OSError, ssl.SSLError) as exc:
            raise AdapterError("api_unavailable") from exc
        return _Api(_api_host(), port, token, context), name, namespace, metrics_enabled

    def snapshot(self) -> dict:
        with self._condition:
            now = time.monotonic()
            if self._cached is not None and now - self._cached_at < CACHE_SECONDS:
                return deepcopy(self._cached)
            if self._sampling:
                previous_cache_time = self._cached_at
                self._condition.wait(timeout=TOTAL_TIMEOUT_SECONDS + 0.25)
                if (
                    not self._sampling
                    and self._cached is not None
                    and self._cached_at > previous_cache_time
                ):
                    return deepcopy(self._cached)
                return _unavailable("timeout")
            self._sampling = True
        try:
            api, name, namespace, metrics_enabled = self._api()
            value = _snapshot(api, name, namespace, metrics_enabled)
        except AdapterError as exc:
            value = _unavailable(exc.reason)
        finally:
            with self._condition:
                self._cached = value
                self._cached_at = time.monotonic()
                self._sampling = False
                self._condition.notify_all()
        return deepcopy(value)


def _unavailable(reason: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "unavailable",
        "sampled_at": _utc_now(),
        "reason": reason if reason in {
            "access_denied", "api_unavailable", "invalid_response", "missing_workload",
            "timeout", "too_many_items",
        } else "api_unavailable",
        "deployment": {"status": "unavailable"},
        "metrics": {"status": "unavailable"},
    }


PROVIDER = Provider()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NCT-Kubernetes-Health/1"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path == "/healthz":
            value = {"status": "ok"}
        elif self.path == "/snapshot":
            value = PROVIDER.snapshot()
        else:
            self.send_error(404)
            return
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8090), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
