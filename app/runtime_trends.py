"""Bounded, restart-local CPU and memory trend sampling."""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import threading
import time

from app.runtime_health import (
    _container_cpu_allowance,
    _container_cpu_usage_seconds,
    _container_memory,
    _process_memory,
)


SAMPLE_INTERVAL_SECONDS = 5.0
WINDOW_SECONDS = 3600.0
MAX_ATTEMPTS = 720
NEAR_PEAK_RATIO = 0.95
GAP_TOLERANCE_SECONDS = 7.5


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class _Series:
    def __init__(self, *, unit: str, basis: str) -> None:
        self.unit = unit
        self.basis = basis
        self.attempts: deque[tuple[float, float | None, str, str]] = deque(maxlen=MAX_ATTEMPTS)

    def reset(self, *, basis: str) -> None:
        self.basis = basis
        self.attempts.clear()

    def add(
        self,
        sampled_at: float,
        value: float | None,
        sampled_at_utc: str,
        *,
        state: str | None = None,
    ) -> None:
        if value is not None:
            state = "available"
        elif state not in {"warming_up", "unavailable"}:
            state = "unavailable"
        self.attempts.append((sampled_at, value, sampled_at_utc, state))
        cutoff = sampled_at - WINDOW_SECONDS
        while self.attempts and self.attempts[0][0] < cutoff:
            self.attempts.popleft()

    def snapshot(self) -> dict[str, object]:
        available = [
            (at, value, wall)
            for at, value, wall, _state in self.attempts
            if value is not None
        ]
        latest_state = self.attempts[-1][3] if self.attempts else "unavailable"
        result: dict[str, object] = {
            "status": "available" if available else latest_state,
            "unit": self.unit,
            "basis": self.basis,
            "window_seconds": int(WINDOW_SECONDS),
            "sample_interval_seconds": int(SAMPLE_INTERVAL_SECONDS),
            "sampling_attempts": len(self.attempts),
            "available_samples": len(available),
            "warming_up_samples": sum(1 for *_item, state in self.attempts if state == "warming_up"),
            "unavailable_samples": sum(1 for *_item, state in self.attempts if state == "unavailable"),
            "near_peak_percent": int(NEAR_PEAK_RATIO * 100),
            "current": None,
            "average": None,
            "maximum": None,
            "longest_near_peak_seconds": 0.0,
            "last_success_at": available[-1][2] if available else None,
        }
        if not available:
            return result
        values = [value for _at, value, _wall in available]
        maximum = max(values)
        result["current"] = self.attempts[-1][1]
        result["average"] = round(sum(values) / len(values), 1)
        result["maximum"] = round(maximum, 1)
        if maximum <= 0:
            return result
        threshold = maximum * NEAR_PEAK_RATIO
        longest = 0.0
        current = 0.0
        previous_at: float | None = None
        previous_qualified = False
        for sampled_at, value, _wall, _state in self.attempts:
            qualified = value is not None and value >= threshold
            if qualified and previous_qualified and previous_at is not None:
                gap = sampled_at - previous_at
                current = current + gap if 0 < gap <= GAP_TOLERANCE_SECONDS else 0.0
            elif qualified:
                current = 0.0
            else:
                current = 0.0
            longest = max(longest, current)
            previous_at = sampled_at
            previous_qualified = qualified
        result["longest_near_peak_seconds"] = round(longest, 1)
        return result

    def latest_unavailable(self) -> bool:
        return bool(self.attempts and self.attempts[-1][3] == "unavailable")


class RuntimeTrendSampler:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._state = "stopped"
        self._last_sample_at: str | None = None
        self._previous_process_cpu: tuple[float, float] | None = None
        self._previous_container_cpu: tuple[float, float] | None = None
        self._container_cpu_basis_key: tuple[str, float | None] | None = None
        self._series: dict[str, _Series] = {}
        self._reset_locked()

    def _reset_locked(self) -> None:
        self._previous_process_cpu = None
        self._previous_container_cpu = None
        self._container_cpu_basis_key = None
        self._last_sample_at = None
        self._series = {
            "process_cpu": _Series(unit="percent", basis="Percent of one CPU"),
            "container_cpu": _Series(unit="percent", basis="Percent of one CPU"),
            "process_memory": _Series(unit="bytes", basis="NCT process resident memory"),
            "container_memory": _Series(unit="bytes", basis="Linux control-group memory"),
        }

    @staticmethod
    def _cpu_delta(
        previous: tuple[float, float] | None, now: float, used: float | None,
    ) -> tuple[float | None, tuple[float, float] | None]:
        if used is None:
            return None, previous
        current = (now, used)
        if previous is None or now <= previous[0] or used < previous[1]:
            return None, current
        elapsed = now - previous[0]
        if elapsed < 0.01:
            return None, current
        return max(0.0, (used - previous[1]) / elapsed * 100), current

    @staticmethod
    def _safe(callable_, key: str) -> float | None:
        try:
            item = callable_()
            if not isinstance(item, dict) or item.get("status") != "available":
                return None
            value = item.get(key)
            return float(value) if value is not None and float(value) >= 0 else None
        except Exception:
            return None

    def sample_once(self, *, sampled_at: float | None = None, sampled_at_utc: str | None = None) -> None:
        now = time.monotonic() if sampled_at is None else float(sampled_at)
        wall = _utc_now() if sampled_at_utc is None else sampled_at_utc
        try:
            process_used = time.process_time()
        except Exception:
            process_used = None
        try:
            container_used = _container_cpu_usage_seconds()
        except Exception:
            container_used = None
        try:
            allowance = _container_cpu_allowance()
        except Exception:
            allowance = None
        process_memory = self._safe(_process_memory, "current_bytes")
        container_memory = self._safe(_container_memory, "current_bytes")

        with self._lock:
            process_cpu, self._previous_process_cpu = self._cpu_delta(
                self._previous_process_cpu, now, process_used,
            )
            process_cpu_state = (
                "available" if process_cpu is not None
                else ("warming_up" if process_used is not None else "unavailable")
            )
            container_cpu, self._previous_container_cpu = self._cpu_delta(
                self._previous_container_cpu, now, container_used,
            )
            container_cpu_state = (
                "available" if container_cpu is not None
                else ("warming_up" if container_used is not None else "unavailable")
            )
            if allowance is not None and allowance > 0:
                basis_key = ("allowance", round(float(allowance), 6))
                basis = f"Percent of {allowance:g}-CPU container allowance"
                if container_cpu is not None:
                    container_cpu /= allowance
            else:
                basis_key = ("one_cpu", None)
                basis = "Percent of one CPU"
            previous_basis_key = self._container_cpu_basis_key
            if basis_key != previous_basis_key:
                self._series["container_cpu"].reset(basis=basis)
                self._container_cpu_basis_key = basis_key
                # A CPU delta that spans two measurement bases cannot be assigned
                # truthfully to either segment. Keep the new raw baseline but record
                # the transition attempt as unavailable.
                container_cpu = None
                if previous_basis_key is not None:
                    container_cpu_state = "unavailable"
            self._series["process_cpu"].add(
                now, process_cpu, wall, state=process_cpu_state,
            )
            self._series["container_cpu"].add(
                now, container_cpu, wall, state=container_cpu_state,
            )
            self._series["process_memory"].add(
                now,
                process_memory,
                wall,
                state="available" if process_memory is not None else "unavailable",
            )
            self._series["container_memory"].add(
                now,
                container_memory,
                wall,
                state="available" if container_memory is not None else "unavailable",
            )
            self._last_sample_at = wall

    def _record_unavailable_attempt(self, sampled_at: float, sampled_at_utc: str) -> None:
        with self._lock:
            for item in self._series.values():
                item.add(sampled_at, None, sampled_at_utc, state="unavailable")
            self._last_sample_at = sampled_at_utc

    def _run(self) -> None:
        while not self._stop.is_set():
            sampled_at = time.monotonic()
            sampled_at_utc = _utc_now()
            try:
                self.sample_once(
                    sampled_at=sampled_at,
                    sampled_at_utc=sampled_at_utc,
                )
            except Exception:
                # Per-metric failures are handled inside sample_once. This final boundary
                # makes an unexpected defect a visible gap instead of leaving stale
                # values looking current or allowing an old near-peak stretch to continue.
                self._record_unavailable_attempt(sampled_at, sampled_at_utc)
            self._stop.wait(SAMPLE_INTERVAL_SECONDS)

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._reset_locked()
            self._stop = threading.Event()
            self._state = "starting"
            thread = threading.Thread(
                target=self._run, name="runtime-trend-sampler", daemon=True,
            )
            self._thread = thread
        try:
            thread.start()
        except RuntimeError:
            with self._lock:
                self._state = "failed"
            return False
        with self._lock:
            self._state = "running"
        return True

    def stop(self, timeout_seconds: float = 2.0) -> bool:
        with self._lock:
            thread = self._thread
            if thread is None:
                self._state = "stopped"
                return True
            self._stop.set()
        thread.join(timeout=max(0.0, timeout_seconds))
        stopped = not thread.is_alive()
        with self._lock:
            self._state = "stopped" if stopped else "failed"
            if stopped:
                self._thread = None
        return stopped

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            series = {name: item.snapshot() for name, item in self._series.items()}
            success_times = [
                item["last_success_at"] for item in series.values() if item["last_success_at"]
            ]
            unavailable = any(item.latest_unavailable() for item in self._series.values())
            state = self._state
            if state == "running" and unavailable:
                state = "degraded"
            return {
                "status": state,
                "retention": "memory_only",
                "window_seconds": int(WINDOW_SECONDS),
                "sample_interval_seconds": int(SAMPLE_INTERVAL_SECONDS),
                "maximum_attempts_per_metric": MAX_ATTEMPTS,
                "near_peak_percent": int(NEAR_PEAK_RATIO * 100),
                "last_sample_at": self._last_sample_at,
                "last_success_at": max(success_times) if success_times else None,
                "metrics": series,
            }


_SAMPLER = RuntimeTrendSampler()


def start_runtime_trends() -> bool:
    return _SAMPLER.start()


def stop_runtime_trends(timeout_seconds: float = 2.0) -> bool:
    return _SAMPLER.stop(timeout_seconds)


def runtime_trends_snapshot() -> dict[str, object]:
    return _SAMPLER.snapshot()
