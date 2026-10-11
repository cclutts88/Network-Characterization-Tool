from __future__ import annotations

import os

from fastapi import HTTPException


ACTIVE_COLLECTION_ENV = "NCT_ACTIVE_COLLECTION_MODE"
ENABLED = "enabled"
DISABLED = "disabled"
DISABLED_DETAIL = (
    "Active scanning and device collection are unavailable in this analysis-only "
    "deployment. Import retained evidence for analysis or use an approved collection "
    "worker outside this profile."
)


def active_collection_mode() -> str:
    value = os.environ.get(ACTIVE_COLLECTION_ENV, ENABLED).strip().lower()
    if value not in {ENABLED, DISABLED}:
        raise RuntimeError(
            f"{ACTIVE_COLLECTION_ENV} must be either {ENABLED!r} or {DISABLED!r}"
        )
    return value


def active_collection_enabled() -> bool:
    return active_collection_mode() == ENABLED


def active_collection_status() -> dict:
    enabled = active_collection_enabled()
    return {
        "enabled": enabled,
        "mode": ENABLED if enabled else "analysis_only",
        "detail": (
            "This deployment can start authorized scans and device collections."
            if enabled
            else DISABLED_DETAIL
        ),
    }


def deployment_profile_status() -> dict:
    profile = os.environ.get("NCT_DEPLOYMENT_PROFILE", "standalone").strip().lower()
    if profile == "kubernetes_single_replica_analysis":
        return {
            "profile": profile,
            "label": "Kubernetes · one replica · analysis only",
            "replicas": 1,
        }
    return {"profile": "standalone", "label": "Standalone", "replicas": 1}


def require_active_collection() -> None:
    if not active_collection_enabled():
        raise HTTPException(status_code=503, detail=DISABLED_DETAIL)
