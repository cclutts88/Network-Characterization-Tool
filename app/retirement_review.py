"""Short-lived, server-authenticated operator retirement reviews."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from app.evidence_retirement import EvidenceRetirementError


_KEY = secrets.token_bytes(32)
_TTL_SECONDS = 10 * 60
_MAX_TOKEN_BYTES = 4096


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_review_token(review: dict[str, object], *, actor: str) -> str:
    impact = review.get("impact")
    body = {
        "actor": str(actor),
        "source_family": str(review["source_family"]),
        "encounter_id": str(review["encounter_id"]),
        "authority_revision": int(review["authority_revision"]),
        "identity_snapshot_sha256": str(review["identity_snapshot_sha256"]),
        "impact_sha256": hashlib.sha256(_canonical(impact)).hexdigest(),
        "expires_at": int(time.time()) + _TTL_SECONDS,
        "nonce": secrets.token_hex(16),
    }
    payload = _canonical(body)
    signature = hmac.new(_KEY, payload, hashlib.sha256).digest()
    return f"{_encode(payload)}.{_encode(signature)}"


def verify_review_token(
    token: str, *, actor: str, source_family: str, encounter_id: str,
) -> dict[str, object]:
    if not isinstance(token, str) or not token or len(token.encode()) > _MAX_TOKEN_BYTES:
        raise EvidenceRetirementError("Retirement review token is invalid")
    try:
        encoded, signed = token.split(".", 1)
        payload = _decode(encoded)
        signature = _decode(signed)
        body = json.loads(payload)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceRetirementError("Retirement review token is invalid") from exc
    expected = hmac.new(_KEY, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected) or not isinstance(body, dict):
        raise EvidenceRetirementError("Retirement review token is invalid")
    required = {
        "actor", "source_family", "encounter_id", "authority_revision",
        "identity_snapshot_sha256", "impact_sha256", "expires_at", "nonce",
    }
    if set(body) != required:
        raise EvidenceRetirementError("Retirement review token is invalid")
    if (
        body["actor"] != actor
        or body["source_family"] != source_family
        or body["encounter_id"] != encounter_id
    ):
        raise EvidenceRetirementError(
            "Retirement review belongs to a different signed-in actor or encounter"
        )
    if not isinstance(body["expires_at"], int) or body["expires_at"] < int(time.time()):
        raise EvidenceRetirementError("Retirement review expired; review the source again")
    if not isinstance(body["authority_revision"], int) or body["authority_revision"] < 0:
        raise EvidenceRetirementError("Retirement review token is invalid")
    for key in ("identity_snapshot_sha256", "impact_sha256"):
        if not isinstance(body[key], str) or len(body[key]) != 64:
            raise EvidenceRetirementError("Retirement review token is invalid")
    return body
