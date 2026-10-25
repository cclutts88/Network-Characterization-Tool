"""Shared, versioned rules for device-command attribution receipts."""
from __future__ import annotations

import hashlib
import json


COMMAND_RECEIPT_SCHEMA_VERSION = 1
COMMAND_RECEIPT_EXECUTION_STATUS = "sent_in_completed_authenticated_session"
COMMAND_RECEIPT_ACKNOWLEDGEMENT = (
    "session_completed_command_not_individually_acknowledged"
)


def normalize_command_for_attribution(command: object) -> str:
    """Collapse layout whitespace outside quotes without changing quoted content."""
    text = str(command or "").strip()
    normalized: list[str] = []
    quote: str | None = None
    escaped = False
    pending_space = False
    for char in text:
        if quote is not None:
            normalized.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            if pending_space and normalized:
                normalized.append(" ")
            pending_space = False
            normalized.append(char)
            quote = char
        elif char.isspace():
            pending_space = bool(normalized)
        else:
            if pending_space and normalized:
                normalized.append(" ")
            pending_space = False
            normalized.append(char)
    return "".join(normalized)


def command_receipt_source(
    *, run_id: object, sequence: object, command: object,
    device_identity: object, contact_started_at: object,
    contact_completed_at: object,
) -> dict:
    return {
        "schema_version": COMMAND_RECEIPT_SCHEMA_VERSION,
        "run_id": str(run_id or ""),
        "sequence": sequence,
        "command": str(command or ""),
        "device_identity": device_identity,
        "contact_started_at": str(contact_started_at or ""),
        "contact_completed_at": str(contact_completed_at or ""),
    }


def command_receipt_id(source: dict) -> str:
    canonical = json.dumps(source, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def command_receipt_is_valid(
    receipt: object,
    *, run_id: str,
    device_identity: dict,
    contact_started_at: str,
    contact_completed_at: str,
) -> bool:
    """Validate one frozen receipt using only its retained semantic contract."""
    if not isinstance(receipt, dict):
        return False
    sequence = receipt.get("sequence")
    command = receipt.get("command")
    if not isinstance(sequence, int) or sequence < 1 or not isinstance(command, str):
        return False
    source = command_receipt_source(
        run_id=run_id,
        sequence=sequence,
        command=command,
        device_identity=device_identity,
        contact_started_at=contact_started_at,
        contact_completed_at=contact_completed_at,
    )
    return (
        receipt.get("receipt_id") == command_receipt_id(source)
        and receipt.get("run_id") == run_id
        and receipt.get("device_identity") == device_identity
        and receipt.get("contact_started_at") == contact_started_at
        and receipt.get("contact_completed_at") == contact_completed_at
        and receipt.get("normalized_command")
        == normalize_command_for_attribution(command)
        and receipt.get("execution_status") == COMMAND_RECEIPT_EXECUTION_STATUS
        and receipt.get("acknowledgement") == COMMAND_RECEIPT_ACKNOWLEDGEMENT
    )
