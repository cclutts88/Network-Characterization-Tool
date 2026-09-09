from __future__ import annotations

import json
import os
import re
import shlex
import socket
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

DATA_DIR = Path(os.environ.get("ANALYZER_DATA_DIR", "/data"))
CONFIG_DIR = DATA_DIR / "device-configs"
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
KEY_RE = re.compile(r"^/keys/[A-Za-z0-9._/-]{1,180}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
ARTIFACT_NAMES = ("manifest.json", "stdout.txt", "stderr.txt", "accountability.pcap", "capture-stderr.txt")
UPLOADED_ARTIFACT_RE = re.compile(r"^uploaded-[A-Za-z0-9_.-]{1,100}$")
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

VENDORS = ("vyos", "cisco", "juniper", "pfsense")
DEVICE_TYPES = ("router", "firewall")

TEMPLATES: dict[str, dict[str, tuple[str, ...]]] = {
    "vyos": {
        "router": (
            "show version",
            "show configuration commands",
            "show interfaces",
            "show ip route",
            "show firewall",
        ),
        "firewall": (
            "show version",
            "show configuration commands",
            "show interfaces",
            "show ip route",
            "show firewall",
        ),
    },
    "cisco": {
        "router": (
            "terminal length 0",
            "show version",
            "show running-config",
            "show ip interface brief",
            "show ip route",
            "show access-lists",
        ),
        "firewall": (
            "terminal pager 0",
            "show version",
            "show running-config",
            "show interface ip brief",
            "show route",
            "show access-list",
        ),
    },
    "juniper": {
        "router": (
            "show version",
            "show configuration | display set",
            "show interfaces terse",
            "show route",
            "show firewall",
        ),
        "firewall": (
            "show version",
            "show configuration | display set",
            "show interfaces terse",
            "show route",
            "show security policies",
            "show firewall",
        ),
    },
    "pfsense": {
        "router": (
            "cat /etc/version",
            "ifconfig",
            "netstat -rn",
            "pfctl -sr",
            "pfctl -sn",
        ),
        "firewall": (
            "cat /etc/version",
            "ifconfig",
            "netstat -rn",
            "pfctl -sr",
            "pfctl -sn",
            "pfSsh.php playback config",
        ),
    },
}

router = APIRouter(prefix="/api/device-configs", tags=["device-configs"])


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_name(value: str, fallback: str = "device") -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return (value[:80] or fallback)


class DeviceConfigPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)
    originating_host: str = Field(min_length=1, max_length=255)
    vendor: Literal["vyos", "cisco", "juniper", "pfsense"]
    device_type: Literal["router", "firewall"]
    device_address: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    key_path: str | None = Field(default=None, max_length=200)
    accountability_interface: str = Field(min_length=1, max_length=64)

    @field_validator("operator", "reason", "originating_host", "device_address", "username")
    @classmethod
    def clean_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank")
        return value

    @field_validator("device_address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        if not HOST_RE.fullmatch(value):
            raise ValueError("Use a hostname or IP address without shell characters")
        return value

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not USER_RE.fullmatch(value):
            raise ValueError("Use a simple SSH username")
        return value

    @field_validator("accountability_interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        value = value.strip()
        if not INTERFACE_RE.fullmatch(value):
            raise ValueError("Choose a valid analyzer capture interface")
        return value

    @field_validator("key_path")
    @classmethod
    def validate_key_path(cls, value: str | None) -> str | None:
        if value is not None and (not KEY_RE.fullmatch(value.strip()) or ".." in Path(value.strip()).parts):
            raise ValueError("Key paths must be under /keys")
        return value.strip() if value else None


def build_plan(plan: DeviceConfigPlan) -> dict:
    commands = list(TEMPLATES[plan.vendor][plan.device_type])
    run_id = uuid.uuid4().hex
    name = safe_name(plan.device_address)
    target = f"{plan.username}@{plan.device_address}"
    ssh_args = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new", "-p", str(plan.ssh_port),
    ]
    if plan.key_path:
        ssh_args += ["-o", "IdentitiesOnly=yes", "-i", plan.key_path]
    if plan.vendor == "vyos":
        remote = "vbash -s"
        remote_input = "\n".join(
            ["source /opt/vyatta/etc/functions/script-template"]
            + [f"run {command}" for command in commands]
            + ["exit"]
        ) + "\n"
        ssh_args += [target, remote]
        script_lines = remote_input.rstrip("\n").splitlines()
        ssh_command = f"printf '%s\\n' {shlex.join(script_lines)} | {shlex.join(ssh_args)}"
    else:
        remote_input = None
        ssh_args += [target, "; ".join(commands)]
        ssh_command = shlex.join(ssh_args)
    local_file = f"{name}-{run_id[:12]}-config.txt"
    scp_args = ["scp", "-P", str(plan.ssh_port)]
    if plan.key_path:
        scp_args += ["-i", plan.key_path]
    scp_args += [f"{target}:/tmp/{local_file}", f"./{local_file}"]
    return {
        "run_id": run_id,
        "vendor": plan.vendor,
        "device_type": plan.device_type,
        "device_address": plan.device_address,
        "username": plan.username,
        "accountability_interface": plan.accountability_interface,
        "capture_command": shlex.join([
            "tcpdump", "-i", plan.accountability_interface, "-p", "-nn", "-U", "-s", "0",
            "-w", "accountability.pcap",
        ]),
        "commands": commands,
        "ssh_command": ssh_command,
        "ssh_args": ssh_args,
        "remote_input": remote_input,
        "scp_command": shlex.join(scp_args),
        "remote_output_path": f"/tmp/{local_file}",
        "notes": "The command set is read-only except for session-only terminal pagination settings on Cisco devices.",
    }


def manifest_for(plan: DeviceConfigPlan, preview: dict, status: str, **extra: object) -> dict:
    value = {
        "run_id": preview["run_id"],
        "created_at": utc_now(),
        "operator": plan.operator,
        "reason": plan.reason,
        "originating_host": plan.originating_host,
        "vendor": plan.vendor,
        "device_type": plan.device_type,
        "device_address": plan.device_address,
        "username": plan.username,
        "ssh_port": plan.ssh_port,
        "accountability_interface": plan.accountability_interface,
        "capture_required": True,
        "capture_command": preview["capture_command"],
        "commands": preview["commands"],
        "ssh_command": preview["ssh_command"],
        "scp_command": preview["scp_command"],
        "status": status,
    }
    value.update(extra)
    return value


def key_preflight(key_path: str | None) -> dict:
    """Check only the analyzer-local key file; never return key material."""
    if not key_path:
        return {"status": "not_provided", "message": "No key path was supplied; the analyzer SSH agent will be used if available."}
    path = Path(key_path)
    if not path.is_file():
        return {"status": "missing", "message": f"Private key is not readable at {key_path} inside the analyzer."}
    if not os.access(path, os.R_OK):
        return {"status": "unreadable", "message": f"Private key exists but the analyzer process cannot read {key_path}."}
    try:
        checked = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(path)],
            input="",
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"status": "unverified", "message": "ssh-keygen is unavailable or the key check timed out."}
    if checked.returncode != 0:
        return {"status": "invalid", "message": "The supplied private key could not be parsed without prompting."}
    return {"status": "valid", "message": f"Private key is readable and valid at {key_path} inside the analyzer."}


def available_interfaces() -> set[str]:
    return {name for _, name in socket.if_nameindex() if name != "lo"}


def validate_runtime_interface(interface: str) -> None:
    allowed = available_interfaces()
    if interface not in allowed:
        raise ValueError(
            f"Capture interface {interface!r} is not available; choose one of: "
            + ", ".join(sorted(allowed))
        )


def capture_argv(interface: str, output_path: Path) -> list[str]:
    return [
        "tcpdump", "-i", interface, "-p", "-nn", "-U", "-s", "0",
        "-w", str(output_path),
    ]


def start_accountability_capture(interface: str, run_dir: Path) -> tuple[object, object, list[str]]:
    validate_runtime_interface(interface)
    args = capture_argv(interface, run_dir / "accountability.pcap")
    stderr_handle = (run_dir / "capture-stderr.txt").open("wb")
    try:
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=stderr_handle)
        time.sleep(0.35)
        if process.poll() is not None:
            stderr_handle.close()
            detail = (run_dir / "capture-stderr.txt").read_text(errors="replace")[:4000]
            raise RuntimeError(detail or f"tcpdump exited with status {process.returncode}")
        return process, stderr_handle, args
    except Exception:
        if not stderr_handle.closed:
            stderr_handle.close()
        raise


def stop_accountability_capture(process: object | None, stderr_handle: object | None) -> None:
    if process is not None:
        try:
            if process.poll() is None:
                # Give libpcap time to deliver the final outbound packets from its
                # kernel buffer before stopping tcpdump. Without this drain window,
                # very short SSH preflight connections can leave a header-only PCAP.
                time.sleep(1.0)
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            if stderr_handle is not None and not stderr_handle.closed:
                stderr_handle.close()
    elif stderr_handle is not None and not stderr_handle.closed:
        stderr_handle.close()


def capture_is_valid(run_dir: Path) -> bool:
    path = run_dir / "accountability.pcap"
    # 24 bytes is only the global PCAP header. Accountability evidence must
    # contain at least one packet record (16-byte record header plus payload).
    return path.is_file() and path.stat().st_size > 40


def artifact_records(run_id: str, run_dir: Path) -> list[dict]:
    names = list(ARTIFACT_NAMES)
    names.extend(
        path.name for path in sorted(run_dir.glob("uploaded-*"))
        if path.is_file() and UPLOADED_ARTIFACT_RE.fullmatch(path.name)
    )
    return [
        {
            "name": name,
            "size": (run_dir / name).stat().st_size,
            "url": f"/api/device-configs/{run_id}/files/{name}",
        }
        for name in names
        if (run_dir / name).is_file()
    ]


def classify_ssh_failure(stderr: str, key_status: str) -> str:
    text = (stderr or "").lower()
    if key_status in {"missing", "unreadable", "invalid"}:
        return "local_key_problem"
    if "host key verification failed" in text or "known_hosts" in text:
        return "host_key_problem"
    if "permission denied" in text or "publickey" in text:
        return "remote_key_rejected"
    if "timed out" in text or "connection refused" in text or "no route to host" in text:
        return "network_connection_problem"
    return "remote_command_failed"


@router.get("/vendors")
def vendors() -> dict:
    return {"vendors": list(VENDORS), "device_types": list(DEVICE_TYPES), "templates": {k: list(v) for k, v in TEMPLATES.items()}}


@router.post("/preview")
def preview(plan: DeviceConfigPlan) -> dict:
    value = build_plan(plan)
    value.pop("ssh_args", None)
    value.pop("remote_input", None)
    return value


@router.post("/preflight")
def preflight(plan: DeviceConfigPlan) -> dict:
    """Validate the key and capture every non-interactive SSH access check."""
    key = key_preflight(plan.key_path)
    result = {"key": key, "device_address": plan.device_address, "username": plan.username, "ssh_port": plan.ssh_port}
    if key["status"] in {"missing", "unreadable", "invalid"}:
        result.update({"status": "blocked", "failure_class": "local_key_problem", "message": key["message"]})
        return result
    preview_data = build_plan(plan)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    run_dir = CONFIG_DIR / preview_data["run_id"]
    run_dir.mkdir(parents=True, exist_ok=False)
    manifest = manifest_for(plan, preview_data, "running", operation="ssh_preflight", key_status=key["status"])
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    args = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new", "-p", str(plan.ssh_port),
    ]
    if plan.key_path:
        args += ["-o", "IdentitiesOnly=yes", "-i", plan.key_path]
    args += [f"{plan.username}@{plan.device_address}", "true"]
    process = None
    capture_stderr = None
    exit_code = None
    try:
        process, capture_stderr, _ = start_accountability_capture(plan.accountability_interface, run_dir)
        try:
            checked = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
            exit_code = checked.returncode
            stderr = checked.stderr[:4000]
            if checked.returncode == 0:
                result.update({"status": "ready", "failure_class": None, "message": "Non-interactive SSH authentication succeeded with packet-capture accountability."})
            else:
                result.update({"status": "blocked", "failure_class": classify_ssh_failure(stderr, key["status"]), "message": stderr or "SSH preflight returned a non-zero result."})
        except subprocess.TimeoutExpired:
            result.update({"status": "blocked", "failure_class": "network_connection_problem", "message": "SSH preflight timed out after 20 seconds."})
        except FileNotFoundError:
            result.update({"status": "blocked", "failure_class": "remote_command_failed", "message": "SSH client is not available in the analyzer."})
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        result.update({"status": "blocked", "failure_class": "accountability_capture_problem", "message": f"Mandatory tcpdump accountability could not start: {exc}"})
    finally:
        stop_accountability_capture(process, capture_stderr)
    if result.get("failure_class") != "accountability_capture_problem" and not capture_is_valid(run_dir):
        result.update({"status": "blocked", "failure_class": "accountability_capture_problem", "message": "Mandatory tcpdump accountability did not produce a valid PCAP."})
    manifest.update({
        "status": "completed" if result.get("status") == "ready" else "failed",
        "completed_at": utc_now(),
        "exit_code": exit_code,
        "failure_class": result.get("failure_class"),
    })
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    result["accountability_run_id"] = preview_data["run_id"]
    result["accountability_artifacts"] = artifact_records(preview_data["run_id"], run_dir)
    return result


@router.post("/execute")
def execute(plan: DeviceConfigPlan) -> dict:
    preview_data = build_plan(plan)
    key = key_preflight(plan.key_path)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    run_dir = CONFIG_DIR / preview_data["run_id"]
    run_dir.mkdir(parents=True, exist_ok=False)
    manifest = manifest_for(plan, preview_data, "running", operation="configuration_pull", key_status=key["status"])
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    stdout = ""
    stderr = ""
    exit_code = None
    status = "failed"
    failure_class = None
    process = None
    capture_stderr = None
    if key["status"] in {"missing", "unreadable", "invalid"}:
        stderr = key["message"]
        failure_class = "local_key_problem"
        (run_dir / "stdout.txt").write_text("")
        (run_dir / "stderr.txt").write_text(stderr)
        manifest.update({"status": status, "completed_at": utc_now(), "exit_code": exit_code, "failure_class": failure_class})
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return {**manifest, "stdout": stdout, "stderr": stderr, "scp_command": preview_data["scp_command"], "artifacts": artifact_records(preview_data["run_id"], run_dir)}
    try:
        process, capture_stderr, _ = start_accountability_capture(plan.accountability_interface, run_dir)
        try:
            completed = subprocess.run(
                preview_data["ssh_args"],
                input=preview_data["remote_input"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            stdout = completed.stdout[:200_000]
            stderr = completed.stderr[:50_000]
            exit_code = completed.returncode
            status = "completed" if completed.returncode == 0 else "failed"
            failure_class = None if completed.returncode == 0 else classify_ssh_failure(stderr, key["status"])
        except subprocess.TimeoutExpired as exc:
            stderr = (exc.stderr or "Command timed out") if isinstance(exc.stderr, str) else "Command timed out"
            stderr = stderr[:50_000]
            status = "timed_out"
            failure_class = "network_connection_problem"
        except FileNotFoundError:
            stderr = "SSH client is not available in the analyzer."
            status = "failed"
            failure_class = "remote_command_failed"
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        stderr = f"Mandatory tcpdump accountability could not start: {exc}"
        status = "failed"
        failure_class = "accountability_capture_problem"
    finally:
        stop_accountability_capture(process, capture_stderr)
    if failure_class != "accountability_capture_problem" and not capture_is_valid(run_dir):
        status = "failed"
        failure_class = "accountability_capture_problem"
        stderr = (stderr + "\n" if stderr else "") + "Mandatory tcpdump accountability did not produce a valid PCAP."
    (run_dir / "stdout.txt").write_text(stdout)
    (run_dir / "stderr.txt").write_text(stderr)
    manifest.update({"status": status, "completed_at": utc_now(), "exit_code": exit_code, "failure_class": failure_class})
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return {
        **manifest,
        "stdout": stdout,
        "stderr": stderr,
        "scp_command": preview_data["scp_command"],
        "artifacts": artifact_records(preview_data["run_id"], run_dir),
    }


@router.post("/upload")
async def upload_result(
    operator: str = Form(...),
    reason: str = Form(...),
    originating_host: str = Form(...),
    vendor: str = Form(...),
    device_type: str = Form(...),
    device_address: str = Form(...),
    result_file: UploadFile = File(...),
) -> dict:
    """Import an existing router/firewall configuration result without contacting a device."""
    values = {
        "operator": operator.strip(),
        "reason": reason.strip(),
        "originating_host": originating_host.strip(),
        "device_address": device_address.strip(),
    }
    if any(not value for value in values.values()):
        raise HTTPException(status_code=422, detail="Operator, reason, originating host, and device address are required")
    if len(values["operator"]) > 100 or len(values["reason"]) > 500 or len(values["originating_host"]) > 255:
        raise HTTPException(status_code=422, detail="One or more upload fields exceed the allowed length")
    if vendor not in VENDORS or device_type not in DEVICE_TYPES:
        raise HTTPException(status_code=422, detail="Choose a supported vendor and device type")
    if not HOST_RE.fullmatch(values["device_address"]):
        raise HTTPException(status_code=422, detail="Use a hostname or IP address without shell characters")

    content = await result_file.read(MAX_UPLOAD_BYTES + 1)
    await result_file.close()
    if not content:
        raise HTTPException(status_code=422, detail="Choose a non-empty result file")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Result files are limited to 5 MB")

    run_id = uuid.uuid4().hex
    run_dir = CONFIG_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    original_name = (result_file.filename or "configuration-result.txt").strip()
    stored_name = f"uploaded-{safe_name(original_name, 'configuration-result.txt')}"
    (run_dir / stored_name).write_bytes(content)
    completed_at = utc_now()
    manifest = {
        "run_id": run_id,
        "created_at": completed_at,
        "completed_at": completed_at,
        "operator": values["operator"],
        "reason": values["reason"],
        "originating_host": values["originating_host"],
        "vendor": vendor,
        "device_type": device_type,
        "device_address": values["device_address"],
        "operation": "manual_upload",
        "status": "uploaded",
        "capture_required": False,
        "network_contacted": False,
        "source_filename": original_name[:255],
        "source_content_type": result_file.content_type or "application/octet-stream",
        "uploaded_size": len(content),
        "commands": [],
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return {**manifest, "artifacts": artifact_records(run_id, run_dir)}


@router.get("")
def history(limit: int = Query(default=30, ge=1, le=100)) -> list[dict]:
    if not CONFIG_DIR.exists():
        return []
    records: list[dict] = []
    for path in sorted(CONFIG_DIR.glob("*/manifest.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            value = json.loads(path.read_text())
            if value.get("operation") == "ssh_preflight":
                continue
            value.pop("key_path", None)
            value["artifacts"] = artifact_records(value["run_id"], path.parent)
            records.append(value)
        except (OSError, ValueError):
            continue
        if len(records) >= limit:
            break
    return records


@router.get("/{run_id}/files/{filename}")
def download_artifact(run_id: str, filename: str) -> FileResponse:
    """Download one allowlisted artifact from a recorded device collection."""
    allowed_name = filename in ARTIFACT_NAMES or bool(UPLOADED_ARTIFACT_RE.fullmatch(filename))
    if not RUN_ID_RE.fullmatch(run_id) or not allowed_name:
        raise HTTPException(status_code=404, detail="Collection artifact was not found")
    path = CONFIG_DIR / run_id / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Collection artifact was not found")
    if filename == "manifest.json":
        media_type = "application/json"
    elif filename == "accountability.pcap":
        media_type = "application/vnd.tcpdump.pcap"
    elif UPLOADED_ARTIFACT_RE.fullmatch(filename):
        media_type = "application/octet-stream"
    else:
        media_type = "text/plain"
    return FileResponse(path, media_type=media_type, filename=f"{run_id}-{filename}")
