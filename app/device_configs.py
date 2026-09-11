from __future__ import annotations

import json
import os
import pty
import re
import select
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from app.build_info import APP_VERSION, BUILD_COMMIT, BUILD_ID
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

DATA_DIR = Path(os.environ.get("ANALYZER_DATA_DIR", "/data"))
CONFIG_DIR = DATA_DIR / "device-configs"
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
KEY_RE = re.compile(r"^/keys/[A-Za-z0-9._/-]{1,180}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
CUSTOM_COMMAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/,=|?*+-]{0,199}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
ARTIFACT_NAMES = ("manifest.json", "stdout.txt", "stderr.txt", "accountability.pcap", "capture-stderr.txt")
UPLOADED_ARTIFACT_RE = re.compile(r"^uploaded-[A-Za-z0-9_.-]{1,100}$")
COLLECTION_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}-config\.txt$")
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
PASSWORD_SESSION_TTL_SECONDS = 90
MAX_ADDITIONAL_COMMANDS = 20
READ_ONLY_COMMAND_PREFIXES = {
    "show", "display", "get", "ping", "traceroute", "mtr",
    "cat", "netstat", "sockstat", "uptime", "uname", "dmesg",
}
READ_ONLY_FILTER_PREFIXES = {
    "include", "exclude", "match", "display", "grep", "egrep",
    "head", "tail", "count", "no-more",
}

VENDORS = ("vyos", "cisco", "juniper", "pfsense")
DEVICE_TYPES = ("router", "firewall")

TEMPLATES: dict[str, dict[str, tuple[str, ...]]] = {
    "vyos": {
        "router": (
            "show version",
            "show configuration commands",
            "show interfaces",
            "show ip route",
            "show arp",
            "show ipv6 neighbors",
            "show lldp neighbors detail",
            "show firewall",
        ),
        "firewall": (
            "show version",
            "show configuration commands",
            "show interfaces",
            "show ip route",
            "show arp",
            "show ipv6 neighbors",
            "show lldp neighbors detail",
            "show firewall",
        ),
    },
    "cisco": {
        "router": (
            "terminal length 0",
            "show version",
            "show running-config",
            "show ip interface brief",
            "show interfaces",
            "show ip route",
            "show ip arp",
            "show ipv6 neighbors",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show access-lists",
        ),
        "firewall": (
            "terminal pager 0",
            "show version",
            "show running-config",
            "show interface ip brief",
            "show interface",
            "show route",
            "show arp",
            "show ipv6 neighbor",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show access-list",
        ),
    },
    "juniper": {
        "router": (
            "show version",
            "show configuration | display set",
            "show interfaces terse",
            "show interfaces detail",
            "show route",
            "show arp no-resolve",
            "show ipv6 neighbors",
            "show lldp neighbors detail",
            "show firewall",
        ),
        "firewall": (
            "show version",
            "show configuration | display set",
            "show interfaces terse",
            "show interfaces detail",
            "show route",
            "show arp no-resolve",
            "show ipv6 neighbors",
            "show lldp neighbors detail",
            "show security policies",
            "show firewall",
        ),
    },
    "pfsense": {
        "router": (
            "cat /etc/version",
            "ifconfig",
            "netstat -rn",
            "arp -an",
            "ndp -an",
            "pfctl -sr",
            "pfctl -sn",
            "cat /cf/conf/config.xml",
        ),
        "firewall": (
            "cat /etc/version",
            "ifconfig",
            "netstat -rn",
            "arp -an",
            "ndp -an",
            "pfctl -sr",
            "pfctl -sn",
            "cat /cf/conf/config.xml",
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
    device_name: str | None = Field(default=None, max_length=100)
    username: str = Field(min_length=1, max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    key_path: str | None = Field(default=None, max_length=200)
    authentication_mode: Literal["password_prompt", "key"] = "key"
    accountability_interface: str = Field(min_length=1, max_length=64)
    additional_commands: list[str] = Field(default_factory=list, max_length=MAX_ADDITIONAL_COMMANDS)

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

    @field_validator("device_name")
    @classmethod
    def clean_device_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

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

    @field_validator("additional_commands")
    @classmethod
    def validate_additional_commands(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw_command in values:
            command = raw_command.strip()
            if not command:
                continue
            if not CUSTOM_COMMAND_RE.fullmatch(command):
                raise ValueError(
                    "Additional commands may use letters, numbers, spaces, and safe read-only punctuation only"
                )
            pipeline = [segment.strip() for segment in command.split("|")]
            if any(not segment for segment in pipeline):
                raise ValueError("Additional command pipelines cannot contain an empty step")
            primary = pipeline[0].split(maxsplit=1)[0].lower()
            if primary not in READ_ONLY_COMMAND_PREFIXES:
                raise ValueError(
                    "Additional commands must start with a supported read-only command such as show, display, get, ping, traceroute, or cat"
                )
            for filter_step in pipeline[1:]:
                filter_name = filter_step.split(maxsplit=1)[0].lower()
                if filter_name not in READ_ONLY_FILTER_PREFIXES:
                    raise ValueError(
                        "Pipeline steps must use a supported output filter such as include, exclude, match, display, grep, head, tail, or count"
                    )
            if command not in cleaned:
                cleaned.append(command)
        return cleaned


def build_plan(plan: DeviceConfigPlan) -> dict:
    template_commands = list(TEMPLATES[plan.vendor][plan.device_type])
    additional_commands = list(plan.additional_commands)
    commands = template_commands + additional_commands
    run_id = uuid.uuid4().hex
    name = safe_name(plan.device_name or plan.device_address)
    target = f"{plan.username}@{plan.device_address}"
    interactive = plan.authentication_mode == "password_prompt"
    ssh_args = ["ssh"]
    if not interactive:
        ssh_args += ["-o", "BatchMode=yes"]
    ssh_args += [
        "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
        "-p", str(plan.ssh_port),
    ]
    if plan.key_path:
        ssh_args += ["-o", "IdentitiesOnly=yes", "-i", plan.key_path]
    if interactive:
        remote_input = None
        ssh_args += [target]
        ssh_command = shlex.join(ssh_args)
    elif plan.vendor == "vyos":
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
        "device_name": plan.device_name,
        "username": plan.username,
        "accountability_interface": plan.accountability_interface,
        "capture_command": shlex.join([
            "tcpdump", "-i", plan.accountability_interface, "-p", "-nn", "-U", "-s", "0",
            "-w", "accountability.pcap",
        ]),
        "template_commands": template_commands,
        "additional_commands": additional_commands,
        "commands": commands,
        "ssh_command": ssh_command,
        "ssh_args": ssh_args,
        "remote_input": remote_input,
        "scp_command": shlex.join(scp_args),
        "remote_output_path": f"/tmp/{local_file}",
        "local_output_name": local_file,
        "authentication_mode": plan.authentication_mode,
        "cleanup_plan": (
            "Create a temporary output file on the device, copy it back to the analyzer, delete the remote file, and close the SSH session."
            if plan.vendor in {"vyos", "pfsense"}
            else "Collect through the SSH output stream, create no remote file, and close the SSH session."
        ),
        "notes": "The template and validated operator additions are read-only except for session-only terminal pagination settings on Cisco devices.",
    }


def manifest_for(plan: DeviceConfigPlan, preview: dict, status: str, **extra: object) -> dict:
    value = {
        "application_version": APP_VERSION,
        "build_id": BUILD_ID,
        "build_commit": BUILD_COMMIT,
        "run_id": preview["run_id"],
        "created_at": utc_now(),
        "operator": plan.operator,
        "reason": plan.reason,
        "originating_host": plan.originating_host,
        "vendor": plan.vendor,
        "device_type": plan.device_type,
        "device_address": plan.device_address,
        "device_name": plan.device_name,
        "username": plan.username,
        "ssh_port": plan.ssh_port,
        "authentication_mode": plan.authentication_mode,
        "credentials_stored": False,
        "accountability_interface": plan.accountability_interface,
        "capture_required": True,
        "capture_command": preview["capture_command"],
        "template_commands": preview["template_commands"],
        "additional_commands": preview["additional_commands"],
        "commands": preview["commands"],
        "ssh_command": preview["ssh_command"],
        "scp_command": preview["scp_command"],
        "cleanup_plan": preview["cleanup_plan"],
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


class InteractivePasswordSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: SecretStr = Field(min_length=1, max_length=1024)


@dataclass
class InteractiveSshSession:
    session_id: str
    plan: DeviceConfigPlan
    preview: dict
    run_dir: Path
    control_dir: Path
    control_path: Path
    master_process: subprocess.Popen[bytes]
    pty_fd: int
    capture_process: object
    capture_stderr: object
    manifest: dict
    created_monotonic: float = field(default_factory=time.monotonic)
    timer: threading.Timer | None = None


_INTERACTIVE_SESSIONS: dict[str, InteractiveSshSession] = {}
_INTERACTIVE_SESSIONS_LOCK = threading.Lock()


def _transport_is_secure(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    if forwarded == "https" or request.url.scheme == "https":
        return True
    if request.url.hostname in {"localhost", "127.0.0.1", "::1"}:
        return True
    return os.environ.get("ALLOW_INSECURE_DEVICE_PASSWORDS", "").lower() in {"1", "true", "yes"}


def _require_secure_password_transport(request: Request) -> None:
    if not _transport_is_secure(request):
        raise HTTPException(
            status_code=400,
            detail=(
                "Interactive SSH passwords require HTTPS. Configure TLS for the analyzer before "
                "using password-based device collection."
            ),
        )


def _read_pty(session: InteractiveSshSession, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    output = bytearray()
    while time.monotonic() < deadline:
        if session.control_path.exists():
            break
        if session.master_process.poll() is not None:
            break
        ready, _, _ = select.select([session.pty_fd], [], [], 0.15)
        if not ready:
            continue
        try:
            chunk = os.read(session.pty_fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
        text = output.decode(errors="replace")
        if re.search(r"(?i)(password|verification code)[^:\r\n]*:\s*$", text):
            break
    return output.decode(errors="replace")[-4000:]


def _control_check(session: InteractiveSshSession) -> bool:
    if not session.control_path.exists():
        return False
    checked = subprocess.run(
        [
            "ssh", "-S", str(session.control_path), "-p", str(session.plan.ssh_port),
            "-O", "check", f"{session.plan.username}@{session.plan.device_address}",
        ],
        capture_output=True,
        timeout=5,
        check=False,
    )
    return checked.returncode == 0


def _close_interactive_resources(session: InteractiveSshSession) -> None:
    target = f"{session.plan.username}@{session.plan.device_address}"
    if session.timer is not None:
        session.timer.cancel()
    if session.control_path.exists():
        subprocess.run(
            ["ssh", "-S", str(session.control_path), "-p", str(session.plan.ssh_port), "-O", "exit", target],
            capture_output=True,
            timeout=5,
            check=False,
        )
    if session.master_process.poll() is None:
        session.master_process.terminate()
        try:
            session.master_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            session.master_process.kill()
            session.master_process.wait(timeout=3)
    try:
        os.close(session.pty_fd)
    except OSError:
        pass
    stop_accountability_capture(session.capture_process, session.capture_stderr)
    shutil.rmtree(session.control_dir, ignore_errors=True)


def _finish_interactive_session(
    session: InteractiveSshSession,
    *,
    status: str,
    stderr: str,
    failure_class: str | None,
    exit_code: int | None = None,
    extra: dict | None = None,
) -> dict:
    with _INTERACTIVE_SESSIONS_LOCK:
        _INTERACTIVE_SESSIONS.pop(session.session_id, None)
    _close_interactive_resources(session)
    if failure_class != "accountability_capture_problem" and not capture_is_valid(session.run_dir):
        status = "failed"
        failure_class = "accountability_capture_problem"
        stderr = (stderr + "\n" if stderr else "") + "Mandatory tcpdump accountability did not produce a valid PCAP."
    stdout_path = session.run_dir / "stdout.txt"
    stderr_path = session.run_dir / "stderr.txt"
    if not stdout_path.exists():
        stdout_path.write_text("")
    stderr_path.write_text(stderr[:50_000])
    session.manifest.update(
        {
            "status": status,
            "completed_at": utc_now(),
            "exit_code": exit_code,
            "failure_class": failure_class,
            "credentials_stored": False,
        }
    )
    if extra:
        session.manifest.update(extra)
    (session.run_dir / "manifest.json").write_text(json.dumps(session.manifest, indent=2) + "\n")
    stdout = stdout_path.read_text(errors="replace")[:200_000]
    return {
        **session.manifest,
        "stdout": stdout,
        "stderr": stderr[:50_000],
        "artifacts": artifact_records(session.preview["run_id"], session.run_dir),
    }


def _expire_interactive_session(session_id: str) -> None:
    with _INTERACTIVE_SESSIONS_LOCK:
        session = _INTERACTIVE_SESSIONS.get(session_id)
    if session is None or time.monotonic() - session.created_monotonic < PASSWORD_SESSION_TTL_SECONDS:
        return
    _finish_interactive_session(
        session,
        status="expired",
        stderr="The password prompt expired before the operator completed authentication.",
        failure_class="authentication_expired",
    )


def _control_ssh_args(session: InteractiveSshSession) -> list[str]:
    return [
        "ssh", "-S", str(session.control_path), "-p", str(session.plan.ssh_port),
        f"{session.plan.username}@{session.plan.device_address}",
    ]


def _interactive_master_args(plan: DeviceConfigPlan, control_path: Path) -> list[str]:
    """Build the internal SSH command with the PTY as its controlling terminal."""
    target = f"{plan.username}@{plan.device_address}"
    return [
        "setsid", "--ctty", "ssh", "-M", "-N", "-T",
        "-o", "ControlMaster=yes", "-o", f"ControlPath={control_path}",
        "-o", "ControlPersist=no", "-o", "NumberOfPasswordPrompts=1",
        "-o", "PubkeyAuthentication=no", "-o", "GSSAPIAuthentication=no",
        "-o", "PreferredAuthentications=keyboard-interactive,password",
        "-o", "KbdInteractiveAuthentication=yes", "-o", "PasswordAuthentication=yes",
        "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
        "-p", str(plan.ssh_port), target,
    ]


def _run_interactive_collection(session: InteractiveSshSession) -> dict:
    plan = session.plan
    preview = session.preview
    target = f"{plan.username}@{plan.device_address}"
    local_output = session.run_dir / preview["local_output_name"]
    remote_output = preview["remote_output_path"]
    stderr_parts: list[str] = []
    exit_code: int | None = None
    transfer_method = "ssh_stdout"
    cleanup_status = "not_required"
    remote_created = False
    try:
        if plan.vendor in {"vyos", "pfsense"}:
            transfer_method = "scp_control_session"
            remote_created = True
            if plan.vendor == "vyos":
                remote_input = "\n".join(
                    ["source /opt/vyatta/etc/functions/script-template"]
                    + [f"run {command}" for command in preview["commands"]]
                    + ["exit"]
                ) + "\n"
                remote_command = f"vbash -s > {shlex.quote(remote_output)}"
            else:
                remote_input = None
                labeled_commands = []
                for command in preview["commands"]:
                    labeled_commands.extend([f"printf '\\n===== {command} =====\\n'", command])
                remote_script = "{ " + "; ".join(labeled_commands) + f"; }} > {shlex.quote(remote_output)}"
                remote_command = f"sh -c {shlex.quote(remote_script)}"
            collected = subprocess.run(
                _control_ssh_args(session) + [remote_command],
                input=remote_input,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            exit_code = collected.returncode
            if collected.stderr:
                stderr_parts.append(collected.stderr[:20_000])
            if collected.returncode != 0:
                raise RuntimeError("The remote collection command returned a non-zero result.")
            copied = subprocess.run(
                [
                    "scp", "-q", "-P", str(plan.ssh_port), "-o", f"ControlPath={session.control_path}",
                    f"{target}:{remote_output}", str(local_output),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if copied.stderr:
                stderr_parts.append(copied.stderr[:20_000])
            if copied.returncode != 0 or not local_output.is_file():
                raise RuntimeError("SCP could not copy the collected configuration back to the analyzer.")
        else:
            collected = subprocess.run(
                _control_ssh_args(session) + ["; ".join(preview["commands"])],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            exit_code = collected.returncode
            local_output.write_text(collected.stdout[:200_000])
            if collected.stderr:
                stderr_parts.append(collected.stderr[:20_000])
            if collected.returncode != 0:
                raise RuntimeError("The remote collection command returned a non-zero result.")
        (session.run_dir / "stdout.txt").write_text(local_output.read_text(errors="replace")[:200_000])
        status = "completed"
        failure_class = None
    except subprocess.TimeoutExpired:
        status = "timed_out"
        failure_class = "network_connection_problem"
        stderr_parts.append("The device collection timed out.")
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        status = "failed"
        failure_class = "remote_command_failed"
        stderr_parts.append(str(exc))
    finally:
        if remote_created:
            try:
                cleaned = subprocess.run(
                    _control_ssh_args(session) + [f"rm -f -- {shlex.quote(remote_output)}"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                cleanup_status = "completed" if cleaned.returncode == 0 else "failed"
                if cleaned.stderr:
                    stderr_parts.append(cleaned.stderr[:4000])
            except (FileNotFoundError, subprocess.TimeoutExpired):
                cleanup_status = "failed"
                stderr_parts.append("Remote temporary-file cleanup could not be confirmed.")
    return _finish_interactive_session(
        session,
        status=status,
        stderr="\n".join(part.strip() for part in stderr_parts if part.strip()),
        failure_class=failure_class,
        exit_code=exit_code,
        extra={
            "transfer_method": transfer_method,
            "remote_temp_created": remote_created,
            "remote_cleanup_status": cleanup_status,
            "local_output_name": preview["local_output_name"],
        },
    )


def artifact_records(run_id: str, run_dir: Path) -> list[dict]:
    names = list(ARTIFACT_NAMES)
    names.extend(
        path.name for path in sorted(run_dir.glob("uploaded-*"))
        if path.is_file() and UPLOADED_ARTIFACT_RE.fullmatch(path.name)
    )
    names.extend(
        path.name for path in sorted(run_dir.glob("*-config.txt"))
        if path.is_file() and COLLECTION_ARTIFACT_RE.fullmatch(path.name)
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


@router.post("/interactive/start")
def start_interactive_session(plan: DeviceConfigPlan, request: Request) -> dict:
    """Open a short-lived SSH control session and stop at the device password prompt."""
    _require_secure_password_transport(request)
    if plan.authentication_mode != "password_prompt":
        raise HTTPException(status_code=422, detail="Choose password-prompt authentication for this workflow")
    preview_data = build_plan(plan)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    run_dir = CONFIG_DIR / preview_data["run_id"]
    run_dir.mkdir(parents=True, exist_ok=False)
    manifest = manifest_for(
        plan,
        preview_data,
        "waiting_for_password",
        operation="interactive_configuration_pull",
        credential_transport="https",
        credential_retention="none",
    )
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    capture_process = None
    capture_stderr = None
    control_dir: Path | None = None
    master_fd: int | None = None
    slave_fd: int | None = None
    master_process: subprocess.Popen[bytes] | None = None
    try:
        capture_process, capture_stderr, _ = start_accountability_capture(plan.accountability_interface, run_dir)
        control_dir = Path(tempfile.mkdtemp(prefix=f"nct-ssh-{preview_data['run_id'][:12]}-", dir="/tmp"))
        control_dir.chmod(0o700)
        control_path = control_dir / "control.sock"
        master_fd, slave_fd = pty.openpty()
        # OpenSSH reads interactive passwords from /dev/tty rather than stdin.
        # The API process has no controlling terminal, so attach the PTY we
        # created above as the child's controlling terminal before starting
        # SSH. Without this, OpenSSH immediately sends an empty password and
        # reports Permission denied before the operator dialog can appear.
        master_args = _interactive_master_args(plan, control_path)
        master_process = subprocess.Popen(
            master_args,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
        os.close(slave_fd)
        slave_fd = None
        session_id = uuid.uuid4().hex
        session = InteractiveSshSession(
            session_id=session_id,
            plan=plan,
            preview=preview_data,
            run_dir=run_dir,
            control_dir=control_dir,
            control_path=control_path,
            master_process=master_process,
            pty_fd=master_fd,
            capture_process=capture_process,
            capture_stderr=capture_stderr,
            manifest=manifest,
        )
        prompt_output = _read_pty(session, 12)
        if _control_check(session):
            return _run_interactive_collection(session)
        if not re.search(r"(?i)(password|verification code)[^:\r\n]*:\s*$", prompt_output):
            message = "SSH did not present a supported password prompt. Check reachability, the username, and device SSH settings."
            if "permission denied" in prompt_output.lower():
                message = "The device rejected password authentication for this account."
            return _finish_interactive_session(
                session,
                status="failed",
                stderr=message,
                failure_class="authentication_prompt_failed",
                exit_code=master_process.poll(),
            )
        with _INTERACTIVE_SESSIONS_LOCK:
            _INTERACTIVE_SESSIONS[session_id] = session
        timer = threading.Timer(PASSWORD_SESSION_TTL_SECONDS + 1, _expire_interactive_session, args=(session_id,))
        timer.daemon = True
        session.timer = timer
        timer.start()
        return {
            "status": "waiting_for_password",
            "session_id": session_id,
            "run_id": preview_data["run_id"],
            "device_address": plan.device_address,
            "username": plan.username,
            "ssh_port": plan.ssh_port,
            "expires_in_seconds": PASSWORD_SESSION_TTL_SECONDS,
            "message": (
                "SSH is waiting for the password for "
                f"{plan.username}@{plan.device_address}."
            ),
        }
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        if slave_fd is not None:
            os.close(slave_fd)
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass
        if master_process is not None and master_process.poll() is None:
            master_process.terminate()
        stop_accountability_capture(capture_process, capture_stderr)
        if control_dir is not None:
            shutil.rmtree(control_dir, ignore_errors=True)
        manifest.update(
            {
                "status": "failed",
                "completed_at": utc_now(),
                "failure_class": "session_start_failed",
                "credentials_stored": False,
            }
        )
        (run_dir / "stderr.txt").write_text(str(exc)[:50_000])
        (run_dir / "stdout.txt").write_text("")
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        raise HTTPException(status_code=502, detail="The interactive SSH session could not be started") from exc


@router.post("/interactive/{session_id}/password")
def submit_interactive_password(
    session_id: str,
    submission: InteractivePasswordSubmission,
    request: Request,
) -> dict:
    """Send a one-time password to the waiting SSH PTY without persisting or logging it."""
    _require_secure_password_transport(request)
    with _INTERACTIVE_SESSIONS_LOCK:
        session = _INTERACTIVE_SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="The SSH password prompt is no longer active")
    if time.monotonic() - session.created_monotonic >= PASSWORD_SESSION_TTL_SECONDS:
        _expire_interactive_session(session_id)
        raise HTTPException(status_code=410, detail="The SSH password prompt expired; start a new session")
    password_bytes = bytearray(submission.password.get_secret_value().encode("utf-8"))
    try:
        os.write(session.pty_fd, password_bytes + b"\n")
    finally:
        for index in range(len(password_bytes)):
            password_bytes[index] = 0
        del password_bytes
        del submission
    authentication_output = _read_pty(session, 15)
    if not _control_check(session):
        message = "SSH authentication failed. Recheck the username and password, then start a new session."
        if session.master_process.poll() is None:
            message = "SSH did not finish authentication before the prompt timed out."
        return _finish_interactive_session(
            session,
            status="failed",
            stderr=message,
            failure_class="authentication_failed",
            exit_code=session.master_process.poll(),
            extra={"authentication_output_retained": False},
        )
    del authentication_output
    return _run_interactive_collection(session)


@router.post("/interactive/{session_id}/cancel")
def cancel_interactive_session(session_id: str) -> dict:
    with _INTERACTIVE_SESSIONS_LOCK:
        session = _INTERACTIVE_SESSIONS.get(session_id)
    if session is None:
        return {"status": "closed", "message": "The SSH password prompt is already closed."}
    result = _finish_interactive_session(
        session,
        status="cancelled",
        stderr="The operator cancelled the SSH password prompt.",
        failure_class="operator_cancelled",
    )
    return {"status": result["status"], "run_id": result["run_id"], "message": "The SSH session was closed."}


@router.post("/preflight")
def preflight(plan: DeviceConfigPlan) -> dict:
    """Validate the key and capture every non-interactive SSH access check."""
    if plan.authentication_mode != "key":
        raise HTTPException(status_code=409, detail="Use the interactive SSH endpoints for password-prompt authentication")
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
    if plan.authentication_mode != "key":
        raise HTTPException(status_code=409, detail="Use the interactive SSH endpoints for password-prompt authentication")
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
    device_name: str = Form(""),
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
    clean_device_name = device_name.strip()
    if len(clean_device_name) > 100:
        raise HTTPException(status_code=422, detail="Device name is limited to 100 characters")
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
        "application_version": APP_VERSION,
        "build_id": BUILD_ID,
        "build_commit": BUILD_COMMIT,
        "run_id": run_id,
        "created_at": completed_at,
        "completed_at": completed_at,
        "operator": values["operator"],
        "reason": values["reason"],
        "originating_host": values["originating_host"],
        "vendor": vendor,
        "device_type": device_type,
        "device_address": values["device_address"],
        "device_name": clean_device_name or None,
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
    allowed_name = (
        filename in ARTIFACT_NAMES
        or bool(UPLOADED_ARTIFACT_RE.fullmatch(filename))
        or bool(COLLECTION_ARTIFACT_RE.fullmatch(filename))
    )
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
