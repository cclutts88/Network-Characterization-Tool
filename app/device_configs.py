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
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Literal

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from app.build_info import APP_VERSION, BUILD_COMMIT, BUILD_ID
from app.request_identity import bind_signed_in_actor, signed_in_username
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

DATA_DIR = Path(os.environ.get("ANALYZER_DATA_DIR", "/data"))
CONFIG_DIR = DATA_DIR / "device-configs"
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
KEY_RE = re.compile(r"^/keys/[A-Za-z0-9._/-]{1,180}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
CUSTOM_COMMAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/,=|?*+-]{0,199}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
ARTIFACT_NAMES = (
    "manifest.json",
    "stdout.txt",
    "stderr.txt",
    "command-history.txt",
    "accountability.pcap",
    "capture-stderr.txt",
)
UPLOADED_ARTIFACT_RE = re.compile(r"^uploaded-[A-Za-z0-9_.-]{1,100}$")
COLLECTION_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}-config\.txt$")
MAX_SUMMARY_ITEMS = 500
MAX_RETAINED_COLLECTION_BYTES = 100 * 1024 * 1024
MAX_UPLOAD_BYTES = MAX_RETAINED_COLLECTION_BYTES
MAX_SUMMARY_TEXT_BYTES = MAX_RETAINED_COLLECTION_BYTES
MAX_RESPONSE_OUTPUT_CHARS = 200_000
COLLECTION_COPY_CHUNK_BYTES = 1024 * 1024
PASSWORD_SESSION_TTL_SECONDS = 90
CISCO_COLLECTION_TIMEOUT_SECONDS = 600
MAX_ADDITIONAL_COMMANDS = 20
READ_ONLY_COMMAND_PREFIXES = {
    "show", "display", "get", "ping", "traceroute", "mtr",
    "cat", "netstat", "sockstat", "uptime", "uname", "dmesg",
}
READ_ONLY_FILTER_PREFIXES = {
    "include", "exclude", "match", "display", "grep", "egrep",
    "head", "tail", "count", "no-more",
}

VENDORS = ("vyos", "cisco", "juniper", "pfsense", "unifi")
DEVICE_TYPES = ("router", "firewall", "switch")

COMMAND_HISTORY_COMMANDS = {
    "vyos": "show history",
    "cisco": "show history",
    "juniper": "show cli history | no-more",
    "pfsense": "cat ~/.history",
    "unifi": "cat ~/.bash_history ~/.ash_history ~/.history 2>/dev/null",
}

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
            "show dhcp server leases",
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
            "show dhcp server leases",
            "show firewall",
        ),
    },
    "cisco": {
        "router": (
            "terminal length 0",
            "show version",
            "show running-config",
            "show startup-config",
            "show ip interface brief",
            "show interfaces",
            "show ip route",
            "show ip arp",
            "show ipv6 neighbors",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show hosts",
            "show ip dhcp binding",
            "show access-lists",
        ),
        "firewall": (
            "terminal pager 0",
            "show version",
            "show running-config",
            "show startup-config",
            "show interface ip brief",
            "show interface",
            "show route",
            "show arp",
            "show ipv6 neighbor",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show hosts",
            "show dhcpd binding",
            "show access-list",
        ),
        "switch": (
            "terminal length 0",
            "show version",
            "show running-config",
            "show startup-config",
            "show ip interface brief",
            "show interfaces status",
            "show interfaces description",
            "show interfaces switchport",
            "show interfaces trunk",
            "show vlan brief",
            "show mac address-table",
            "show spanning-tree summary",
            "show spanning-tree",
            "show etherchannel summary",
            "show port-channel summary",
            "show power inline",
            "show ip arp",
            "show ipv6 neighbors",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show hosts",
            "show ip dhcp snooping binding",
            "show ip route",
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
        "switch": (
            "show version",
            "show configuration | display set",
            "show interfaces terse",
            "show interfaces descriptions",
            "show ethernet-switching interfaces detail",
            "show ethernet-switching table",
            "show vlans detail",
            "show spanning-tree bridge",
            "show spanning-tree interface",
            "show lacp interfaces",
            "show poe interface all",
            "show arp no-resolve",
            "show ipv6 neighbors",
            "show lldp neighbors detail",
            "show route",
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
            "cat /var/dhcpd/var/db/dhcpd.leases",
            "cat /var/unbound/host_entries.conf",
            "for table in $(pfctl -s Tables | tr -d '<>'); do printf '__NCT_PF_TABLE__ %s\\n' \"$table\"; pfctl -t \"$table\" -T show; done",
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
            "cat /var/dhcpd/var/db/dhcpd.leases",
            "cat /var/unbound/host_entries.conf",
            "for table in $(pfctl -s Tables | tr -d '<>'); do printf '__NCT_PF_TABLE__ %s\\n' \"$table\"; pfctl -t \"$table\" -T show; done",
            "cat /cf/conf/config.xml",
        ),
    },
    "unifi": {
        "router": (
            "uname -a",
            "cat /etc/os-release",
            "ubnt-device-info summary",
            "ip -details address show",
            "ip -4 route show table all",
            "ip -6 route show table all",
            "ip -4 neigh show",
            "ip -6 neigh show",
            "bridge vlan show",
            "ss -lntup",
            "iptables-save",
            "nft list ruleset",
            "ipset save",
            "lldpcli show neighbors details",
            "cat /run/dnsmasq.leases",
            "cat /mnt/data/udapi-config/dnsmasq.lease",
        ),
        "firewall": (
            "uname -a",
            "cat /etc/os-release",
            "ubnt-device-info summary",
            "ip -details address show",
            "ip -4 route show table all",
            "ip -6 route show table all",
            "ip -4 neigh show",
            "ip -6 neigh show",
            "bridge vlan show",
            "ss -lntup",
            "iptables-save",
            "nft list ruleset",
            "ipset save",
            "lldpcli show neighbors details",
            "cat /run/dnsmasq.leases",
            "cat /mnt/data/udapi-config/dnsmasq.lease",
        ),
        "switch": (
            "uname -a",
            "cat /etc/os-release",
            "ubnt-device-info",
            "mca-cli-op info",
            "mca-cli-op show",
            "ip -details address show",
            "ip -details link show",
            "ip -4 route show table all",
            "ip -6 route show table all",
            "ip -4 neigh show",
            "ip -6 neigh show",
            "bridge link show",
            "bridge vlan show",
            "bridge fdb show",
            "swctrl port show",
            "swctrl mac show",
            "swctrl vlan show",
            "stp show",
            "lldpcli show neighbors details",
            "cat /run/dnsmasq.leases",
            "cat /mnt/data/udapi-config/dnsmasq.lease",
            "ss -lntup",
        ),
    },
}

DEVICE_TYPES_BY_VENDOR = {
    vendor: tuple(templates)
    for vendor, templates in TEMPLATES.items()
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
    reason: str = Field(default="", max_length=500)
    originating_host: str = Field(min_length=1, max_length=255)
    vendor: Literal["vyos", "cisco", "juniper", "pfsense", "unifi"]
    device_type: Literal["router", "firewall", "switch"]
    device_types: list[Literal["router", "firewall", "switch"]] | None = Field(
        default=None, min_length=1, max_length=2
    )
    device_address: str = Field(min_length=1, max_length=255)
    device_name: str | None = Field(default=None, max_length=100)
    username: str = Field(min_length=1, max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    key_path: str | None = Field(default=None, max_length=200)
    authentication_mode: Literal["password_prompt", "key"] = "key"
    accountability_interface: str = Field(min_length=1, max_length=64)
    additional_commands: list[str] = Field(default_factory=list, max_length=MAX_ADDITIONAL_COMMANDS)

    @model_validator(mode="after")
    def validate_vendor_device_type(self) -> "DeviceConfigPlan":
        selected = list(dict.fromkeys(self.device_types or [self.device_type]))
        unsupported = [item for item in selected if item not in TEMPLATES.get(self.vendor, {})]
        if unsupported:
            supported = ", ".join(DEVICE_TYPES_BY_VENDOR.get(self.vendor, ()))
            raise ValueError(
                f"{self.vendor} does not provide a {unsupported[0]} collection profile; "
                f"choose one of: {supported}"
            )
        if "switch" in selected and len(selected) > 1:
            raise ValueError("Switch collection cannot be combined with Router or Firewall")
        self.device_types = selected
        self.device_type = (
            "firewall" if set(selected) == {"router", "firewall"} else selected[0]
        )
        return self

    @field_validator("operator", "originating_host", "device_address", "username")
    @classmethod
    def clean_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank")
        return value

    @field_validator("reason")
    @classmethod
    def clean_optional_reason(cls, value: str) -> str:
        return value.strip()

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


def _control_ssh_args_for_plan(plan: DeviceConfigPlan, control_path: Path) -> list[str]:
    return [
        "ssh", "-S", str(control_path), "-p", str(plan.ssh_port),
        f"{plan.username}@{plan.device_address}",
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


def _interactive_collection_command(
    plan: DeviceConfigPlan,
    commands: list[str],
    remote_output: str | None,
) -> tuple[str | None, str]:
    """Return the stdin and remote command used by the interactive collector."""
    if plan.vendor == "vyos":
        if not remote_output:
            raise ValueError("VyOS interactive collection requires a remote output path")
        remote_input = "\n".join(
            ["source /opt/vyatta/etc/functions/script-template"]
            + [f"run {command}" for command in commands]
            + ["exit"]
        ) + "\n"
        return remote_input, f"vbash -s > {shlex.quote(remote_output)}"
    if plan.vendor == "pfsense":
        if not remote_output:
            raise ValueError("pfSense interactive collection requires a remote output path")
        labeled_commands: list[str] = []
        for command in commands:
            labeled_commands.extend([f"printf '\\n===== {command} =====\\n'", command])
        remote_script = "{ " + "; ".join(labeled_commands) + f"; }} > {shlex.quote(remote_output)}"
        return None, f"sh -c {shlex.quote(remote_script)}"
    if plan.vendor == "unifi":
        labeled_commands = []
        for command in commands:
            labeled_commands.extend(
                [
                    f"printf '\\n===== {command} =====\\n'",
                    (
                        f"{command} 2>&1 || "
                        "printf '\\n[NCT] Command unavailable or returned a non-zero status.\\n'"
                    ),
                ]
            )
        remote_script = "{ " + "; ".join(labeled_commands) + "; }"
        return None, f"sh -c {shlex.quote(remote_script)}"
    return None, "; ".join(commands)


def _history_remote_command(plan: DeviceConfigPlan) -> tuple[str | None, str]:
    command = COMMAND_HISTORY_COMMANDS[plan.vendor]
    if plan.vendor == "vyos":
        return (
            "\n".join(
                [
                    "source /opt/vyatta/etc/functions/script-template",
                    f"run {command}",
                    "exit",
                ]
            )
            + "\n",
            "vbash -s",
        )
    if plan.vendor in {"pfsense", "unifi"}:
        return None, f"sh -c {shlex.quote(command)}"
    return None, command


def build_plan(plan: DeviceConfigPlan) -> dict:
    selected_device_types = plan.device_types or [plan.device_type]
    template_commands = list(dict.fromkeys(
        command
        for device_type in selected_device_types
        for command in TEMPLATES[plan.vendor][device_type]
    ))
    additional_commands = list(plan.additional_commands)
    history_command = COMMAND_HISTORY_COMMANDS[plan.vendor]
    collection_commands = template_commands + additional_commands
    commands = [history_command] + [
        command for command in collection_commands if command != history_command
    ]
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
    ssh_base_args = list(ssh_args)
    history_input, history_remote_command = _history_remote_command(plan)
    history_ssh_args = ssh_base_args + [target, history_remote_command]
    if interactive:
        remote_input = None
        ssh_args += [target]
        ssh_command = shlex.join(ssh_args)
    elif plan.vendor == "vyos":
        remote = "vbash -s"
        remote_input = "\n".join(
            ["source /opt/vyatta/etc/functions/script-template"]
            + [f"run {command}" for command in collection_commands]
            + ["exit"]
        ) + "\n"
        ssh_args += [target, remote]
        script_lines = remote_input.rstrip("\n").splitlines()
        ssh_command = f"printf '%s\\n' {shlex.join(script_lines)} | {shlex.join(ssh_args)}"
    elif plan.vendor == "unifi":
        remote_input, remote = _interactive_collection_command(plan, collection_commands, None)
        ssh_args += [target, remote]
        ssh_command = shlex.join(ssh_args)
    else:
        remote_input = None
        ssh_args += [target, "; ".join(collection_commands)]
        ssh_command = shlex.join(ssh_args)
    run_dir = CONFIG_DIR / run_id
    local_file = f"{name}-{run_id[:12]}-config.txt"
    local_output = run_dir / local_file
    retained_output = run_dir / "stdout.txt"
    remote_file_workflow = interactive and plan.vendor in {"vyos", "pfsense"}
    remote_output = f"/tmp/{local_file}" if remote_file_workflow else None
    transfer_method = (
        "scp_control_session"
        if remote_file_workflow
        else "ssh_command_sequence" if plan.vendor == "cisco" else "ssh_stdout"
    )
    scp_args: list[str] | None = None
    cleanup_args: list[str] | None = None
    execution_steps: list[dict[str, str]] = []

    def add_step(phase: str, location: str, kind: str, command: str, detail: str) -> None:
        execution_steps.append(
            {
                "phase": phase,
                "location": location,
                "kind": kind,
                "command": command,
                "detail": detail,
            }
        )

    if not interactive and plan.key_path:
        add_step(
            "Validate local SSH key",
            "NCT host",
            "system command",
            shlex.join(["ssh-keygen", "-y", "-f", plan.key_path]),
            "Confirms that the analyzer can read and parse the selected private key without exposing its contents.",
        )
    add_step(
        "Start accountability capture",
        "NCT host",
        "system command",
        shlex.join(capture_argv(plan.accountability_interface, run_dir / "accountability.pcap")),
        "Starts before the SSH connection and is stopped after the session closes.",
    )
    if interactive:
        control_path = Path("<runtime-ssh-control-socket>")
        control_args = _control_ssh_args_for_plan(plan, control_path)
        add_step(
            "Open one-time SSH session",
            "NCT host",
            "system command",
            shlex.join(_interactive_master_args(plan, control_path)),
            "The runtime replaces the displayed control-socket placeholder with a private temporary path. The password is entered through the protected prompt and never added to this command.",
        )
        add_step(
            "Verify authenticated SSH session",
            "NCT host",
            "system command",
            shlex.join(control_args[:-1] + ["-O", "check", control_args[-1]]),
            "Checks the private control session after immediate authentication or again after the one-time password prompt succeeds.",
        )
        remote_input, remote_command = _interactive_collection_command(
            plan, collection_commands, remote_output
        )
        collection_args = control_args + [remote_command]
        collection_command = shlex.join(collection_args)
        if remote_input:
            script_lines = remote_input.rstrip("\n").splitlines()
            collection_command = f"printf '%s\\n' {shlex.join(script_lines)} | {collection_command}"
        add_step(
            "Capture command history",
            "Network device over SSH",
            "device command",
            history_command,
            "Runs before configuration and state collection. NCT retains the result separately and labels known NCT collection commands during analysis.",
        )
        add_step(
            "Run read-only device collection",
            "Network device over SSH",
            "device command",
            collection_command,
            (
                f"The device writes the command output to the temporary file {remote_output}."
                if remote_file_workflow
                else "The device returns the command output directly through the authenticated SSH stream; no remote file is created."
            ),
        )
        if remote_file_workflow:
            scp_args = [
                "scp", "-q", "-P", str(plan.ssh_port),
                "-o", f"ControlPath={control_path}",
                f"{target}:{remote_output}", str(local_output),
            ]
            add_step(
                "Copy temporary output to NCT",
                "NCT host",
                "system command",
                shlex.join(scp_args),
                f"Creates the retained local collection file {local_output}.",
            )
        else:
            add_step(
                "Retain streamed output",
                "NCT evidence storage",
                "internal file write",
                str(local_output),
                "NCT writes the SSH standard output directly to this local file.",
            )
        add_step(
            "Normalize retained output",
            "NCT evidence storage",
            "internal file write",
            str(retained_output),
            "NCT keeps the complete collection file for analysis and stores a small normalized response preview alongside it.",
        )
        if remote_file_workflow:
            cleanup_args = control_args + [f"rm -f -- {shlex.quote(remote_output)}"]
            add_step(
                "Remove temporary device file",
                "Network device over SSH",
                "cleanup command",
                shlex.join(cleanup_args),
                "Runs even when collection or copy-back fails; the saved manifest records whether cleanup was confirmed.",
            )
        add_step(
            "Close one-time SSH session",
            "NCT host",
            "system command",
            shlex.join(control_args[:-1] + ["-O", "exit", control_args[-1]]),
            "Closes the in-memory authenticated connection and removes its temporary control socket.",
        )
    else:
        add_step(
            "Capture command history",
            "Network device over SSH",
            "device command",
            history_command,
            "Runs before configuration and state collection. NCT retains the result separately and labels known NCT collection commands during analysis.",
        )
        add_step(
            "Run read-only device collection",
            "Network device over SSH",
            "device command",
            ssh_command,
            "The device returns output through SSH; key-based collection does not create or copy a remote temporary file.",
        )
        add_step(
            "Retain streamed output",
            "NCT evidence storage",
            "internal file write",
            str(local_output),
            "NCT writes SSH standard output directly to this complete local evidence file and keeps a small API response preview separately.",
        )
    return {
        "run_id": run_id,
        "operator": plan.operator,
        "vendor": plan.vendor,
        "device_type": plan.device_type,
        "device_types": selected_device_types,
        "device_role_label": " + ".join(item.title() for item in selected_device_types),
        "device_address": plan.device_address,
        "device_name": plan.device_name,
        "username": plan.username,
        "accountability_interface": plan.accountability_interface,
        "capture_command": next(
            step["command"] for step in execution_steps
            if step["phase"] == "Start accountability capture"
        ),
        "template_commands": template_commands,
        "additional_commands": additional_commands,
        "commands": commands,
        "history_command": history_command,
        "collection_commands": collection_commands,
        "history_input": history_input,
        "history_ssh_args": history_ssh_args,
        "ssh_command": ssh_command,
        "ssh_args": ssh_args,
        "remote_input": remote_input,
        "scp_command": shlex.join(scp_args) if scp_args else None,
        "remote_output_path": remote_output,
        "local_output_name": local_file,
        "authentication_mode": plan.authentication_mode,
        "transfer_method": transfer_method,
        "execution_steps": execution_steps,
        "cleanup_plan": (
            "Create a temporary output file on the device, copy it back to the analyzer, delete the remote file, and close the SSH session."
            if remote_file_workflow
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
        "device_types": preview["device_types"],
        "device_role_label": preview["device_role_label"],
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
        "history_command": preview["history_command"],
        "ssh_command": preview["ssh_command"],
        "scp_command": preview["scp_command"],
        "transfer_method": preview["transfer_method"],
        "remote_output_path": preview["remote_output_path"],
        "execution_steps": preview["execution_steps"],
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


class DeviceDeleteConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: str = Field(min_length=1, max_length=100)


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
    session.manifest["output_complete"] = (
        status == "completed" and not bool(session.manifest.get("output_truncated"))
    )
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
    return _control_ssh_args_for_plan(session.plan, session.control_path)


def _read_text_prefix(path: Path, limit: int) -> str:
    if not path.is_file() or limit <= 0:
        return ""
    with path.open("rb") as handle:
        return handle.read(limit).decode("utf-8", errors="replace")


def _limit_retained_collection_file(path: Path) -> bool:
    """Apply the disk-safety boundary after a streamed collection."""
    if not path.is_file() or path.stat().st_size <= MAX_RETAINED_COLLECTION_BYTES:
        return False
    with path.open("r+b") as handle:
        handle.truncate(MAX_RETAINED_COLLECTION_BYTES)
    return True


def _file_has_useful_device_output(path: Path) -> bool:
    if not path.is_file():
        return False
    meaningful_length = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.lstrip().startswith(("% Invalid", "% Ambiguous", "% Incomplete")):
                continue
            meaningful_length += len(line)
            if meaningful_length >= 20:
                return True
    return False


def _stream_command_to_file(
    args: list[str], *, input_text: str | None, output_path: Path, timeout: int
) -> tuple[subprocess.CompletedProcess[str], bool]:
    """Send SSH stdout directly to retained storage instead of holding it in memory."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", errors="replace") as output:
        completed = subprocess.run(
            args,
            input=input_text,
            stdout=output,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    return completed, _limit_retained_collection_file(output_path)


def _useful_device_output(value: str) -> bool:
    cleaned = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", value or "").strip()
    if not cleaned:
        return False
    meaningful = [
        line.strip()
        for line in cleaned.splitlines()
        if line.strip()
        and not line.lstrip().startswith(("% Invalid", "% Ambiguous", "% Incomplete"))
    ]
    return len("\n".join(meaningful)) >= 20


def _extract_command_section(path: Path, command: str) -> str:
    """Read one early labeled command section without loading a large collection."""
    if not path.is_file():
        return ""
    prefix = _read_text_prefix(path, min(MAX_RESPONSE_OUTPUT_CHARS, 512_000))
    marker = f"===== {command} ====="
    start = prefix.find(marker)
    if start < 0:
        return ""
    body = prefix[start + len(marker):].lstrip("\r\n")
    next_marker = body.find("\n===== ")
    return (body[:next_marker] if next_marker >= 0 else body).strip()


def _capture_history_to_file(
    ssh_args: list[str],
    history_input: str | None,
    output_path: Path,
) -> tuple[str, str, bool]:
    """Capture history first; preserve an explicit unavailable record on failure."""
    try:
        completed, truncated = _stream_command_to_file(
            ssh_args,
            input_text=history_input,
            output_path=output_path,
            timeout=45,
        )
        value = _read_text_prefix(output_path, MAX_RESPONSE_OUTPUT_CHARS).strip()
        if completed.returncode == 0 and value:
            return "captured", completed.stderr[:4000], truncated
        detail = completed.stderr.strip() or "The device returned no command-history entries."
        output_path.write_text(f"[NCT] Command history unavailable: {detail}\n")
        return "unavailable", detail[:4000], truncated
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        detail = "Command-history capture timed out." if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(f"[NCT] Command history unavailable: {detail}\n")
        return "unavailable", detail[:4000], False


def _normalized_cisco_shell_line(raw_line: str) -> str:
    """Remove terminal control sequences while retaining readable evidence."""
    value = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", raw_line or "")
    value = value.replace("\r", "").rstrip("\n")
    while "\b" in value:
        value = re.sub(r"[^\b]\b", "", value)
    return value.replace("\b", "")


def _cisco_echoed_command(line: str, sent_commands: list[str]) -> str | None:
    stripped = line.strip()
    for command in sent_commands:
        if stripped == command or re.fullmatch(
            rf".{{0,160}}[>#]\s*{re.escape(command)}\s*", stripped
        ):
            return command
    return None


def _cisco_transcript_lines(lines, sent_commands: list[str]):
    """Yield the command and cleaned evidence from one Cisco shell transcript."""
    current_command: str | None = None
    for raw_line in lines:
        raw_line = _normalized_cisco_shell_line(raw_line)
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("connection to ") and line.lower().endswith(" closed."):
            continue
        echoed_command = _cisco_echoed_command(line, sent_commands)
        if echoed_command:
            current_command = echoed_command
            continue
        if re.fullmatch(r".{0,160}[>#]\s*", line):
            continue
        if current_command:
            yield current_command, raw_line.rstrip()


def _clean_cisco_shell_lines(lines, sent_commands: list[str]):
    """Yield cleaned Cisco evidence one line at a time."""
    for _command, line in _cisco_transcript_lines(lines, sent_commands):
        yield line


def _clean_cisco_shell_output(value: str, sent_commands: list[str]) -> str:
    """Remove terminal echoes while preserving the device's evidence and errors."""
    return "\n".join(_clean_cisco_shell_lines((value or "").splitlines(), sent_commands)).strip()


def _read_cisco_pty_until_prompt(
    master_fd: int,
    process: subprocess.Popen[bytes],
    timeout: float,
) -> tuple[str, str | None, bool]:
    """Read one Cisco shell response through its PTY until the next device prompt."""
    deadline = time.monotonic() + max(0.1, timeout)
    output = bytearray()
    prompt: str | None = None
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            [master_fd], [], [], min(0.25, max(0.0, deadline - time.monotonic()))
        )
        if ready:
            try:
                chunk = os.read(master_fd, 65_536)
            except OSError:
                chunk = b""
            if not chunk:
                break
            output.extend(chunk)
            prompt_window = output[-8192:]
            normalized = "\n".join(
                _normalized_cisco_shell_line(line)
                for line in prompt_window.decode(errors="replace").splitlines()
            )
            match = re.search(r"(?:^|\n)([^\n]{1,160}[>#])\s*$", normalized)
            if match:
                prompt = match.group(1).strip()
                return output.decode(errors="replace"), prompt, True
        elif process.poll() is not None:
            break
    return output.decode(errors="replace"), prompt, False


def _collect_cisco_command_outputs(
    ssh_prefix: list[str], commands: list[str]
) -> tuple[dict[str, str], set[str], str, int, str | None]:
    """Run Cisco commands one at a time, waiting for the prompt after every command."""
    pager_commands = {"terminal length 0", "terminal pager 0"}
    pager_command = next((command for command in commands if command in pager_commands), None)
    requested_commands = [command for command in commands if command not in pager_commands]
    history_command = next(
        (command for command in requested_commands if command == "show history"), None
    )
    send_commands = (
        ([history_command] if history_command else [])
        + ([pager_command] if pager_command else [])
        + [command for command in requested_commands if command != history_command]
    )
    shell_args = ssh_prefix[:-1] + ["-tt", ssh_prefix[-1]]
    master_fd, slave_fd = pty.openpty()
    process: subprocess.Popen[bytes] | None = None
    output_by_command: dict[str, str] = {}
    responded_commands: set[str] = set()
    transcript_tail = ""
    transport_error: str | None = None
    deadline = time.monotonic() + CISCO_COLLECTION_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            shell_args,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
        os.close(slave_fd)
        slave_fd = -1
        initial, _prompt, ready = _read_cisco_pty_until_prompt(
            master_fd, process, min(30.0, max(0.1, deadline - time.monotonic()))
        )
        transcript_tail = initial[-4000:]
        if not ready:
            transport_error = "The Cisco SSH session did not reach a device prompt."
        for command in send_commands:
            if transport_error:
                break
            os.write(master_fd, (command + "\n").encode())
            response, _prompt, complete = _read_cisco_pty_until_prompt(
                master_fd, process, max(0.1, deadline - time.monotonic())
            )
            transcript_tail = (transcript_tail + response)[-4000:]
            if not complete:
                transport_error = (
                    "The Cisco SSH session ended before every requested command completed."
                )
                break
            responded_commands.add(command)
            if command in requested_commands:
                output_by_command[command] = _clean_cisco_shell_output(response, [command])
        if not transport_error:
            os.write(master_fd, b"exit\n")
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                transport_error = "The Cisco SSH session did not close cleanly after collection."
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        elif process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        exit_code = process.returncode if process.returncode is not None else 255
        return output_by_command, responded_commands, transcript_tail, exit_code, transport_error
    finally:
        if slave_fd >= 0:
            os.close(slave_fd)
        try:
            os.close(master_fd)
        except OSError:
            pass
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)


def _run_cisco_command_sequence(
    ssh_prefix: list[str], commands: list[str]
) -> tuple[str, str, int, list[str], str | None]:
    """Collect every Cisco command through one prompt-gated interactive shell."""
    pager_commands = {"terminal length 0", "terminal pager 0"}
    requested_commands = [command for command in commands if command not in pager_commands]
    outputs, responded, transcript_tail, exit_code, transport_error = (
        _collect_cisco_command_outputs(ssh_prefix, commands)
    )
    sections = [
        f"===== {command} =====\n{outputs.get(command, '').rstrip()}\n"
        for command in requested_commands if command in responded
    ]
    failed_commands = [
        command for command in requested_commands
        if exit_code != 0
        or command not in responded
        or not _useful_device_output(outputs.get(command, ""))
    ]
    running_config_collected = _useful_device_output(outputs.get("show running-config", ""))
    retained = "\n".join(sections)
    if not _useful_device_output(retained):
        fallback = _clean_cisco_shell_output(transcript_tail, commands)
        if fallback:
            retained = f"===== Cisco interactive session =====\n{fallback.rstrip()}\n"
    fatal_error = None
    if transport_error:
        fatal_error = transport_error
    elif not _useful_device_output(retained):
        fatal_error = "The Cisco device returned no usable collection output."
    elif "show running-config" in commands and not running_config_collected:
        fatal_error = (
            "The Cisco device did not return its running configuration; "
            "the collection was not marked complete."
        )
    elif exit_code != 0:
        fatal_error = "The Cisco SSH session ended before a clean collection completion."
    return retained, transport_error or "", exit_code, failed_commands, fatal_error


def _run_cisco_command_sequence_to_file(
    ssh_prefix: list[str], commands: list[str], output_path: Path
) -> tuple[str, int, list[str], str | None, bool]:
    """Retain one prompt-gated Cisco shell response for each requested command."""
    pager_commands = {"terminal length 0", "terminal pager 0"}
    requested_commands = [command for command in commands if command not in pager_commands]
    outputs, responded, _transcript_tail, exit_code, transport_error = (
        _collect_cisco_command_outputs(ssh_prefix, commands)
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", errors="replace") as retained:
        first = True
        for command in requested_commands:
            if command not in responded:
                continue
            if not first:
                retained.write("\n")
            retained.write(f"===== {command} =====\n")
            value = outputs.get(command, "").rstrip()
            if value:
                retained.write(value + "\n")
            first = False
    useful_lengths = {
        command: len(outputs.get(command, "").strip())
        if _useful_device_output(outputs.get(command, "")) else 0
        for command in requested_commands
    }
    overall_useful_length = sum(useful_lengths.values())
    failed_commands = [
        command for command in requested_commands
        if exit_code != 0 or command not in responded or useful_lengths[command] < 20
    ]
    running_config_collected = useful_lengths.get("show running-config", 0) >= 20
    output_truncated = _limit_retained_collection_file(output_path)
    fatal_error = None
    if transport_error:
        fatal_error = transport_error
    elif overall_useful_length < 20:
        fatal_error = "The Cisco device returned no usable collection output."
    elif "show running-config" in commands and not running_config_collected:
        fatal_error = (
            "The Cisco device did not return its running configuration; "
            "the collection was not marked complete."
        )
    elif exit_code != 0:
        fatal_error = "The Cisco SSH session ended before a clean collection completion."
    return transport_error or "", exit_code, failed_commands, fatal_error, output_truncated


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
    output_truncated = False
    history_path = session.run_dir / "command-history.txt"
    history_status = "unavailable"
    history_truncated = False
    try:
        if plan.vendor != "cisco":
            history_input, history_remote = _history_remote_command(plan)
            history_status, history_error, history_truncated = _capture_history_to_file(
                _control_ssh_args(session) + [history_remote],
                history_input,
                history_path,
            )
            if history_error:
                stderr_parts.append(f"Command history: {history_error}")
        if plan.vendor in {"vyos", "pfsense"}:
            transfer_method = "scp_control_session"
            remote_created = True
            remote_input, remote_command = _interactive_collection_command(
                plan, preview["collection_commands"], remote_output
            )
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
        elif plan.vendor == "cisco":
            transfer_method = "ssh_command_sequence"
            command_stderr, exit_code, failed_commands, collection_error, output_truncated = (
                _run_cisco_command_sequence_to_file(
                    _control_ssh_args(session), preview["commands"], local_output
                )
            )
            if command_stderr:
                stderr_parts.append(command_stderr[:20_000])
            if failed_commands:
                stderr_parts.append(
                    "Some Cisco commands returned no usable evidence: "
                    + ", ".join(failed_commands)
                )
            history_value = _extract_command_section(
                local_output, preview["history_command"]
            )
            if history_value:
                history_path.write_text(history_value.rstrip() + "\n")
                history_status = "captured"
            else:
                history_path.write_text(
                    "[NCT] Command history unavailable: the device returned no history section.\n"
                )
            if collection_error:
                raise RuntimeError(collection_error)
        else:
            remote_input, remote_command = _interactive_collection_command(
                plan, preview["collection_commands"], None
            )
            collected, output_truncated = _stream_command_to_file(
                _control_ssh_args(session) + [remote_command],
                input_text=remote_input,
                output_path=local_output,
                timeout=120,
            )
            exit_code = collected.returncode
            if collected.stderr:
                stderr_parts.append(collected.stderr[:20_000])
            if collected.returncode != 0:
                raise RuntimeError("The remote collection command returned a non-zero result.")
            if not _file_has_useful_device_output(local_output):
                raise RuntimeError("The device returned no usable collection output.")
        if plan.vendor in {"vyos", "pfsense"}:
            output_truncated = _limit_retained_collection_file(local_output)
        (session.run_dir / "stdout.txt").write_text(_read_text_prefix(local_output, MAX_RESPONSE_OUTPUT_CHARS))
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
        if local_output.is_file() and not (session.run_dir / "stdout.txt").is_file():
            (session.run_dir / "stdout.txt").write_text(
                _read_text_prefix(local_output, MAX_RESPONSE_OUTPUT_CHARS)
            )
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
            "output_truncated": output_truncated,
            "output_complete": status == "completed" and not output_truncated,
            "retained_output_bytes": local_output.stat().st_size if local_output.is_file() else 0,
            "output_limit_bytes": MAX_RETAINED_COLLECTION_BYTES,
            "command_history_status": history_status,
            "command_history_truncated": history_truncated,
            "command_history_artifact": "command-history.txt",
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
    # An uploaded filename can also match the normal collection-result suffix.
    # Preserve display order while ensuring it appears only once in history.
    names = list(dict.fromkeys(names))
    return [
        {
            "name": name,
            "size": (run_dir / name).stat().st_size,
            "url": f"/api/device-configs/{run_id}/files/{name}",
        }
        for name in names
        if (run_dir / name).is_file()
    ]


def device_collection_directory(run_id: str, config_dir: Path | None = None) -> Path:
    """Resolve one collection directory without permitting path traversal."""
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Invalid device collection identifier")
    root = (CONFIG_DIR if config_dir is None else config_dir).resolve()
    candidate = (root / run_id).resolve()
    if candidate.parent != root:
        raise ValueError("Invalid device collection path")
    return candidate


def _read_summary_text(run_dir: Path, filenames: list[str]) -> tuple[str, str | None, bool]:
    for filename in filenames:
        path = run_dir / filename
        if not path.is_file():
            continue
        with path.open("rb") as handle:
            raw = handle.read(MAX_SUMMARY_TEXT_BYTES + 1)
        truncated = len(raw) > MAX_SUMMARY_TEXT_BYTES
        return raw[:MAX_SUMMARY_TEXT_BYTES].decode("utf-8", errors="replace"), filename, truncated
    return "", None, False


def _configuration_source_names(run_dir: Path) -> list[str]:
    uploaded = [
        path.name for path in sorted(run_dir.glob("uploaded-*"))
        if path.is_file() and UPLOADED_ARTIFACT_RE.fullmatch(path.name)
    ]
    collected = [
        path.name for path in sorted(run_dir.glob("*-config.txt"))
        if path.is_file() and COLLECTION_ARTIFACT_RE.fullmatch(path.name)
    ]
    return list(dict.fromkeys(uploaded + collected + ["stdout.txt"]))


def _labeled_command_sections(text: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        match = re.fullmatch(r"===== (.+?) =====", raw_line.strip())
        if match:
            current = match.group(1).strip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(raw_line)
    return {command: "\n".join(lines).strip() for command, lines in sections.items()}


def _known_nct_device_commands() -> set[str]:
    values = set(COMMAND_HISTORY_COMMANDS.values())
    for templates in TEMPLATES.values():
        for commands in templates.values():
            values.update(commands)
    return {" ".join(value.lower().split()) for value in values}


def _history_command_value(raw_line: str) -> str:
    value = raw_line.strip()
    if not value or value.startswith("[NCT]") or re.fullmatch(r"#\d{9,}", value):
        return ""
    value = re.sub(r"^\s*\d+\s+", "", value)
    value = re.sub(r"^[^\s]{1,80}[>#]\s*", "", value)
    return value.strip()


def parse_command_history(
    raw_history: str,
    attempted: bool,
    nct_commands: Iterable[str] | None = None,
) -> dict:
    known = _known_nct_device_commands()
    known.update(
        " ".join(str(command).lower().split())
        for command in (nct_commands or [])
        if str(command).strip()
    )
    if re.search(r"(?im)^\s*(?:%|\[NCT\]|.*(?:permission denied|command not found|no such file|syntax error|unknown command))", raw_history):
        raw_history = ""
    entries = []
    for line_number, raw_line in enumerate(raw_history.splitlines(), start=1):
        command = _history_command_value(raw_line)
        if not command:
            continue
        normalized = " ".join(command.lower().split())
        classification = "nct_collection" if normalized in known else "other"
        entries.append(
            {
                "position": len(entries) + 1,
                "line_number": line_number,
                "command": command[:1000],
                "classification": classification,
                "label": (
                    "Matches NCT collection command (origin unverified)"
                    if classification == "nct_collection"
                    else "Operator or other activity"
                ),
            }
        )
        if len(entries) >= MAX_SUMMARY_ITEMS:
            break
    status = "captured" if entries else "unavailable" if attempted else "not_collected"
    return {
        "status": status,
        "attempted": attempted,
        "entries": entries,
        "nct_command_count": sum(
            item["classification"] == "nct_collection" for item in entries
        ),
        "other_command_count": sum(item["classification"] == "other" for item in entries),
        "scope_note": (
            "Command text alone cannot establish who ran it. Device command-history buffers vary by platform and account. Cisco and Junos history is normally limited to the current CLI session; this evidence is not a replacement for centralized AAA command accounting."
        ),
    }


def _normalized_cisco_config_lines(value: str) -> list[str]:
    ignored = (
        "building configuration",
        "current configuration :",
        "using ",
        "last configuration change",
        "nvram config last updated",
    )
    result = []
    for raw_line in value.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped == "!" or stripped.lower().startswith(ignored):
            continue
        result.append(line)
    return result


def assess_volatile_configuration(configuration_text: str, vendor: str) -> dict:
    if vendor != "cisco":
        return {
            "status": "not_supported",
            "comparable": False,
            "detail": "This platform does not expose a directly comparable Cisco-style startup and running configuration through the current guarded profile.",
            "running_only": [],
            "startup_only": [],
        }
    sections = _labeled_command_sections(configuration_text)
    for command in ("show running-config", "show startup-config"):
        value = sections.get(command, "")
        if re.search(r"(?im)^\s*(?:%|\[NCT\]|.*(?:permission denied|not present|not found|invalid input))", value):
            sections[command] = ""
    running = _normalized_cisco_config_lines(sections.get("show running-config", ""))
    startup = _normalized_cisco_config_lines(sections.get("show startup-config", ""))
    if not running or not startup:
        return {
            "status": "unavailable",
            "comparable": False,
            "detail": "Both running and startup configuration evidence are required for the volatile-memory comparison.",
            "running_only": [],
            "startup_only": [],
        }
    # Compare commands in their parent section so moving an identical line
    # to another interface/ACL remains visible.
    def contextual(lines):
        parent = ""
        result = []
        for line in lines:
            if not line[:1].isspace():
                parent = line
                result.append(line)
            else:
                result.append(f"{parent} -> {line.strip()}")
        return result
    running = contextual(running)
    startup = contextual(startup)
    running_counts = Counter(running)
    startup_counts = Counter(startup)

    def ordered_difference(lines: list[str], counts: Counter) -> list[str]:
        remaining = counts.copy()
        values = []
        for line in lines:
            if remaining[line] <= 0:
                continue
            values.append(line)
            remaining[line] -= 1
            if len(values) >= MAX_SUMMARY_ITEMS:
                break
        return values

    running_counts_only = running_counts - startup_counts
    startup_counts_only = startup_counts - running_counts
    running_only = ordered_difference(running, running_counts_only)
    startup_only = ordered_difference(startup, startup_counts_only)
    order_changed = running != startup and running_counts == startup_counts
    different = bool(running_only or startup_only or order_changed)
    return {
        "status": "different" if different else "matching",
        "comparable": True,
        "detail": (
            "The live running configuration differs from the saved startup configuration. "
            + ("Command order differs; review the full configurations. " if order_changed else "")
            + "Validate authorized unsaved work before treating this as adversary activity. This comparison does not detect memory-only code."
            if different
            else "The retained running and startup configurations match after removing volatile headers."
        ),
        "running_only": running_only,
        "startup_only": startup_only,
        "running_only_count": sum(running_counts_only.values()),
        "startup_only_count": sum(startup_counts_only.values()),
        "truncated": (
            sum(running_counts_only.values()) > len(running_only)
            or sum(startup_counts_only.values()) > len(startup_only)
        ),
    }


def _evidence_lines(text: str, patterns: tuple[re.Pattern[str], ...]) -> list[dict]:
    records: list[dict] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line in seen or not any(pattern.search(line) for pattern in patterns):
            continue
        seen.add(line)
        records.append({"line_number": line_number, "evidence": line[:1000]})
        if len(records) >= MAX_SUMMARY_ITEMS:
            break
    return records


def _merge_evidence(*groups: list[dict]) -> list[dict]:
    records: list[dict] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            evidence = str(item.get("evidence") or "")
            if not evidence or evidence in seen:
                continue
            seen.add(evidence)
            records.append(item)
            if len(records) >= MAX_SUMMARY_ITEMS:
                return records
    return records


def _linux_policy_evidence(text: str) -> dict[str, list[dict]]:
    """Classify retained iptables-save and ipset-save output by table context."""
    firewall_acl: list[dict] = []
    nat: list[dict] = []
    network_objects: list[dict] = []
    table: str | None = None
    chain_orders: dict[tuple[str, str], int] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if line.startswith("*") and len(line) > 1:
            table = line[1:].strip().lower()
            continue
        if line == "COMMIT":
            table = None
            continue
        record = {
            "line_number": line_number,
            "evidence": line[:1000],
            "source_format": "linux_saved_rules",
        }
        rule = re.match(r"^-A\s+(?P<chain>\S+)(?P<body>.*)$", line, re.I)
        if rule and table:
            chain = rule.group("chain")
            order_key = (table, chain)
            chain_orders[order_key] = chain_orders.get(order_key, 0) + 1
            record.update({
                "table": table,
                "chain": chain,
                "rule_order": chain_orders[order_key],
            })
            action = re.search(r"(?:^|\s)-j\s+(\S+)", rule.group("body"), re.I)
            protocol = re.search(r"(?:^|\s)-p\s+(\S+)", rule.group("body"), re.I)
            source = re.search(r"(?:^|\s)-s\s+(\S+)", rule.group("body"), re.I)
            destination = re.search(r"(?:^|\s)-d\s+(\S+)", rule.group("body"), re.I)
            source_set = re.search(r"--match-set\s+(\S+)\s+src\b", rule.group("body"), re.I)
            destination_set = re.search(r"--match-set\s+(\S+)\s+dst\b", rule.group("body"), re.I)
            destination_port = re.search(r"(?:^|\s)--?dports?\s+(\S+)", rule.group("body"), re.I)
            for key, match in (
                ("action", action),
                ("protocol", protocol),
                ("source", source),
                ("destination", destination),
                ("source_set", source_set),
                ("destination_set", destination_set),
                ("destination_ports", destination_port),
            ):
                if match:
                    record[key] = match.group(1)
        elif table:
            record["table"] = table
        if table == "filter" and (line.startswith("-A ") or re.match(r"^:[A-Za-z0-9_.:-]+\s+(?:ACCEPT|DROP|REJECT|-)", line, re.I)):
            firewall_acl.append(record)
        elif table == "nat" and (line.startswith("-A ") or re.match(r"^:[A-Za-z0-9_.:-]+\s+(?:ACCEPT|DROP|REJECT|-)", line, re.I)):
            nat.append(record)
        elif re.match(r"^(?:create|add)\s+[A-Za-z0-9_.:-]+(?:\s|$)", line, re.I):
            network_objects.append(record)
    return {
        "firewall_acl": firewall_acl[:MAX_SUMMARY_ITEMS],
        "nat": nat[:MAX_SUMMARY_ITEMS],
        "network_objects": network_objects[:MAX_SUMMARY_ITEMS],
    }


VLAN_PATTERNS = (
    re.compile(r"^vlan\s+\d+\b", re.I),
    re.compile(r"\bswitchport\s+(?:access|trunk).*\bvlan\b", re.I),
    re.compile(r"\bset\s+vlans\s+\S+\s+vlan-id\s+\d+\b", re.I),
    re.compile(r"\bvif\s+\d+\b", re.I),
    re.compile(r"<(?:vlan|vlanif)>", re.I),
)
FIREWALL_ACL_PATTERNS = (
    re.compile(r"^(?:ip\s+)?access-list\b", re.I),
    re.compile(r"^(?:standard|extended)\s+ip\s+access\s+list\b", re.I),
    re.compile(r"\bset\s+(?:firewall|security\s+policies)\b", re.I),
    re.compile(r"^(?:pass|block)\s+(?:in|out)\b", re.I),
    re.compile(r"^(?:iptables\s+-A|nft\s+add\s+rule)\b", re.I),
    re.compile(r"<rule>", re.I),
)
NAT_PATTERNS = (
    re.compile(r"\bset\s+nat\b", re.I),
    re.compile(r"^ip\s+nat\b", re.I),
    re.compile(r"^nat\s*\(", re.I),
    re.compile(r"\b(?:source-nat|destination-nat)\b", re.I),
    re.compile(r"<(?:nat|outbound)>", re.I),
)
NETWORK_OBJECT_PATTERNS = (
    re.compile(r"^(?:object|object-group)\s+network\b", re.I),
    re.compile(r"^network-object\b", re.I),
    re.compile(r"\bset\s+(?:firewall\s+group|security\s+address-book)\b", re.I),
    re.compile(r"^(?:host|subnet)\s+(?:\d{1,3}\.){3}\d{1,3}\b", re.I),
    re.compile(r"<(?:alias|network)>\b", re.I),
)
SWITCHING_PATTERNS = (
    re.compile(r"\bswitchport\b", re.I),
    re.compile(r"\b(?:mac\s+address-table|ethernet-switching\s+table|bridge\s+fdb)\b", re.I),
    re.compile(r"\bspanning[- ]tree\b", re.I),
    re.compile(r"\b(?:channel-group|port-channel|etherchannel|lacp|802\.3ad)\b", re.I),
    re.compile(r"\b(?:power\s+inline|poe)\b", re.I),
    re.compile(r"\b(?:interface-mode|port-mode)\s+(?:access|trunk)\b", re.I),
    re.compile(r"\bvlan\s+members\b", re.I),
    re.compile(r"^[0-9A-Fa-f:.]{11,17}\s+dev\s+[A-Za-z0-9_.:/-]+", re.I),
)


def active_configuration_text(configuration_text: str) -> str:
    """Exclude saved startup state and command history from live-state parsers."""
    excluded_commands = {"show startup-config", *COMMAND_HISTORY_COMMANDS.values()}
    current_command = None
    active_lines = []
    for line in configuration_text.splitlines():
        marker = re.fullmatch(r"===== (.+?) =====", line.strip())
        if marker:
            current_command = marker.group(1).strip()
        if current_command not in excluded_commands:
            active_lines.append(line)
    return "\n".join(active_lines)


def device_collection_summary(run_id: str, config_dir: Path | None = None) -> dict:
    """Create a bounded, review-oriented summary from retained device evidence."""
    run_dir = device_collection_directory(run_id, config_dir)
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("Device collection was not found")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
    configuration_text, source_filename, configuration_truncated = _read_summary_text(
        run_dir, _configuration_source_names(run_dir)
    )
    raw_output, raw_filename, raw_truncated = _read_summary_text(
        run_dir, ["stdout.txt"] + _configuration_source_names(run_dir)
    )
    history_path = run_dir / "command-history.txt"
    history_text = (
        _read_text_prefix(history_path, MAX_RESPONSE_OUTPUT_CHARS)
        if history_path.is_file()
        else _labeled_command_sections(configuration_text).get(
            str(manifest.get("history_command") or "show history"), ""
        )
    )
    command_history = parse_command_history(
        history_text,
        attempted=(
            history_path.is_file()
            or bool(manifest.get("command_history_status"))
            or bool(manifest.get("history_command"))
        ),
        nct_commands=manifest.get("commands") or [],
    )
    volatile_configuration = assess_volatile_configuration(
        configuration_text, str(manifest.get("vendor") or "").lower()
    )
    if configuration_truncated or manifest.get("output_complete") is False:
        volatile_configuration = {
            "status": "unavailable", "comparable": False,
            "detail": "The retained configuration is incomplete; collect complete running and startup evidence before comparing them.",
            "running_only": [], "startup_only": [],
        }

    # History and saved startup state are evidence for separate review, never
    # input to the current forwarding/policy parsers.
    configuration_text = active_configuration_text(configuration_text)

    from app.mac_enrichment import parse_neighbor_text
    from app.iptables_policy import parse_iptables_policy
    from app.network_map import parse_config_text
    from app.switching import merge_switch_interfaces, parse_switch_evidence
    from app.topology_neighbors import parse_topology_neighbors
    from app.vendor_policy import parse_vendor_policy

    interfaces, routes = parse_config_text(configuration_text)
    switch_detail = parse_switch_evidence(configuration_text, manifest.get("commands", []))
    interfaces = merge_switch_interfaces(interfaces, switch_detail)
    neighbors = parse_neighbor_text(configuration_text)
    topology_neighbors = parse_topology_neighbors(configuration_text)
    vlans = _evidence_lines(configuration_text, VLAN_PATTERNS)
    linux_policy = _linux_policy_evidence(configuration_text)
    iptables_policy = parse_iptables_policy(
        configuration_text, source_truncated=configuration_truncated
    )
    vendor_policy = parse_vendor_policy(configuration_text)
    firewall_acl = _merge_evidence(
        _evidence_lines(configuration_text, FIREWALL_ACL_PATTERNS),
        linux_policy["firewall_acl"],
    )
    nat = _merge_evidence(
        _evidence_lines(configuration_text, NAT_PATTERNS),
        linux_policy["nat"],
    )
    network_objects = _merge_evidence(
        _evidence_lines(configuration_text, NETWORK_OBJECT_PATTERNS),
        linux_policy["network_objects"],
    )
    network_objects_total = max(
        len(network_objects),
        int(iptables_policy["counts"]["ipsets"])
        + int(iptables_policy["counts"]["ipset_members"]),
    )
    switching = _evidence_lines(configuration_text, SWITCHING_PATTERNS)
    commands = [str(value) for value in manifest.get("commands", [])][:MAX_SUMMARY_ITEMS]
    routes = [
        {
            **route,
            "route_type": (
                "default" if route.get("network") in {"0.0.0.0/0", "::/0"}
                else "connected" if route.get("direct")
                else "routed"
            ),
        }
        for route in routes
    ]
    result = {
        "run_id": run_id,
        "source_filename": source_filename,
        "raw_filename": raw_filename,
        "configuration_truncated": configuration_truncated,
        "raw_truncated": raw_truncated,
        "counts": {
            "interfaces": len(interfaces),
            "routes": len(routes),
            "neighbors": len(neighbors),
            "topology_neighbors": len(topology_neighbors),
            "vlans": len(vlans),
            "switch_vlans": len(switch_detail.get("vlans") or []),
            "firewall_acl": len(firewall_acl),
            "nat": len(nat),
            "network_objects": len(network_objects),
            "network_objects_total": network_objects_total,
            "policy_chains": iptables_policy["counts"]["chains"],
            "policy_rules": iptables_policy["counts"]["rules"],
            "policy_sets": iptables_policy["counts"]["ipsets"],
            "policy_set_members": iptables_policy["counts"]["ipset_members"],
            "applied_policy_rules": (vendor_policy.get("counts") or {}).get("rules", 0),
            "policy_attachments": (vendor_policy.get("counts") or {}).get("attachments", 0),
            "applied_policy_objects": (vendor_policy.get("counts") or {}).get("objects", 0),
            "switching": len(switching),
            "learned_macs": len(switch_detail["mac_table"]),
            "switch_ports": len(switch_detail["ports"]),
            "port_channels": len(switch_detail["port_channels"]),
            "spanning_tree": len(switch_detail["spanning_tree"]),
            "command_results": len(switch_detail["command_results"]),
            "commands": len(commands),
            "command_history": len(command_history["entries"]),
            "non_nct_commands": command_history["other_command_count"],
            "running_only_config": volatile_configuration.get("running_only_count", 0),
            "startup_only_config": volatile_configuration.get("startup_only_count", 0),
            "lines": len(configuration_text.splitlines()),
        },
        "interfaces": interfaces[:MAX_SUMMARY_ITEMS],
        "routes": routes,
        "neighbors": neighbors[:MAX_SUMMARY_ITEMS],
        "topology_neighbors": topology_neighbors[:MAX_SUMMARY_ITEMS],
        "vlans": vlans,
        "firewall_acl": firewall_acl,
        "nat": nat,
        "network_objects": network_objects,
        "iptables_policy": iptables_policy,
        "vendor_policy": vendor_policy,
        "switching": switching,
        "switch_detail": switch_detail,
        "command_results": switch_detail["command_results"],
        "commands": commands,
        "command_history": command_history,
        "volatile_configuration": volatile_configuration,
        "configuration_text": configuration_text,
        "raw_output": raw_output,
    }
    return result


def delete_device_collection(
    run_id: str, confirmation: str, config_dir: Path | None = None
) -> dict:
    """Delete exactly one inactive collection after a valid short-lived challenge."""
    run_dir = device_collection_directory(run_id, config_dir)
    if not (run_dir / "manifest.json").is_file():
        raise FileNotFoundError("Device collection was not found")
    with _INTERACTIVE_SESSIONS_LOCK:
        if any(session.preview.get("run_id") == run_id for session in _INTERACTIVE_SESSIONS.values()):
            raise RuntimeError("An active SSH collection cannot be deleted")
    from app.poc import consume_delete_challenge

    if not consume_delete_challenge("device-collection", run_id, confirmation):
        raise PermissionError("The confirmation code is invalid or expired")
    from app.device_analysis import delete_device_analysis_storage
    from app.poc import DB_PATH
    delete_device_analysis_storage(run_id, DB_PATH)
    shutil.rmtree(run_dir)
    return {"deleted": True, "run_id": run_id}


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
    return {
        "vendors": list(VENDORS),
        "device_types": list(DEVICE_TYPES),
        "device_types_by_vendor": {
            vendor: list(types) for vendor, types in DEVICE_TYPES_BY_VENDOR.items()
        },
        "templates": {
            vendor: {device_type: list(commands) for device_type, commands in templates.items()}
            for vendor, templates in TEMPLATES.items()
        },
    }


@router.post("/preview")
def preview(plan: DeviceConfigPlan, request: Request) -> dict:
    plan = bind_signed_in_actor(request, plan, "operator")
    value = build_plan(plan)
    value.pop("ssh_args", None)
    value.pop("remote_input", None)
    return value


@router.post("/interactive/start")
def start_interactive_session(plan: DeviceConfigPlan, request: Request) -> dict:
    """Open a short-lived SSH control session and stop at the device password prompt."""
    _require_secure_password_transport(request)
    plan = bind_signed_in_actor(request, plan, "operator")
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
def preflight(plan: DeviceConfigPlan, request: Request) -> dict:
    """Validate the key and capture every non-interactive SSH access check."""
    plan = bind_signed_in_actor(request, plan, "operator")
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
def execute(plan: DeviceConfigPlan, request: Request) -> dict:
    plan = bind_signed_in_actor(request, plan, "operator")
    if plan.authentication_mode != "key":
        raise HTTPException(status_code=409, detail="Use the interactive SSH endpoints for password-prompt authentication")
    preview_data = build_plan(plan)
    key = key_preflight(plan.key_path)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    run_dir = CONFIG_DIR / preview_data["run_id"]
    run_dir.mkdir(parents=True, exist_ok=False)
    local_output = run_dir / preview_data["local_output_name"]
    manifest = manifest_for(plan, preview_data, "running", operation="configuration_pull", key_status=key["status"])
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    stdout = ""
    stderr = ""
    exit_code = None
    status = "failed"
    failure_class = None
    output_truncated = False
    process = None
    capture_stderr = None
    history_path = run_dir / "command-history.txt"
    history_status = "not_collected"
    history_truncated = False
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
            if plan.vendor == "cisco":
                stderr, exit_code, failed_commands, collection_error, output_truncated = _run_cisco_command_sequence_to_file(
                    preview_data["ssh_args"][:-1], preview_data["commands"], local_output
                )
                status = "failed" if collection_error else "completed"
                failure_class = "empty_collection_output" if collection_error else None
                if failed_commands:
                    stderr = (stderr + "\n" if stderr else "") + (
                        "Some Cisco commands returned no usable evidence: "
                        + ", ".join(failed_commands)
                    )
                if collection_error:
                    stderr = (stderr + "\n" if stderr else "") + collection_error
                history_value = _extract_command_section(
                    local_output, preview_data["history_command"]
                )
                if history_value:
                    history_path.write_text(history_value.rstrip() + "\n")
                    history_status = "captured"
                else:
                    history_path.write_text(
                        "[NCT] Command history unavailable: the device returned no history section.\n"
                    )
            else:
                history_status, history_error, history_truncated = _capture_history_to_file(
                    preview_data["history_ssh_args"],
                    preview_data["history_input"],
                    history_path,
                )
                if history_error:
                    stderr = f"Command history: {history_error}"
                completed, output_truncated = _stream_command_to_file(
                    preview_data["ssh_args"],
                    input_text=preview_data["remote_input"],
                    output_path=local_output,
                    timeout=120,
                )
                collection_stderr = completed.stderr[:50_000]
                stderr = (stderr + "\n" if stderr and collection_stderr else stderr) + collection_stderr
                exit_code = completed.returncode
                status = "completed" if completed.returncode == 0 else "failed"
                failure_class = None if completed.returncode == 0 else classify_ssh_failure(stderr, key["status"])
                if status == "completed" and not _file_has_useful_device_output(local_output):
                    status = "failed"
                    failure_class = "empty_collection_output"
                    stderr = (stderr + "\n" if stderr else "") + "The device returned no usable collection output."
        except subprocess.TimeoutExpired as exc:
            stderr = (exc.stderr or "Command timed out") if isinstance(exc.stderr, str) else "Command timed out"
            stderr = stderr[:50_000]
            status = "timed_out"
            failure_class = "network_connection_problem"
        except RuntimeError as exc:
            stderr = str(exc)
            status = "failed"
            failure_class = "empty_collection_output"
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
    stdout = _read_text_prefix(local_output, MAX_RESPONSE_OUTPUT_CHARS)
    (run_dir / "stdout.txt").write_text(stdout)
    (run_dir / "stderr.txt").write_text(stderr)
    manifest.update({
        "status": status,
        "completed_at": utc_now(),
        "exit_code": exit_code,
        "failure_class": failure_class,
        "output_truncated": output_truncated,
        "output_complete": status == "completed" and not output_truncated,
        "retained_output_bytes": local_output.stat().st_size if local_output.is_file() else 0,
        "output_limit_bytes": MAX_RETAINED_COLLECTION_BYTES,
        "local_output_name": preview_data["local_output_name"],
        "command_history_status": history_status,
        "command_history_truncated": history_truncated,
        "command_history_artifact": "command-history.txt",
    })
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return {
        **manifest,
        "stdout": stdout[:MAX_RESPONSE_OUTPUT_CHARS],
        "stderr": stderr,
        "scp_command": preview_data["scp_command"],
        "artifacts": artifact_records(preview_data["run_id"], run_dir),
    }


@router.post("/upload")
async def upload_result(
    request: Request,
    operator: str = Form(...),
    reason: str = Form(""),
    originating_host: str = Form(...),
    vendor: str = Form(...),
    device_type: str = Form(...),
    device_address: str = Form(...),
    device_name: str = Form(""),
    result_file: UploadFile = File(...),
) -> dict:
    """Import an existing router, firewall, or switch result without contacting a device."""
    values = {
        "operator": signed_in_username(request) or operator.strip(),
        "reason": reason.strip(),
        "originating_host": originating_host.strip(),
        "device_address": device_address.strip(),
    }
    required_values = (
        values["operator"],
        values["originating_host"],
        values["device_address"],
    )
    if any(not value for value in required_values):
        raise HTTPException(status_code=422, detail="Operator, originating host, and device address are required")
    if len(values["operator"]) > 100 or len(values["reason"]) > 500 or len(values["originating_host"]) > 255:
        raise HTTPException(status_code=422, detail="One or more upload fields exceed the allowed length")
    clean_device_name = device_name.strip()
    if len(clean_device_name) > 100:
        raise HTTPException(status_code=422, detail="Device name is limited to 100 characters")
    if (
        vendor not in VENDORS
        or device_type not in DEVICE_TYPES
        or device_type not in TEMPLATES.get(vendor, {})
    ):
        raise HTTPException(status_code=422, detail="Choose a supported vendor and device type")
    if not HOST_RE.fullmatch(values["device_address"]):
        raise HTTPException(status_code=422, detail="Use a hostname or IP address without shell characters")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    run_dir = CONFIG_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    original_name = (result_file.filename or "configuration-result.txt").strip()
    stored_name = f"uploaded-{safe_name(original_name, 'configuration-result.txt')}"
    stored_path = run_dir / stored_name
    uploaded_size = 0
    try:
        with stored_path.open("wb") as retained:
            while chunk := await result_file.read(COLLECTION_COPY_CHUNK_BYTES):
                uploaded_size += len(chunk)
                if uploaded_size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="Result files are limited to 100 MB",
                    )
                retained.write(chunk)
    except Exception:
        stored_path.unlink(missing_ok=True)
        run_dir.rmdir()
        raise
    finally:
        await result_file.close()
    if uploaded_size == 0:
        stored_path.unlink(missing_ok=True)
        run_dir.rmdir()
        raise HTTPException(status_code=422, detail="Choose a non-empty result file")
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
        "uploaded_size": uploaded_size,
        "output_complete": True,
        "retained_output_bytes": uploaded_size,
        "output_limit_bytes": MAX_RETAINED_COLLECTION_BYTES,
        "commands": [],
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return {**manifest, "artifacts": artifact_records(run_id, run_dir)}


@router.get("")
def history(limit: int = Query(default=25, ge=1, le=100), offset: int = 0) -> list[dict]:
    if offset < 0:
        raise HTTPException(status_code=422, detail="History offset must not be negative")
    if not CONFIG_DIR.exists():
        return []
    records: list[dict] = []
    skipped = 0
    for path in sorted(CONFIG_DIR.glob("*/manifest.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            value = json.loads(path.read_text())
            if value.get("operation") == "ssh_preflight":
                continue
            if skipped < offset:
                skipped += 1
                continue
            value.pop("key_path", None)
            records.append({
                key: value.get(key)
                for key in (
                    "run_id", "created_at", "completed_at", "status", "operation",
                    "vendor", "device_type", "device_types", "device_role_label",
                    "device_address", "device_name", "username", "ssh_port",
                    "authentication_mode", "accountability_interface", "operator",
                    "originating_host", "reason", "exit_code", "failure_class",
                    "source_filename", "additional_commands", "remote_temp_created",
                    "remote_cleanup_status", "command_history_status",
                )
            })
        except (OSError, ValueError):
            continue
        if len(records) >= limit:
            break
    return records


@router.get("/network-candidates")
def network_candidates() -> dict:
    """List config-derived subnets that still need explicit operator review."""
    from app.network_map import configuration_network_candidates

    return {"candidates": configuration_network_candidates()}


@router.get("/{run_id}/summary")
def collection_summary(run_id: str) -> dict:
    try:
        return device_collection_summary(run_id)
    except (ValueError, FileNotFoundError, json.JSONDecodeError, OSError):
        raise HTTPException(status_code=404, detail="Device collection was not found") from None


@router.post("/{run_id}/delete-challenge")
def collection_delete_challenge(run_id: str) -> dict:
    try:
        run_dir = device_collection_directory(run_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Device collection was not found") from None
    if not (run_dir / "manifest.json").is_file():
        raise HTTPException(status_code=404, detail="Device collection was not found")
    from app.poc import issue_delete_challenge

    return issue_delete_challenge("device-collection", run_id)


@router.post("/{run_id}/delete")
def delete_collection(run_id: str, body: DeviceDeleteConfirmation) -> dict:
    try:
        return delete_device_collection(run_id, body.confirmation)
    except (ValueError, FileNotFoundError):
        raise HTTPException(status_code=404, detail="Device collection was not found") from None
    except PermissionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


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


@router.get("/{run_id}")
def collection_detail(run_id: str) -> dict:
    """Load one full manifest and its evidence-file metadata on demand."""
    try:
        run_dir = device_collection_directory(run_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Device collection was not found") from None
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise HTTPException(status_code=404, detail="Device collection was not found")
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise HTTPException(status_code=422, detail="The retained collection manifest is unreadable") from None
    value.pop("key_path", None)
    value["artifacts"] = artifact_records(run_id, run_dir)
    return value
