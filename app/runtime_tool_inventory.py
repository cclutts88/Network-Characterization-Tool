"""Read-only inventory for capabilities bundled with the running NCT image."""
from __future__ import annotations

from functools import lru_cache
import re
import shutil
import subprocess

from app.build_info import APP_VERSION


@lru_cache(maxsize=1)
def bundled_tool_inventory() -> dict[str, dict[str, str | bool]]:
    """Return runtime facts without writing Mission Environment declarations."""
    nmap_path = shutil.which("nmap")
    nmap_version = ""
    nmap_detail = "Nmap is not installed in the running NCT container."
    if nmap_path:
        try:
            completed = subprocess.run(
                [nmap_path, "--version"],
                capture_output=True,
                check=False,
                text=True,
                timeout=3,
            )
            first_line = (completed.stdout or completed.stderr or "").splitlines()[0]
            match = re.search(r"Nmap version\s+([^\s]+)", first_line, re.IGNORECASE)
            nmap_version = match.group(1) if match else first_line.strip()
            nmap_detail = f"Detected from {nmap_path}."
        except (OSError, subprocess.SubprocessError, IndexError):
            nmap_detail = f"The Nmap executable exists at {nmap_path}, but its version could not be read."
    return {
        "nmap": {
            "runtime_managed": True,
            "availability": "available" if nmap_path else "unavailable",
            "version_text": nmap_version,
            "default_access_method": "Installed in the NCT container" if nmap_path else "",
            "runtime_source": nmap_detail,
        },
        "device_config": {
            "runtime_managed": True,
            "availability": "available",
            "version_text": APP_VERSION,
            "default_access_method": "Built into NCT",
            "runtime_source": "Detected from the running NCT build and bundled device-collection capability.",
        },
    }


def apply_bundled_tool_inventory(tools: list[dict]) -> list[dict]:
    """Overlay runtime facts while retaining declared access notes and audit versions."""
    inventory = bundled_tool_inventory()
    enriched: list[dict] = []
    for item in tools:
        result = dict(item)
        runtime = inventory.get(str(item.get("tool_key") or ""))
        if runtime:
            result["declared_availability"] = item.get("availability")
            result["declared_version_text"] = item.get("version_text") or ""
            result.update(runtime)
            if not result.get("access_method"):
                result["access_method"] = runtime["default_access_method"]
        else:
            result["runtime_managed"] = False
        enriched.append(result)
    return enriched
