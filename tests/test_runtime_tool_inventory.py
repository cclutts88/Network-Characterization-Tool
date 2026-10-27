from types import SimpleNamespace


def test_bundled_tool_inventory_detects_nmap_and_nct_device_capability(monkeypatch):
    import app.runtime_tool_inventory as inventory

    inventory.bundled_tool_inventory.cache_clear()
    monkeypatch.setattr(inventory.shutil, "which", lambda command: "/usr/bin/nmap")
    monkeypatch.setattr(
        inventory.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="Nmap version 7.95 ( https://nmap.org )\n", stderr=""
        ),
    )

    detected = inventory.bundled_tool_inventory()

    assert detected["nmap"]["availability"] == "available"
    assert detected["nmap"]["version_text"] == "7.95"
    assert detected["device_config"]["availability"] == "available"
    assert detected["device_config"]["version_text"] == inventory.APP_VERSION
    inventory.bundled_tool_inventory.cache_clear()


def test_runtime_overlay_preserves_access_notes_and_audit_identity(monkeypatch):
    import app.runtime_tool_inventory as inventory

    monkeypatch.setattr(
        inventory,
        "bundled_tool_inventory",
        lambda: {
            "nmap": {
                "runtime_managed": True,
                "availability": "available",
                "version_text": "7.95",
                "default_access_method": "Installed in NCT",
                "runtime_source": "Detected locally.",
            }
        },
    )
    original = [{
        "tool_key": "nmap",
        "availability": "unknown",
        "version_text": "",
        "access_method": "Approved operations path",
        "version": 4,
    }]

    result = inventory.apply_bundled_tool_inventory(original)[0]

    assert result["availability"] == "available"
    assert result["version_text"] == "7.95"
    assert result["access_method"] == "Approved operations path"
    assert result["version"] == 4
    assert result["declared_availability"] == "unknown"
