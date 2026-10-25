from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_network_scope_management_has_one_navigation_home():
    shell = (ROOT / "app" / "shell_ui.py").read_text(encoding="utf-8")
    mission = (ROOT / "app" / "mission_environment_ui.py").read_text(encoding="utf-8")
    main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")

    assert 'id="nct-scopes-link"' not in shell
    assert '>Network Scopes</a>' not in shell
    assert 'href="/settings/mission-environment"' in shell
    assert 'href="/settings/network-scopes"' in mission
    assert '@app.get("/settings/network-scopes"' in main
