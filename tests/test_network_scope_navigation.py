from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_network_scope_management_has_one_navigation_home():
    shell = (ROOT / "app" / "shell_ui.py").read_text(encoding="utf-8")
    mission = (ROOT / "app" / "mission_environment_ui.py").read_text(encoding="utf-8")
    main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")

    assert 'id="nct-scopes-link"' not in shell
    assert '>Network Scopes</a>' not in shell
    assert "{title:'Mission Environment',icon:'mission'" in shell
    assert "href:'/settings/mission-environment#missionScopePanel'" in shell
    assert "href:'/settings/mission-environment#noStrikePanel'" in shell
    assert "href:'/settings/mission-environment#coveragePanel'" not in shell
    assert "support:{toolPanel:['coveragePanel']}" in shell
    assert 'id="nct-mission-environment-link"' not in shell
    assert 'href="/settings/network-scopes"' not in mission
    assert 'id="scopeIdentityForm"' in mission
    assert '@app.get("/settings/network-scopes"' in main
    assert 'url="/settings/mission-environment#missionScopePanel"' in main
