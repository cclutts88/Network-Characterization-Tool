import json

from app.database import connect_database
from app.evidence_retirement import init_evidence_retirement_storage
from app.retirement_guard_cli import main


def test_guard_cli_provisions_checks_and_marks_restore_hold(tmp_path, capsys):
    data = tmp_path / "data"
    guard = tmp_path / "guard"
    data.mkdir()
    db_path = data / "analyzer.db"
    with connect_database(db_path):
        pass
    init_evidence_retirement_storage(db_path)
    identity = "docker-volume:test-data"
    assert main([
        "provision", "--guard-dir", str(guard),
        "--installation-id", "test-install", "--data-identity", identity,
    ]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "provisioned"
    assert main([
        "check", "--db", str(db_path), "--data-dir", str(data),
        "--guard-dir", str(guard), "--data-identity", identity,
    ]) == 0
    checked = json.loads(capsys.readouterr().out)
    assert checked["state"] == "ready" and checked["revision"] == 0
    assert main([
        "mark-restore-hold", "--guard-dir", str(guard),
        "--data-identity", identity, "--operation-id", "restore-test",
        "--detail", "before data replacement",
    ]) == 0
    held = json.loads(capsys.readouterr().out)
    assert held["state"] == "hold"
    assert main([
        "check", "--db", str(db_path), "--data-dir", str(data),
        "--guard-dir", str(guard), "--data-identity", identity,
    ]) == 2
    assert json.loads(capsys.readouterr().out)["state"] == "hold"

