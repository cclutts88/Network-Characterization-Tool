import json

import pytest

from app import poc
from app.auth import init_auth_storage


def _request(owner: str = "alpha") -> poc.ScanRunRequest:
    return poc.ScanRunRequest(
        operator=owner,
        created_by=owner,
        executed_by=owner,
        name="Protected waiting scan",
        reason="Authorized queue assignment test",
        originating_host="nct-test",
        interface="eth0",
        profile="standard",
        targets=["192.0.2.1"],
        capture=True,
    )


def _accounts(db_path):
    init_auth_storage(db_path)
    with poc.connect_database(db_path) as db:
        for username, role, disabled in (
            ("admin", "admin", 0),
            ("alpha", "analyst", 0),
            ("bravo", "analyst", 0),
            ("charlie", "analyst", 0),
            ("inactive", "analyst", 1),
            ("observer", "viewer", 0),
        ):
            db.execute(
                """INSERT INTO analyst_users (
                    username, display_name, role, password_salt, password_hash,
                    disabled, created_at, created_by
                ) VALUES (?, ?, ?, 'salt', 'hash', ?, ?, 'test')""",
                (username, username.title(), role, disabled, poc.utc_now()),
            )


def _change(owner: str, expected: str, revision: int) -> poc.ScanRunOwnerChange:
    return poc.ScanRunOwnerChange(
        owner=owner,
        expected_owner=expected,
        expected_assignment_revision=revision,
    )


def test_assignment_rejects_competing_and_aba_stale_requests(tmp_path):
    db_path = tmp_path / "analyzer.db"
    _accounts(db_path)
    run = poc.prepare_scan_run(_request(), db_path=db_path, interfaces={"eth0"})

    first = poc.reassign_queued_scan_operator(
        run["run_id"], _change("bravo", "alpha", 0), db_path,
        actor="admin", role="admin",
    )
    assert first["owner"] == "bravo"
    assert first["queue_assignment_revision"] == 1

    with pytest.raises(poc.ScanRunAssignmentConflict):
        poc.reassign_queued_scan_operator(
            run["run_id"], _change("charlie", "alpha", 0), db_path,
            actor="admin", role="admin",
        )

    returned = poc.reassign_queued_scan_operator(
        run["run_id"], _change("alpha", "bravo", 1), db_path,
        actor="admin", role="admin",
    )
    assert returned["queue_assignment_revision"] == 2
    with pytest.raises(poc.ScanRunAssignmentConflict):
        poc.reassign_queued_scan_operator(
            run["run_id"], _change("charlie", "alpha", 0), db_path,
            actor="admin", role="admin",
        )


def test_assignment_and_dispatch_share_one_atomic_boundary(tmp_path):
    first_db = tmp_path / "assignment-first.db"
    _accounts(first_db)
    run = poc.prepare_scan_run(_request(), db_path=first_db, interfaces={"eth0"})
    poc.reassign_queued_scan_operator(
        run["run_id"], _change("bravo", "alpha", 0), first_db,
        actor="admin", role="admin",
    )
    claimed = poc.claim_next_queued_scan(first_db)
    assert claimed["owner"] == "bravo"
    assert claimed["status"] == "dispatching"

    second_db = tmp_path / "dispatch-first.db"
    _accounts(second_db)
    run = poc.prepare_scan_run(_request(), db_path=second_db, interfaces={"eth0"})
    claimed = poc.claim_next_queued_scan(second_db)
    assert claimed["owner"] == "alpha"
    with pytest.raises(poc.ScanRunAssignmentConflict):
        poc.reassign_queued_scan_operator(
            run["run_id"], _change("bravo", "alpha", 0), second_db,
            actor="admin", role="admin",
        )


def test_assignment_validates_authority_and_target_inside_transaction(tmp_path):
    db_path = tmp_path / "analyzer.db"
    _accounts(db_path)
    run = poc.prepare_scan_run(_request(), db_path=db_path, interfaces={"eth0"})

    with pytest.raises(PermissionError):
        poc.reassign_queued_scan_operator(
            run["run_id"], _change("bravo", "alpha", 0), db_path,
            actor="alpha", role="analyst",
        )
    for target in ("missing", "inactive", "observer"):
        with pytest.raises(ValueError):
            poc.reassign_queued_scan_operator(
                run["run_id"], _change(target, "alpha", 0), db_path,
                actor="admin", role="admin",
            )

    with poc.connect_database(db_path) as db:
        db.execute("UPDATE analyst_users SET disabled = 1 WHERE username = 'admin'")
    with pytest.raises(PermissionError):
        poc.reassign_queued_scan_operator(
            run["run_id"], _change("bravo", "alpha", 0), db_path,
            actor="admin", role="admin",
        )


def test_assignment_audit_failure_rolls_back_and_preserves_scan(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    _accounts(db_path)
    run = poc.prepare_scan_run(_request(), db_path=db_path, interfaces={"eth0"})
    before = poc.get_scan_run_plan(run["run_id"], db_path)

    def fail_audit(*_args, **_kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(poc, "append_scan_audit_on_connection", fail_audit)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        poc.reassign_queued_scan_operator(
            run["run_id"], _change("bravo", "alpha", 0), db_path,
            actor="admin", role="admin",
        )

    after = poc.get_scan_run_plan(run["run_id"], db_path)
    assert after == before
    with poc.connect_database(db_path) as db:
        events = db.execute(
            "SELECT event FROM scan_run_audit WHERE run_id = ? ORDER BY changed_at",
            (run["run_id"],),
        ).fetchall()
    assert [row[0] for row in events] == ["queued"]


def test_assignment_changes_only_assignment_fields(tmp_path):
    db_path = tmp_path / "analyzer.db"
    _accounts(db_path)
    run = poc.prepare_scan_run(_request(), db_path=db_path, interfaces={"eth0"})
    with poc.connect_database(db_path) as db:
        before = json.loads(
            db.execute(
                "SELECT manifest_json FROM scan_runs WHERE run_id = ?",
                (run["run_id"],),
            ).fetchone()[0]
        )
    after = poc.reassign_queued_scan_operator(
        run["run_id"], _change("bravo", "alpha", 0), db_path,
        actor="admin", role="admin",
    )
    allowed = {
        "owner", "owner_changed_at", "owner_changed_by", "queue_assignment_revision"
    }
    assert {key: value for key, value in after.items() if key not in allowed} == {
        key: value for key, value in before.items() if key not in allowed
    }
    assert after["requested_by"] == before["requested_by"]
    assert after["targets"] == before["targets"]
    assert after["profile"] == before["profile"]
