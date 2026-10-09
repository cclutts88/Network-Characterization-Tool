from scripts import benchmark_workspace_contention as benchmark


def test_workspace_contention_suite_compares_serial_and_concurrent_runs(tmp_path):
    result = benchmark.run_suite(
        tmp_path,
        workers=2,
        cycles=8,
        payload_bytes=128,
        recursive_items=100,
        reader_workers=1,
        reads_per_worker=10,
        repeats=1,
        seed=17,
        runtime_label="pytest",
        host_label="test host",
    )

    assert result["passed"] is True
    assert result["guardrail_failures"] == []
    assert [run["mode"] for run in result["runs"]] == ["serial", "concurrent"]
    assert result["configuration"]["percentile_method"].startswith("nearest rank")
    for run in result["runs"]:
        assert run["passed"] is True
        assert run["failures"]["locked_busy_timeout_count"] == 0
        assert run["failures"]["optimistic_conflict_count"] == 0
        assert run["failures"]["unexpected_count"] == 0
        assert run["verification"]["integrity_check"] == ["ok"]
        assert run["verification"]["journal_mode"] == "wal"
        assert run["verification"]["busy_timeout_ms"] == 30_000
        assert run["verification"]["row_counts"] == {
            "ordinary_notes": 8,
            "ordinary_layouts": 2,
            "ordinary_working_views": 2,
            "ordinary_filter_presets": 2,
            "recursive_notes": 101,
        }
        assert [item["action"] for item in run["recursive_operations"]] == [
            "share",
            "unshare",
            "move",
        ]
        assert run["reads"]["attempted"] == 10
        assert run["reads"]["completed"] == 10
        for family in benchmark.FAMILIES:
            # One excluded warm-up plus eight measured updates yields version 10.
            assert run["ordinary_families"][family]["count"] == 16
    assert result["runs"][1]["reads"]["while_writers_active"] > 0
    assert result["runs"][1]["recursive_overlap_contract"]["passed"] is True
    assert all(
        result["runs"][1]["ordinary_during_recursive"][family]["count"] > 0
        for family in benchmark.FAMILIES
    )


def test_concurrent_contract_rejects_zero_recursive_overlap():
    assert benchmark._passes_run_contract(
        mode="concurrent",
        failure_counts={"locked_busy_timeout_count": 0, "unexpected_count": 0},
        verification={"passed": True},
        read_stats={"attempted": 1, "completed": 1, "while_writers_active": 1},
        overlap_timings={family: [] for family in benchmark.FAMILIES},
    ) is False


def test_recursive_verification_rejects_partial_descendant_state(tmp_path):
    db_path = tmp_path / "partial-branch.db"
    states, recursive = benchmark._prepare(
        db_path, workers=1, payload_bytes=0, recursive_items=5
    )
    benchmark._recursive(db_path, recursive)
    with benchmark.connect_database(db_path) as db:
        child_id = db.execute(
            """SELECT note_id FROM analyst_investigation_notes
               WHERE owner = ? AND note_id NOT IN (?, ?) LIMIT 1""",
            (
                recursive["owner"],
                recursive["root"]["note_id"],
                recursive["destination"]["note_id"],
            ),
        ).fetchone()[0]
        db.execute(
            """UPDATE analyst_investigation_notes
               SET visibility = 'shared', shared_page = 'hunt'
               WHERE note_id = ?""",
            (child_id,),
        )

    verification = benchmark._verify(db_path, states, recursive)

    assert verification["passed"] is False
    assert any("recursive descendants" in item for item in verification["failures"])


def test_verification_rejects_primary_row_owner_changes(tmp_path):
    db_path = tmp_path / "wrong-primary-owner.db"
    states, recursive = benchmark._prepare(
        db_path, workers=1, payload_bytes=0, recursive_items=5
    )
    benchmark._recursive(db_path, recursive)
    with benchmark.connect_database(db_path) as db:
        db.execute(
            "UPDATE analyst_workspace_layouts SET owner = 'wrong-owner' WHERE layout_id = ?",
            (states[0]["layout"]["layout_id"],),
        )
        db.execute(
            "UPDATE analyst_filter_presets SET owner = 'wrong-owner' WHERE preset_id = ?",
            (states[0]["filter_preset"]["preset_id"],),
        )

    verification = benchmark._verify(db_path, states, recursive)

    assert verification["passed"] is False
    assert any("expected owner" in item for item in verification["failures"])
    assert any("row ownership/count mismatch" in item for item in verification["failures"])


def test_verification_rejects_audit_owner_changes(tmp_path):
    db_path = tmp_path / "wrong-audit-owner.db"
    states, recursive = benchmark._prepare(
        db_path, workers=1, payload_bytes=0, recursive_items=5
    )
    benchmark._recursive(db_path, recursive)
    with benchmark.connect_database(db_path) as db:
        db.execute(
            """UPDATE analyst_workspace_layout_audit SET owner = 'wrong-owner'
               WHERE layout_id = ?""",
            (states[0]["layout"]["layout_id"],),
        )
        db.execute(
            """UPDATE analyst_investigation_note_audit SET owner = 'wrong-owner'
               WHERE note_id = ? AND action = 'share'""",
            (recursive["root"]["note_id"],),
        )

    verification = benchmark._verify(db_path, states, recursive)

    assert verification["passed"] is False
    assert any("unexpected audit owner" in item for item in verification["failures"])
    assert any("recursive root audit mismatch" in item for item in verification["failures"])


def test_workspace_contention_run_reports_failure_without_false_success(
    tmp_path, monkeypatch
):
    original = benchmark._update
    failed = {"once": False}

    def fail_once(db_path, state, family, cycle, padding):
        if cycle >= 0 and not failed["once"]:
            failed["once"] = True
            raise RuntimeError("simulated benchmark failure")
        return original(db_path, state, family, cycle, padding)

    monkeypatch.setattr(benchmark, "_update", fail_once)
    result = benchmark.run_once(
        tmp_path / "failure.db",
        mode="serial",
        workers=1,
        cycles=1,
        payload_bytes=0,
        recursive_items=2,
        reader_workers=1,
        reads_per_worker=1,
        seed=1,
    )

    assert result["passed"] is False
    assert result["failures"]["unexpected_count"] == 1
    assert "simulated benchmark failure" in result["failures"]["unexpected"][0]
    assert result["verification"]["passed"] is True
