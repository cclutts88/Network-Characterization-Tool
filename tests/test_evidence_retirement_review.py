from pathlib import Path

import pytest

from app.database import connect_database
from app.evidence_retirement import (
    EvidenceRetirementAdapter,
    EvidenceRetirementBlocked,
    EvidenceRetirementError,
    init_evidence_retirement_storage,
    preview_evidence_retirement,
    retire_evidence,
)
from app.retirement_review import issue_review_token, verify_review_token


def _foundation(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    with connect_database(db_path) as db:
        db.execute("CREATE TABLE sources(encounter_id TEXT PRIMARY KEY, identity TEXT)")
        db.executemany(
            "INSERT INTO sources VALUES (?,?)",
            [("one", "identity-one"), ("two", "identity-two")],
        )
    init_evidence_retirement_storage(db_path)

    def identities(db, encounter_id):
        row = db.execute(
            "SELECT identity FROM sources WHERE encounter_id=?", (encounter_id,),
        ).fetchone()
        if row is None:
            raise EvidenceRetirementError("source does not exist")
        return {"encounter_id": encounter_id, "source_identity": row[0]}

    return db_path, EvidenceRetirementAdapter(identities, lambda _db, _id: None)


def _review(db_path, adapter, encounter="one", actor="alice"):
    return preview_evidence_retirement(
        db_path,
        source_family="test_source",
        encounter_id=encounter,
        actor=actor,
        adapter=adapter,
    )


def test_review_token_is_bound_to_actor_encounter_revision_identity_and_impact(tmp_path):
    db_path, adapter = _foundation(tmp_path)
    review = _review(db_path, adapter)
    token = issue_review_token(review, actor="alice")
    verified = verify_review_token(
        token, actor="alice", source_family="test_source", encounter_id="one",
    )
    assert verified["authority_revision"] == 0
    assert verified["identity_snapshot_sha256"] == review["identity_snapshot_sha256"]
    assert len(verified["impact_sha256"]) == 64
    with pytest.raises(EvidenceRetirementError, match="different signed-in actor"):
        verify_review_token(
            token, actor="bob", source_family="test_source", encounter_id="one",
        )
    with pytest.raises(EvidenceRetirementError, match="invalid"):
        verify_review_token(
            token[:-1] + ("A" if token[-1] != "A" else "B"),
            actor="alice", source_family="test_source", encounter_id="one",
        )


def test_final_write_rechecks_exact_review_inside_write_transaction(tmp_path):
    db_path, adapter = _foundation(tmp_path)
    review = _review(db_path, adapter)
    token = issue_review_token(review, actor="alice")
    verified = verify_review_token(
        token, actor="alice", source_family="test_source", encounter_id="one",
    )
    with connect_database(db_path) as db:
        db.execute("UPDATE sources SET identity='changed' WHERE encounter_id='one'")
    with pytest.raises(EvidenceRetirementBlocked, match="identity changed"):
        retire_evidence(
            db_path,
            source_family="test_source",
            encounter_id="one",
            actor="alice",
            reason="retire exact source",
            adapter=adapter,
            expected_authority_revision=verified["authority_revision"],
            expected_identity_snapshot_sha256=verified["identity_snapshot_sha256"],
            expected_impact_sha256=verified["impact_sha256"],
        )


def test_final_write_refuses_review_after_authority_revision_changes(tmp_path):
    db_path, adapter = _foundation(tmp_path)
    review = _review(db_path, adapter, "one")
    token = issue_review_token(review, actor="alice")
    verified = verify_review_token(
        token, actor="alice", source_family="test_source", encounter_id="one",
    )
    retire_evidence(
        db_path,
        source_family="test_source",
        encounter_id="two",
        actor="alice",
        reason="retire other source",
        adapter=adapter,
    )
    with pytest.raises(EvidenceRetirementBlocked, match="authority changed"):
        retire_evidence(
            db_path,
            source_family="test_source",
            encounter_id="one",
            actor="alice",
            reason="retire reviewed source",
            adapter=adapter,
            expected_authority_revision=verified["authority_revision"],
            expected_identity_snapshot_sha256=verified["identity_snapshot_sha256"],
            expected_impact_sha256=verified["impact_sha256"],
        )
