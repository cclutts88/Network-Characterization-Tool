"""Internal evidence-backed endpoint store; production ingestion is not wired yet.

Scope is an explicit caller-owned network context, never an inferred subnet or
Saved Network label. A host here denotes an address endpoint, not a physical box.
Receipts retain assessments without selecting a latest/current truth.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path

from app.artifacts import init_artifact_storage, utc_now
from app.database import connect_database, initialize_once_per_database
from app.network_scopes import init_network_scope_storage


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _id(*parts) -> str:
    return hashlib.sha256(_json(parts).encode()).hexdigest()


def _text(value, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a nonblank, trimmed string")
    return value


def _time(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("assessed_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


@initialize_once_per_database
def init_entity_storage(db_path: Path) -> None:
    init_artifact_storage(db_path)
    init_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS endpoint_entities (
                entity_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL,
                address TEXT NOT NULL,
                UNIQUE(scope_id, address)
            );
            CREATE TABLE IF NOT EXISTS service_entities (
                entity_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES endpoint_entities(entity_id),
                protocol TEXT NOT NULL,
                port INTEGER NOT NULL CHECK(port BETWEEN 0 AND 65535),
                UNIQUE(host_id, protocol, port)
            );
            CREATE TABLE IF NOT EXISTS entity_assessments (
                assessment_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL,
                artifact_observation_id TEXT NOT NULL
                    REFERENCES artifact_observations(observation_id),
                parser_version TEXT NOT NULL,
                assessed_at TEXT,
                recorded_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE(scope_id, artifact_observation_id, parser_version)
            );
            CREATE TABLE IF NOT EXISTS endpoint_receipts (
                assessment_id TEXT NOT NULL REFERENCES entity_assessments(assessment_id),
                host_id TEXT NOT NULL REFERENCES endpoint_entities(entity_id),
                facts_json TEXT NOT NULL,
                PRIMARY KEY(assessment_id, host_id)
            );
            CREATE TABLE IF NOT EXISTS service_receipts (
                assessment_id TEXT NOT NULL REFERENCES entity_assessments(assessment_id),
                service_id TEXT NOT NULL REFERENCES service_entities(entity_id),
                facts_json TEXT NOT NULL,
                PRIMARY KEY(assessment_id, service_id)
            );
            CREATE INDEX IF NOT EXISTS endpoint_receipts_host ON endpoint_receipts(host_id);
            CREATE INDEX IF NOT EXISTS service_receipts_service ON service_receipts(service_id);
            CREATE TRIGGER IF NOT EXISTS entity_assessments_active_scope
                BEFORE INSERT ON entity_assessments
                WHEN NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                )
                BEGIN SELECT RAISE(ABORT, 'network scope is missing or archived'); END;
            CREATE TRIGGER IF NOT EXISTS entity_assessments_scope_immutable
                BEFORE UPDATE OF scope_id ON entity_assessments
                BEGIN SELECT RAISE(ABORT, 'assessment scope is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS endpoint_entities_scope_immutable
                BEFORE UPDATE OF scope_id ON endpoint_entities
                BEGIN SELECT RAISE(ABORT, 'endpoint scope is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS endpoint_entities_active_scope
                BEFORE INSERT ON endpoint_entities
                WHEN NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                )
                BEGIN SELECT RAISE(ABORT, 'network scope is missing or archived'); END;
            CREATE TRIGGER IF NOT EXISTS endpoint_entities_no_update
                BEFORE UPDATE ON endpoint_entities
                BEGIN SELECT RAISE(ABORT, 'endpoint entities are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS endpoint_entities_no_delete
                BEFORE DELETE ON endpoint_entities
                BEGIN SELECT RAISE(ABORT, 'endpoint entities are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS service_entities_no_update
                BEFORE UPDATE ON service_entities
                BEGIN SELECT RAISE(ABORT, 'service entities are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS service_entities_no_delete
                BEFORE DELETE ON service_entities
                BEGIN SELECT RAISE(ABORT, 'service entities are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS entity_assessments_no_update
                BEFORE UPDATE ON entity_assessments
                BEGIN SELECT RAISE(ABORT, 'entity assessments are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS entity_assessments_no_delete
                BEFORE DELETE ON entity_assessments
                BEGIN SELECT RAISE(ABORT, 'entity assessments are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS endpoint_receipts_no_update
                BEFORE UPDATE ON endpoint_receipts
                BEGIN SELECT RAISE(ABORT, 'endpoint receipts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS endpoint_receipts_no_delete
                BEFORE DELETE ON endpoint_receipts
                BEGIN SELECT RAISE(ABORT, 'endpoint receipts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS service_receipts_no_update
                BEFORE UPDATE ON service_receipts
                BEGIN SELECT RAISE(ABORT, 'service receipts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS service_receipts_no_delete
                BEFORE DELETE ON service_receipts
                BEGIN SELECT RAISE(ABORT, 'service receipts are immutable'); END;
        """)


def record_assessment(
    db_path: Path, *, scope_id: str, artifact_observation_id: str,
    parser_version: str, assessed_at: str | None, hosts: list[dict],
    time_basis: str | None = None, assessment_facts: dict | None = None,
) -> str:
    """Atomically retain normalized source facts, including closed/unknown states.

    The adapter must provide facts from the referenced artifact, before analyst
    overrides/enrichment. Missing source time must be None, never upload time.
    Identical replays are no-ops; changed results require a new parser version.
    A missing host/port in a later assessment does not mean it disappeared.
    """
    scope_id = _text(scope_id, "scope_id")
    artifact_observation_id = _text(artifact_observation_id, "artifact_observation_id")
    parser_version = _text(parser_version, "parser_version")
    assessed_at = _time(assessed_at)
    if assessed_at is not None:
        time_basis = _text(time_basis, "time_basis")
    elif time_basis is not None:
        raise ValueError("Unknown assessment time must have no time_basis")
    if assessment_facts is None:
        assessment_facts = {}
    if not isinstance(assessment_facts, dict):
        raise ValueError("Assessment facts must be an object")
    normalized = []
    addresses = set()
    for source in hosts:
        address = str(ipaddress.ip_address(source["address"]))
        if "%" in address:
            raise ValueError("IPv6 zone identifiers require explicit scope mapping")
        if address in addresses:
            raise ValueError("Duplicate host in assessment")
        addresses.add(address)
        facts = source.get("facts", {})
        if not isinstance(facts, dict):
            raise ValueError("Host facts must be an object")
        services = []
        keys = set()
        for service in source.get("services", []):
            protocol = _text(service["protocol"], "protocol").lower()
            if protocol not in {"tcp", "udp", "sctp"}:
                raise ValueError("Unsupported transport protocol")
            port = service["port"]
            if type(port) is not int or not 0 <= port <= 65535:
                raise ValueError("Invalid port")
            if (protocol, port) in keys:
                raise ValueError("Duplicate service in assessment")
            keys.add((protocol, port))
            service_facts = service.get("facts", {})
            if not isinstance(service_facts, dict):
                raise ValueError("Service facts must be an object")
            services.append({"protocol": protocol, "port": port, "facts": service_facts})
        normalized.append({"address": address, "facts": facts,
                           "services": sorted(services, key=lambda s: (s["protocol"], s["port"]))})
    normalized.sort(key=lambda h: h["address"])
    payload = _json({"assessed_at": assessed_at, "time_basis": time_basis,
                     "facts": assessment_facts, "hosts": normalized})
    # Freeze caller-owned dictionaries before opening a transaction. Receipt facts
    # must be exactly the snapshot used for replay conflict detection.
    normalized = json.loads(payload)["hosts"]
    assessment_id = _id(scope_id, artifact_observation_id, parser_version)
    init_entity_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        prior = db.execute("SELECT payload_json FROM entity_assessments WHERE assessment_id = ?",
                           (assessment_id,)).fetchone()
        if prior:
            if prior[0] != payload:
                raise ValueError("Assessment already exists with different facts; use a new parser version")
            return assessment_id
        scope = db.execute(
            "SELECT active FROM network_scopes WHERE scope_id = ?", (scope_id,)
        ).fetchone()
        if scope is None:
            raise ValueError("Network scope does not exist")
        if not bool(scope[0]):
            raise ValueError("Network scope is archived")
        db.execute("INSERT INTO entity_assessments VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (assessment_id, scope_id, artifact_observation_id, parser_version,
                    assessed_at, utc_now(), payload))
        for host in normalized:
            host_id = _id("host", scope_id, host["address"])
            db.execute("INSERT OR IGNORE INTO endpoint_entities VALUES (?, ?, ?)",
                       (host_id, scope_id, host["address"]))
            db.execute("INSERT INTO endpoint_receipts VALUES (?, ?, ?)",
                       (assessment_id, host_id, _json(host["facts"])))
            for service in host["services"]:
                service_id = _id("service", host_id, service["protocol"], service["port"])
                db.execute("INSERT OR IGNORE INTO service_entities VALUES (?, ?, ?, ?)",
                           (service_id, host_id, service["protocol"], service["port"]))
                db.execute("INSERT INTO service_receipts VALUES (?, ?, ?)",
                           (assessment_id, service_id, _json(service["facts"])))
    return assessment_id
