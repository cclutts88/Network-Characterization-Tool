"""Authenticated observability only in disposable acceptance images, never releases."""
import json
from pathlib import Path
import sqlite3

from fastapi import HTTPException, Request
import app.main as main
import app.arkime_connector as passive
import app.storage_health as storage
from app.artifacts import register_artifact_file
from app.derived_jobs import enqueue_nmap_base_job

app = main.app
RUN = "f" * 32


@app.post("/__acceptance/queue-local")
def queue_local(request: Request):
    main.require_admin(request)
    if not (main.DATA_DIR / "recovery/update-maintenance.json").is_file():
        raise HTTPException(409, "Fixture requires paused update verification")
    folder = main.DATA_DIR / "scan-runs" / RUN
    folder.mkdir(parents=True)
    source = folder / "scan.xml"
    source.write_bytes(b'<nmaprun scanner="nmap" version="7.95" start="100"><scaninfo type="syn" protocol="tcp" numservices="1" services="80"/><host starttime="101" endtime="109"><status state="up"/><address addr="192.0.2.25" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host><runstats><finished time="110" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>')
    manifest = {"run_id": RUN, "status": "completed", "created_at": "2026-10-27T00:00:00Z"}
    with sqlite3.connect(main.DB_PATH) as db:
        db.execute("INSERT INTO scan_runs VALUES (?,?,?,?,?,?,?,?,?)", (RUN, manifest["created_at"], "completed", "preview-operator", "isolated local processing", "fixture", "eth0", "Common ports", json.dumps(manifest)))
    register_artifact_file(db_path=main.DB_PATH, source_path=source, source_kind="nmap_scan", source_ref=RUN,
        original_filename="scan.xml", actor="preview-operator", observation_key=f"nmap_scan:{RUN}:scan.xml")
    job = enqueue_nmap_base_job(main.DB_PATH, RUN, request_token="update-release-worker-probe", requested_by="preview-operator")
    return {"job_id": job["job_id"], **workers(request)}


@app.get("/__acceptance/workers")
def workers(request: Request):
    main.require_admin(request)
    with sqlite3.connect(main.DB_PATH) as db:
        states = [row[0] for row in db.execute("SELECT a.state FROM pipeline_job_attempts a JOIN pipeline_jobs j ON a.job_id=j.job_id WHERE j.source_run_id=?", (RUN,))]
    return {"local_attempts": states, "passive_worker_alive": bool(passive._WORKER_THREAD and passive._WORKER_THREAD.is_alive()),
        "storage_enabled": not storage._SHUTTING_DOWN, "update_pause_present": (main.DATA_DIR / "recovery/update-maintenance.json").exists()}
