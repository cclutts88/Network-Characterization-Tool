"""Read-only source catalog; device metadata is a disposable navigation index."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import sqlite3
import threading
import tempfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

from app.database import connect_database

LOG = logging.getLogger(__name__)
LOCK = threading.RLock()
FAILED = set()
RUN = re.compile(r"[0-9a-f]{32}\Z")
MAX_MANIFEST = 2 * 1024 * 1024


def read_manifest_bytes(path):
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    with os.fdopen(fd,'rb') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError('Manifest is not a regular file')
        return handle.read(MAX_MANIFEST+1)


def index_path(db_path):
    owner = os.getuid() if hasattr(os,'getuid') else os.getpid()
    namespace=hashlib.sha256(str(Path(db_path).resolve()).encode()).hexdigest()
    return Path(tempfile.gettempdir()) / f'nct-library-{owner}' / (namespace+'.sqlite3')


def binding(db_path, root):
    p = Path(db_path).resolve()
    s = p.stat()
    return json.dumps([1, str(p), s.st_dev, s.st_ino, str(Path(root).resolve())])


def metadata(path):
    """Only copy display fields. Never index full manifests, commands or secrets."""
    run = path.parent.name
    result = dict(run_id=run, saved_at="", title=run, actor="", target="",
                  status="Unreadable metadata", observation_id="", operation="", digest="")
    if path.parent.is_symlink() or path.is_symlink():
        result["status"] = "Unsafe source path"
        return result
    try:
        raw = read_manifest_bytes(path)
        if len(raw) > MAX_MANIFEST:
            result["status"] = "Metadata exceeds navigation limit"
            return result
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("run_id") != run:
            result["status"] = "Conflicting source identity"
            return result
        def field(k):
            v = value.get(k)
            return v[:500] if isinstance(v, str) else ""
        title = field("source_filename") or field("device_name") or run
        if field("source_filename") and field("device_name"):
            title += ' — ' + field("device_name")
        result.update(saved_at=field("created_at"), title=title,
                      actor=field("operator"), target=field("device_address"),
                      status=field("status") or "Unknown", observation_id=field("artifact_observation_id"),
                      operation=field("operation"))
        result["digest"] = hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError):
        pass
    return result


def _put(db, item):
    keys = list(item)
    db.execute(f"INSERT OR REPLACE INTO devices ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})", list(item.values()))


def rebuild_device_index(db_path, root):
    """Startup only: bounded metadata reads, no evidence parsing or authority writes."""
    root = Path(root)
    with LOCK:
        p = index_path(db_path)
        try:
            data_root=Path(db_path).resolve().parent
            if p.parent.resolve().is_relative_to(data_root) or p.parent.is_symlink() or p.is_symlink():
                raise ValueError('Index must be outside retained evidence in a safe runtime directory')
            p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            if hasattr(os,'getuid') and p.parent.stat().st_uid!=os.getuid():
                raise ValueError('Runtime cache owner mismatch')
            p.parent.chmod(0o700)
            with connect_database(p) as db:
                db.executescript("""CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY, binding TEXT, ready INTEGER, baseline INTEGER);
                CREATE TABLE IF NOT EXISTS devices (run_id TEXT PRIMARY KEY, saved_at TEXT, title TEXT,
                actor TEXT, target TEXT, status TEXT, observation_id TEXT, operation TEXT, digest TEXT);
                CREATE TABLE IF NOT EXISTS dirty (run_id TEXT PRIMARY KEY);
                CREATE INDEX IF NOT EXISTS device_saved ON devices(saved_at DESC,run_id);""")
                db.execute("INSERT OR REPLACE INTO meta VALUES (1,?,0,0)", (binding(db_path, root),))
            with connect_database(p) as db:
                db.execute("DELETE FROM devices")
                db.execute("DELETE FROM dirty")
                if root.is_symlink():
                    raise ValueError("Device evidence directory is a symbolic link")
                if root.exists():
                    for child in root.iterdir():
                        if RUN.fullmatch(child.name) and child.is_dir():
                            _put(db, metadata(child / "manifest.json"))
                db.execute("UPDATE meta SET ready=1,baseline=1 WHERE id=1")
            FAILED.discard(str(p.resolve()))
        except Exception as exc:
            FAILED.add(str(p.resolve()))
            # Navigation failure must not prevent collection or startup. GET reports it.
            LOG.warning("Evidence Library device index unavailable: %s", type(exc).__name__)


@contextmanager
def device_metadata_publication(db_path, root, path):
    """Dirty before source replacement; crash/failure leaves coverage incomplete."""
    path, root = Path(path), Path(root)
    eligible = (path.name == "manifest.json" and path.parent.parent == root
                and RUN.fullmatch(path.parent.name) and index_path(db_path).exists())
    if not eligible:
        yield
        return
    with LOCK:
        marked = False
        try:
            with connect_database(index_path(db_path)) as db:
                db.execute("UPDATE meta SET ready=0 WHERE id=1")
                db.execute("INSERT OR IGNORE INTO dirty VALUES (?)", (path.parent.name,))
            marked = True
        except Exception:
            FAILED.add(str(index_path(db_path).resolve()))
            LOG.warning("Could not mark Evidence Library metadata dirty")
        yield
        if marked:
            try:
                with connect_database(index_path(db_path)) as db:
                    _put(db, metadata(path))
                    db.execute("DELETE FROM dirty WHERE run_id=?", (path.parent.name,))
                    db.execute("UPDATE meta SET ready=1 WHERE baseline=1 AND NOT EXISTS (SELECT 1 FROM dirty)")
            except Exception:
                FAILED.add(str(index_path(db_path).resolve()))
                LOG.warning("Evidence Library metadata publication incomplete")


def _tables(db):
    return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def list_evidence(db_path, root, *, q="", kind="", scope="", analyst="", start="", end="", limit=25, offset=0, after=""):
    from datetime import date
    for value in (start,end):
        if value and (len(value)!=10 or date.fromisoformat(value).isoformat()!=value):
            raise ValueError('Use YYYY-MM-DD dates')
    if start and end and start>end:
        raise ValueError('Start date must not follow end date')
    if kind not in {"", "scan", "import", "device"}:
        raise ValueError("Choose a supported evidence type")
    if not 1 <= limit <= 100 or offset < 0:
        raise ValueError("Invalid page range")
    parts = []
    coverage = "Device index unavailable. Restart NCT to rebuild navigation metadata."
    with connect_database(Path(db_path), read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')
        tables = _tables(db)
        if "scan_runs" in tables:
            scope_sql = "(SELECT scope_id FROM scan_run_scope_contexts c WHERE c.run_id=r.run_id)" if "scan_run_scope_contexts" in tables else "NULL"
            parts.append(f"""SELECT 'scan:'||r.run_id id,'scan' kind,r.run_id source_id,r.created_at saved_at,
            COALESCE(json_extract(m,'$.display_name'),json_extract(m,'$.name'),r.run_id) title,r.operator_name actor,
            COALESCE((SELECT group_concat(COALESCE(json_extract(CASE WHEN j.type='object' THEN j.value ELSE '{{}}' END,'$.name'),'')||' '||COALESCE(json_extract(CASE WHEN j.type='object' THEN j.value ELSE '{{}}' END,'$.cidr'),''),' · ')
                FROM json_each(CASE WHEN json_type(m,'$.saved_networks')='array' THEN json_extract(m,'$.saved_networks')
                WHEN json_type(m,'$.target_selection.saved_networks')='array' THEN json_extract(m,'$.target_selection.saved_networks') ELSE '[]' END) j),'')
                ||' '||COALESCE((SELECT group_concat(j.value,' · ') FROM json_each(CASE
                WHEN json_type(m,'$.targets')='array' THEN json_extract(m,'$.targets')
                WHEN json_type(m,'$.target_selection.manual_targets')='array' THEN json_extract(m,'$.target_selection.manual_targets') ELSE '[]' END) j
                WHERE j.type='text'),'') network,
            COALESCE({scope_sql},'') scope_id,CASE WHEN json_valid(manifest_json) AND json_type(m)='object' THEN r.status ELSE 'Unreadable scan metadata' END status,'' observation_id
            FROM (SELECT *,CASE WHEN json_valid(manifest_json) THEN manifest_json ELSE '{{}}' END m FROM scan_runs) r""")
        if "imports" in tables:
            if "artifact_observations" in tables:
                parts.append("""SELECT 'import:'||o.observation_id,'import',o.sha256,o.observed_at,
                COALESCE(o.original_filename,i.filename,o.observation_id),COALESCE(o.actor,''),'','',
                CASE WHEN i.sha256 IS NULL THEN 'Incomplete import record — source access unavailable' ELSE 'Retained import' END,o.observation_id
                FROM artifact_observations o LEFT JOIN imports i ON i.sha256=o.sha256 WHERE o.source_kind='nmap_import'""")
                legacy = "WHERE NOT EXISTS (SELECT 1 FROM artifact_observations o WHERE o.sha256=i.sha256 AND o.source_kind='nmap_import')"
            else:
                legacy = ""
            parts.append(f"SELECT 'import-legacy:'||i.sha256,'import',i.sha256,i.imported_at,i.filename,'','','','Legacy import','' FROM imports i {legacy}")
        device_attached = False
        try:
            if index_path(db_path).is_symlink() or str(index_path(db_path).resolve()) in FAILED:
                raise ValueError("Unsafe index")
            db.execute("ATTACH DATABASE ? AS library", (index_path(db_path).resolve().as_uri()+"?mode=ro",))
            meta = db.execute("SELECT binding,ready FROM library.meta WHERE id=1").fetchone()
            if not meta or meta[0] != binding(db_path, root) or not meta[1]:
                raise ValueError("Incomplete index")
            device_attached = True
            coverage = "Device metadata indexed at startup and updated by NCT. External file changes require a restart."
        except Exception:
            pass
        if device_attached:
            authority_join = "LEFT JOIN device_collection_authority a ON a.run_id=d.run_id" if "device_collection_authority" in tables else ""
            status = "CASE WHEN a.state='preparing' THEN 'Preparing — not available' ELSE d.status END" if authority_join else "d.status"
            where = "AND COALESCE(a.state,'')!='deleted'" if authority_join else ""
            device_scope = "(SELECT s.scope_id FROM device_scope_assignments s WHERE s.run_id=d.run_id AND s.authority_revision=a.revision ORDER BY s.revision DESC LIMIT 1)" if authority_join and 'device_scope_assignments' in tables else "''"
            parts.append(f"""SELECT 'device:'||d.run_id,'device',d.run_id,d.saved_at,d.title,d.actor,d.target,COALESCE({device_scope},''),
            {status},d.observation_id FROM library.devices d {authority_join}
            WHERE d.operation!='ssh_preflight' {where}""")
        if not parts:
            return {"items": [], "total": 0, "limit": limit, "offset": offset, "device_coverage": coverage}
        # Latest explicit observation assignment overrides unknown; preferences never assign scope.
        union = ' UNION ALL '.join(parts)
        assignment = "(SELECT s.scope_id FROM artifact_scope_assignments s WHERE e.kind='import' AND s.artifact_observation_id=e.observation_id ORDER BY s.revision DESC LIMIT 1)" if "artifact_scope_assignments" in tables else "NULL"
        clauses, args = [], []
        if scope=='__unknown__':
            clauses.append("scope_id=''")
            scope=''
        for clause, value in [("kind=?",kind),("scope_id=?",scope),("actor LIKE ? ESCAPE '\\'", '%'+analyst.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%' if analyst else ''),("substr(saved_at,1,10)>=?",start),("substr(saved_at,1,10)<=?",end)]:
            if value:
                clauses.append(clause); args.append(value)
        if q:
            clauses.append("instr(lower(title||' '||network||' '||source_id),lower(?))>0"); args.append(q)
        cte = f"WITH sources AS ({union}), catalog AS (SELECT e.id,e.kind,e.source_id,e.saved_at,e.title,e.actor,e.network,COALESCE({assignment},e.scope_id) scope_id,e.status FROM sources e)"
        conditions = " WHERE "+' AND '.join(clauses) if clauses else ""
        total = db.execute(cte+" SELECT count(*) FROM catalog"+conditions,args).fetchone()[0]
        page_conditions, page_args = conditions, list(args)
        if after:
            cursor = json.loads(after)
            if not isinstance(cursor,list) or len(cursor)!=2 or any(not isinstance(v,str) or len(v)>600 for v in cursor):
                raise ValueError('Invalid page cursor')
            page_conditions += (' AND ' if conditions else ' WHERE ')+"(saved_at<? OR (saved_at=? AND id>?))"
            page_args += [cursor[0],cursor[0],cursor[1]]
        rows = [dict(r) for r in db.execute(cte+" SELECT * FROM catalog"+page_conditions+" ORDER BY saved_at DESC,id ASC LIMIT ? OFFSET ?",[*page_args,limit+1,offset])]
        more=len(rows)>limit
        rows=rows[:limit]
        next_cursor = json.dumps([rows[-1]['saved_at'],rows[-1]['id']]) if more else ''
        scopes = {r[0]:r[1] for r in db.execute("SELECT scope_id,label FROM network_scopes")} if "network_scopes" in tables else {}
        cached = {r['source_id']:dict(db.execute('SELECT * FROM library.devices WHERE run_id=?',(r['source_id'],)).fetchone()) for r in rows if r['kind']=='device'}
        snapshots = {}
        for run in cached:
            authority = db.execute('SELECT * FROM device_collection_authority WHERE run_id=?',(run,)).fetchone() if 'device_collection_authority' in tables else None
            assignments = [tuple(r) for r in db.execute('SELECT * FROM device_scope_assignments WHERE run_id=? ORDER BY authority_revision,revision',(run,))] if 'device_scope_assignments' in tables else []
            snapshots[run] = (dict(authority) if authority else None,assignments)
    for row in rows:
        row['scope_name'] = scopes.get(row['scope_id'],row['scope_id']) or 'Unknown / unassigned'
        row['actor'] = row['actor'] or 'Unknown'
        row['saved_at'] = row['saved_at'] or 'Unknown'
        row['network'] = row['network'][:2500] or 'Unknown / not recorded'
        sid = quote(row['source_id'], safe='')
        if row['kind']=='device':
            if not RUN.fullmatch(row['source_id']):
                row['status']='Unsafe source identity'
                row['detail_url']=row['analysis_url']=row['download_url']=''
                continue
            current = metadata(Path(root)/row['source_id']/'manifest.json')
            if current['digest'] != cached[row['source_id']]['digest'] or not current['digest']:
                row['status'] = 'Metadata changed / unavailable — restart to refresh catalog'
                row['detail_url'] = row['analysis_url'] = row['download_url'] = ''
                coverage = 'Device metadata changed outside the catalog. Results may be incomplete; restart NCT to rebuild.'
                continue
            from app.device_collection_authority import require_available_collection
            try:
                raw=read_manifest_bytes(Path(root)/row['source_id']/'manifest.json')
                if hashlib.sha256(raw).hexdigest()!=cached[row['source_id']]['digest']:
                    raise ValueError('Source metadata changed during catalog read')
                manifest=json.loads(raw)
                require_available_collection(Path(db_path),row['source_id'],manifest=manifest)
                with connect_database(Path(db_path),read_only=True) as fresh:
                    fresh.row_factory=sqlite3.Row
                    fresh.execute('BEGIN')
                    a=fresh.execute('SELECT * FROM device_collection_authority WHERE run_id=?',(row['source_id'],)).fetchone() if 'device_collection_authority' in tables else None
                    assignments=[tuple(r) for r in fresh.execute('SELECT * FROM device_scope_assignments WHERE run_id=? ORDER BY authority_revision,revision',(row['source_id'],))] if 'device_scope_assignments' in tables else []
                    if (dict(a) if a else None,assignments)!=snapshots[row['source_id']]:
                        raise ValueError('Source context changed; refresh catalog')
            except (ValueError, OSError):
                row['status'] = 'Unavailable / authority requires review'
                row['detail_url'] = row['analysis_url'] = row['download_url'] = ''
                continue
            row['detail_url'] = f'/api/device-configs/{sid}'
            row['analysis_url'] = f'/device-analysis?run={sid}#deviceEvidencePicker'
            row['download_url'] = ''  # Detail lists protected, allowlisted original files.
        elif row['kind']=='scan':
            row['detail_url'] = f'/api/scan-runs/{sid}'
            row['analysis_url'] = f'/analysis?run={sid}'
            row['download_url'] = f'/api/scan-runs/{sid}/artifacts/xml'
        else:
            row['detail_url'] = f'/api/imports/{sid}'
            row['analysis_url'] = ''  # Shared bytes do not establish selected encounter context.
            row['download_url'] = '' if row['status'].startswith('Incomplete import record') else f'/api/imports/{sid}/raw'
    return {"items":rows,"total":total,"limit":limit,"offset":offset,"next_cursor":next_cursor,"scopes":[{'id':k,'label':v} for k,v in scopes.items()],"device_coverage":coverage}
