import json
from pathlib import Path
import sqlite3

import pytest

from app import evidence_library as lib


@pytest.fixture
def store(tmp_path):
    p=tmp_path/'analyzer.db'; root=tmp_path/'device-configs'; root.mkdir()
    with sqlite3.connect(p) as db:
        db.executescript('''CREATE TABLE scan_runs(run_id TEXT PRIMARY KEY,created_at TEXT,status TEXT,operator_name TEXT,manifest_json TEXT);
        CREATE TABLE imports(sha256 TEXT PRIMARY KEY,filename TEXT,stored_path TEXT,imported_at TEXT,metadata_json TEXT);
        CREATE TABLE artifact_observations(observation_id TEXT,sha256 TEXT,source_kind TEXT,observed_at TEXT,original_filename TEXT,actor TEXT);
        CREATE TABLE network_scopes(scope_id TEXT,label TEXT);
        CREATE TABLE scan_run_scope_contexts(run_id TEXT,scope_id TEXT);
        CREATE TABLE artifact_scope_assignments(artifact_observation_id TEXT,scope_id TEXT,revision INTEGER);
        CREATE TABLE device_collection_authority(run_id TEXT,state TEXT,revision INTEGER,artifact_observation_id TEXT,
        artifact_sha256 TEXT,retained_filename TEXT,selection_contract TEXT,semantic_manifest_json TEXT,
        semantic_manifest_sha256 TEXT,created_at TEXT,activated_at TEXT,deleted_at TEXT);
        CREATE TABLE device_scope_assignments(run_id TEXT,authority_revision INTEGER,scope_id TEXT,revision INTEGER);
        INSERT INTO network_scopes VALUES ('scope','Office');''')
    return p,root


def device(root, run='a'*32, **fields):
    path=root/run/'manifest.json'; path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(dict(run_id=run,created_at='2026-11-02T12:00:00+00:00',operation='manual_upload',status='uploaded',operator='Alice',device_name='Router',**fields)))
    return path


def scan(p, run, **changes):
    manifest=dict(name='Office scan',saved_networks=[dict(name='Office Servers',cidr='10.2.0.0/24')],targets=['10.2.0.0/24'])
    manifest.update(changes)
    with sqlite3.connect(p) as db:
        db.execute('INSERT INTO scan_runs VALUES (?,?,?,?,?)',(run,'2026-11-02T12:00:00+00:00','completed','Bob',json.dumps(manifest)))


def test_all_sources_encounters_filters_and_legacy(store):
    p,root=store; device(root); scan(p,'s')
    with sqlite3.connect(p) as db:
        db.execute("INSERT INTO scan_run_scope_contexts VALUES ('s','scope')")
        db.execute("INSERT INTO imports VALUES ('hash','file.xml','/data/imports/file.xml','2026-11-01','{}')")
        db.execute("INSERT INTO imports VALUES ('old','old.xml','/data/imports/old.xml','2026-10-01','{}')")
        for i in ['one','two']:
            db.execute('INSERT INTO artifact_observations VALUES (?,?,?,?,?,?)',(i,'hash','nmap_import','2026-11-01',i+'.xml','Carol'))
        db.execute("INSERT INTO artifact_scope_assignments VALUES ('one','scope',1)")
    lib.rebuild_device_index(p,root)
    result=lib.list_evidence(p,root)
    assert result['total']==5
    assert len({r['id'] for r in result['items']})==5
    assert lib.list_evidence(p,root,q='Office Servers')['total']==1
    assert lib.list_evidence(p,root,q='10.2.0.0/24')['total']==1
    assert lib.list_evidence(p,root,scope='scope')['total']==2
    assert lib.list_evidence(p,root,analyst='carol')['total']==2
    assert lib.list_evidence(p,root,start='2026-11-02',end='2026-11-02')['total']==2
    assert not [r for r in result['items'] if r['kind']=='import' and r['analysis_url']]


def test_get_read_only_and_no_directory_walk(store,monkeypatch):
    p,root=store; device(root); scan(p,'s'); lib.rebuild_device_index(p,root)
    before={x:x.read_bytes() for x in [p,lib.index_path(p)]}
    monkeypatch.setattr(Path,'iterdir',lambda *a:pytest.fail('GET walked directory'))
    lib.list_evidence(p,root)
    assert all(x.read_bytes()==b for x,b in before.items())


def test_cursor_ties_and_concurrent_new_record(store):
    p,root=store; [scan(p,x) for x in ['b','c','d']]; lib.rebuild_device_index(p,root)
    first=lib.list_evidence(p,root,limit=2)
    scan(p,'a')
    second=lib.list_evidence(p,root,limit=2,after=first['next_cursor'])
    assert [x['source_id'] for x in first['items']+second['items']]==['b','c','d']


def test_legacy_unreadable_missing_and_authority_preparing_deleted(store):
    p,root=store; device(root); b=device(root,'b'*32); b.write_text('{bad')
    (root/('c'*32)).mkdir()
    with sqlite3.connect(p) as db:
        db.execute('INSERT INTO device_collection_authority(run_id,state,revision) VALUES (?,?,?)',('a'*32,'preparing',1))
    lib.rebuild_device_index(p,root)
    rows=lib.list_evidence(p,root)['items']
    assert len(rows)==3
    assert next(r for r in rows if r['source_id']=='a'*32)['status']=='Unavailable / authority requires review'
    with sqlite3.connect(p) as db:
        db.execute("UPDATE device_collection_authority SET state='deleted'")
    assert lib.list_evidence(p,root)['total']==2


def test_publication_and_interrupted_publication(store):
    p,root=store; path=device(root); lib.rebuild_device_index(p,root)
    with lib.device_metadata_publication(p,root,path):
        v=json.loads(path.read_text()); v['device_name']='Updated'; path.write_text(json.dumps(v))
    assert lib.list_evidence(p,root,q='Updated')['total']==1
    with pytest.raises(RuntimeError):
        with lib.device_metadata_publication(p,root,path):
            raise RuntimeError('crash')
    assert 'unavailable' in lib.list_evidence(p,root)['device_coverage']
    lib.rebuild_device_index(p,root)
    assert lib.list_evidence(p,root)['total']==1


def test_failed_baseline_cannot_be_promoted_by_one_publication(store):
    p,root=store; path=device(root); lib.rebuild_device_index(p,root)
    with sqlite3.connect(lib.index_path(p)) as db:
        db.execute('UPDATE meta SET baseline=0,ready=0')
    with lib.device_metadata_publication(p,root,path): pass
    assert lib.list_evidence(p,root)['total']==0


def test_changed_visible_metadata_not_silently_trusted(store):
    p,root=store; path=device(root); lib.rebuild_device_index(p,root)
    path.write_text('{}')
    result=lib.list_evidence(p,root)
    assert 'changed' in result['items'][0]['status']
    assert not result['items'][0]['analysis_url']


def test_root_binding_and_bad_page(store):
    p,root=store; device(root); lib.rebuild_device_index(p,root)
    assert lib.list_evidence(p,root/'other')['total']==0
    for args in [dict(kind='bad'),dict(limit=101),dict(offset=-1),dict(after='[1,2]')]:
        with pytest.raises(ValueError): lib.list_evidence(p,root,**args)


def test_metadata_allowlist_size_identity_and_secrets(store):
    p,root=store; path=device(root,password='secret',commands=['secret'],key_path='/secret')
    lib.rebuild_device_index(p,root)
    assert b'secret' not in lib.index_path(p).read_bytes()
    path.write_bytes(b'x'*(lib.MAX_MANIFEST+1))
    assert 'limit' in lib.metadata(path)['status']


def test_index_failure_does_not_break_source_publication(store,monkeypatch):
    p,root=store; path=device(root); lib.rebuild_device_index(p,root)
    original=lib.connect_database
    def fail_index(db_path,**kwargs):
        if Path(db_path)==lib.index_path(p) and not kwargs.get('read_only'):
            raise OSError('disk full')
        return original(db_path,**kwargs)
    monkeypatch.setattr(lib,'connect_database',fail_index)
    with lib.device_metadata_publication(p,root,path):
        path.write_text('{}')
    assert path.read_text()=='{}'
    assert lib.list_evidence(p,root)['total']==0


def test_new_legacy_after_startup_and_scope_revision(store):
    p,root=store; lib.rebuild_device_index(p,root)
    path=root/('b'*32)/'manifest.json'; path.parent.mkdir()
    with lib.device_metadata_publication(p,root,path):
        path.write_text(json.dumps(dict(run_id='b'*32,operation='configuration_pull',status='failed')))
    assert lib.list_evidence(p,root,kind='device')['total']==1
    with sqlite3.connect(p) as db:
        db.execute('INSERT INTO device_collection_authority(run_id,state,revision) VALUES (?,?,?)',('b'*32,'preparing',2))
        db.execute('INSERT INTO device_scope_assignments VALUES (?,?,?,?)',('b'*32,1,'oldscope',1))
        db.execute('INSERT INTO device_scope_assignments VALUES (?,?,?,?)',('b'*32,2,'scope',1))
    assert lib.list_evidence(p,root,scope='oldscope')['total']==0
    assert lib.list_evidence(p,root,scope='scope')['total']==1


def test_failed_rebuild_no_later_false_complete(store,monkeypatch):
    p,root=store; path=device(root); lib.rebuild_device_index(p,root)
    original=lib.metadata
    monkeypatch.setattr(lib,'metadata',lambda *a:(_ for _ in ()).throw(OSError('failure')))
    lib.rebuild_device_index(p,root)
    monkeypatch.setattr(lib,'metadata',original)
    with lib.device_metadata_publication(p,root,path): pass
    assert lib.list_evidence(p,root)['total']==0


def test_malformed_scan_and_dates(store):
    p,root=store; scan(p,'s',saved_networks=['bad',None,7])
    assert lib.list_evidence(p,root)['total']==1
    with sqlite3.connect(p) as db: db.execute("UPDATE scan_runs SET manifest_json='broken'")
    assert lib.list_evidence(p,root)['items'][0]['status']=='Unreadable scan metadata'
    for args in [dict(start='no'),dict(start='2026-02-30'),dict(start='2026-02-03',end='2026-02-01')]:
        with pytest.raises(ValueError): lib.list_evidence(p,root,**args)


@pytest.mark.parametrize('bad',['invalid scalar',17,{},None])
@pytest.mark.parametrize('nested',[False,True])
def test_malformed_saved_network_types_do_not_break_catalog(store,bad,nested):
    p,root=store
    scan(p,'s',**({'saved_networks':None,'target_selection':{'saved_networks':bad,'manual_targets':bad}} if nested else {'saved_networks':bad,'targets':bad}))
    assert lib.list_evidence(p,root)['total']==1


def test_authority_change_between_page_and_action_suppresses_actions(store,monkeypatch):
    from app import device_collection_authority as authority
    p,root=store; device(root); lib.rebuild_device_index(p,root)
    def changed(*a,**k):
        with sqlite3.connect(p) as db:
            db.execute('INSERT INTO device_collection_authority(run_id,state,revision) VALUES (?,?,?)',('a'*32,'active',2))
    monkeypatch.setattr(authority,'require_available_collection',changed)
    row=lib.list_evidence(p,root)['items'][0]
    assert not row['analysis_url']


def test_repeated_startup_index_is_outside_retained_data(store):
    p,root=store; device(root); scan(p,'s')
    before={str(f.relative_to(p.parent)):f.read_bytes() for f in p.parent.rglob('*') if f.is_file()}
    lib.rebuild_device_index(p,root); lib.rebuild_device_index(p,root)
    after={str(f.relative_to(p.parent)):f.read_bytes() for f in p.parent.rglob('*') if f.is_file()}
    assert before==after
    assert not lib.index_path(p).resolve().is_relative_to(p.parent.resolve())
    assert lib.list_evidence(p,root)['total']==2


def test_special_manifest_does_not_block_index(store):
    import os
    if not hasattr(os,'mkfifo'): pytest.skip('FIFO test requires POSIX')
    p,root=store; path=device(root); path.unlink(); os.mkfifo(path)
    lib.rebuild_device_index(p,root)
    result=lib.list_evidence(p,root)
    assert result['total']==1
    assert not result['items'][0]['download_url']


def test_orphan_import_observation_is_visible_without_unsafe_source_link(store):
    p,root=store
    with sqlite3.connect(p) as db:
        db.execute("INSERT INTO artifact_observations VALUES ('orphan','missing','nmap_import','2026-11-02','Retained-incomplete.xml','Alice')")
    row=lib.list_evidence(p,root)['items'][0]
    assert row['id']=='import:orphan' and 'Incomplete' in row['status']
    assert not row['download_url']
