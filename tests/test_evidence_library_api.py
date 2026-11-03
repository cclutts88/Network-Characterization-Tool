import sqlite3

from fastapi.testclient import TestClient

from app import main, device_configs
from app.auth import create_user, create_session, init_auth_storage, SESSION_COOKIE
from app import evidence_library as lib
from tests.test_evidence_library import store, device, scan


def test_authenticated_read_only_catalog_and_protected_device_download(store,monkeypatch):
    p,root=store; path=device(root); (path.parent/'stdout.txt').write_text('representative retained configuration')
    scan(p,'s'); lib.rebuild_device_index(p,root)
    init_auth_storage(p)
    create_user(p,username='library.viewer',display_name='Library viewer',role='viewer',password='isolated test account only',created_by='test')
    token,_=create_session(p,'library.viewer')
    monkeypatch.setenv('NCT_AUTH_MODE','local')
    monkeypatch.setattr(main,'DB_PATH',p); monkeypatch.setattr(main,'CONFIG_DIR',root)
    monkeypatch.setattr(device_configs,'DB_PATH',p); monkeypatch.setattr(device_configs,'CONFIG_DIR',root)
    client=TestClient(main.app)
    assert client.get('/api/evidence-library').status_code==401
    assert client.get('/evidence-library',follow_redirects=False).status_code==303
    client.cookies.set(SESSION_COOKIE,token)
    before=p.read_bytes()
    result=client.get('/api/evidence-library?kind=device').json()
    assert result['total']==1
    assert p.read_bytes()==before
    page=client.get('/evidence-library')
    assert page.status_code==200 and '</form>' in page.text
    record=result['items'][0]
    detail=client.get(record['detail_url'])
    assert detail.status_code==200
    file=next(f for f in detail.json()['artifacts'] if f['name']=='stdout.txt')
    downloaded=client.get(file['url'])
    assert downloaded.status_code==200 and downloaded.content==b'representative retained configuration'
    assert client.get('/api/device-configs/'+('a'*32)+'/files/not-allowed.txt').status_code==404
    for query in ['limit=101','kind=unsupported','start=invalid','after=bad','q='+('a'*201)]:
        assert client.get('/api/evidence-library?'+query).status_code==422
    with sqlite3.connect(p) as db: db.execute("UPDATE scan_runs SET manifest_json='invalid'")
    assert client.get('/api/evidence-library').status_code==200


def test_unavailable_catalog_returns_actionable_error(store,monkeypatch):
    p,root=store
    monkeypatch.setenv('NCT_AUTH_MODE','disabled')
    monkeypatch.setattr(main,'DB_PATH',p.parent/'missing.db')
    response=TestClient(main.app).get('/api/evidence-library')
    assert response.status_code==503
    assert 'no evidence was changed' in response.json()['detail']


def test_filters_precede_paging_on_large_catalog(store):
    p,root=store
    with sqlite3.connect(p) as db:
        db.executemany('INSERT INTO scan_runs VALUES (?,?,?,?,?)',[(str(i),'2026-11-02','completed','Analyst','{"name":"'+('needle' if i==4999 else 'ordinary')+'"}') for i in range(5000)])
    result=lib.list_evidence(p,root,q='needle',limit=25)
    assert result['total']==1 and result['items'][0]['source_id']=='4999'
    assert not result['next_cursor']
