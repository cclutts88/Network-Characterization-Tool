"""Representative isolated browser fixture; never runs against an existing dataset."""
import json
from pathlib import Path
import sqlite3

from app.artifacts import register_artifact_bytes
from app.device_configs import _write_json_atomic
from app.main import parse_xml


def seed():
    from app.main import DB_PATH, CONFIG_DIR, IMPORT_DIR
    if not Path('/tmp/nct-evidence-library-demo').exists():
        raise RuntimeError('Only the disposable library test container may be seeded')
    xml=b'''<?xml version="1.0"?><nmaprun scanner="nmap" start="1793620800" args="nmap -sV 192.0.2.10"><scaninfo type="syn" protocol="tcp" numservices="1" services="443"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host><runstats><finished time="1793620810" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
    import hashlib
    digest=hashlib.sha256(xml).hexdigest()
    with sqlite3.connect(DB_PATH) as db:
        if db.execute('SELECT count(*) FROM imports').fetchone()[0]:
            raise RuntimeError('Fixture already seeded; preserve existing data')
    for i in range(28):
        artifact=register_artifact_bytes(db_path=DB_PATH,content=xml,source_kind='nmap_import',source_ref=f'demo:{i}',original_filename=f'Office-retained-{i:02}.xml',media_type='application/xml',actor='Alice' if i%2 else 'Bob',observed_at=f'2026-11-02T12:{i:02}:00+00:00')
    with sqlite3.connect(DB_PATH) as db:
        db.execute('INSERT INTO imports VALUES (?,?,?,?,?,?)',(digest,'Office-original.xml',artifact['canonical_path'],'2026-11-02T12:00:00+00:00',json.dumps(parse_xml(xml)),'{}'))
    for run,title,target in [('a'*32,'Office router','192.0.2.1'),('b'*32,'Backup firewall','192.0.2.2')]:
        folder=CONFIG_DIR/run; folder.mkdir(parents=True)
        (folder/'stdout.txt').write_text('hostname demo-router\ninterface eth0\n ip address 192.0.2.1/24\n')
        _write_json_atomic(folder/'manifest.json',dict(run_id=run,operation='configuration_pull',status='completed',device_name=title,device_address=target,operator='Alice',created_at='2026-11-01T12:00:00+00:00',vendor='cisco',commands=[],output_complete=True))
    missing=CONFIG_DIR/('c'*32); missing.mkdir()
    _write_json_atomic(missing/'manifest.json',dict(run_id='c'*32,operation='manual_upload',status='incomplete',source_filename='Missing-source.txt',operator='Bob',created_at='2026-10-31T12:00:00+00:00'))
    print('Seeded 28 import encounters sharing one file, 2 legacy devices, 1 incomplete source')


if __name__=='__main__':
    seed()
