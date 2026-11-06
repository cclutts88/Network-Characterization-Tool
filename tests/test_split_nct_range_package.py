import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest

spec=importlib.util.spec_from_file_location('transfer',Path(__file__).parents[1]/'scripts/split_nct_range_package.py')
transfer=importlib.util.module_from_spec(spec);spec.loader.exec_module(transfer)


def original(tmp_path):
    source=tmp_path/'NCT-test.zip';source.write_bytes(b'exact sealed ZIP bytes\x00\xff'*4)
    source.with_suffix('.zip.sha256').write_text(transfer.digest(source)+'  '+source.name+'\n')
    return source


def test_parts_join_to_exact_original_and_preserve_existing_output(tmp_path):
    source=original(tmp_path);result=transfer.split_package(source,part_bytes=24)
    parts=Path(result['directory']);out=tmp_path/'out';out.mkdir()
    assert result['transfer_id']==result['zip_sha256'][:12]
    assert result['part_count']==len(result['parts'])
    assert result['local_reconstruction_verified'] is True
    assert result['required_controller_uploads']==[
        *(part['file'] for part in result['parts']),
        'JOIN-NCT.sh',
        'READ-ME-FIRST.txt',
        'TRANSFER-CHECKSUMS.json',
    ]
    record=json.loads((parts/'TRANSFER-CHECKSUMS.json').read_text())
    assert record['zip_sha256']==transfer.digest(source)
    assert result['transfer_record_sha256']==transfer.digest(parts/'TRANSFER-CHECKSUMS.json')
    assert result['readme_sha256']==transfer.digest(parts/'READ-ME-FIRST.txt')
    assert result['join_script_sha256']==transfer.digest(parts/'JOIN-NCT.sh')
    readme=(parts/'READ-ME-FIRST.txt').read_text()
    assert 'All pieces belong' in readme and 'in that one folder' in readme
    assert 'Upload every file in the transfer folder' in readme
    assert 'Do not leave TRANSFER-CHECKSUMS.json behind' in readme
    assert 'No separate\n  checksum upload is required' in readme
    assert all(p['bytes']<=24 and transfer.digest(parts/p['file'])==p['sha256'] for p in result['parts'])
    def join():return subprocess.run(['sh',str(parts/'JOIN-NCT.sh'),str(out)],capture_output=True,text=True)
    first=join();assert first.returncode==0 and '[4/4] PASS' in first.stdout
    restored=out/source.name;assert restored.read_bytes()==source.read_bytes()
    before=restored.stat().st_ino;repeat=join()
    assert repeat.returncode==0 and restored.stat().st_ino==before
    assert 'already correct' in repeat.stdout and 'no file was replaced' in repeat.stdout.lower()
    restored.write_bytes(b'preserve different ZIP')
    assert join().returncode and restored.read_bytes()==b'preserve different ZIP'
    assert not list(out.glob('.nct-transfer-join.*'))


@pytest.mark.parametrize('problem',['missing','linked','wrong-transfer','contradictory'])
def test_join_requires_the_matching_transfer_identity_record(tmp_path,problem):
    source=original(tmp_path);result=transfer.split_package(source,part_bytes=24)
    parts=Path(result['directory']);record=parts/'TRANSFER-CHECKSUMS.json'
    if problem=='missing':record.unlink()
    elif problem=='linked':
        record.unlink()
        try:record.symlink_to(source)
        except OSError:pytest.skip('host does not permit test symlinks')
    elif problem=='wrong-transfer':
        content=record.read_text().replace(result['transfer_id'],'0'*12,1)
        record.write_text(content)
    else:
        with record.open('a') as stream:
            stream.write('\n{"transfer_id":"wrong","zip_sha256":"wrong"}\n')
    out=tmp_path/'out';out.mkdir()

    joined=subprocess.run(
        ['sh',str(parts/'JOIN-NCT.sh'),str(out)],capture_output=True,text=True,
    )

    assert joined.returncode!=0
    assert 'TRANSFER-CHECKSUMS.json' in joined.stderr
    assert not list(out.iterdir())


@pytest.mark.parametrize('problem',['missing','linked','changed'])
def test_join_requires_the_exact_generated_operator_readme(tmp_path,problem):
    source=original(tmp_path);result=transfer.split_package(source,part_bytes=24)
    parts=Path(result['directory']);readme=parts/'READ-ME-FIRST.txt'
    if problem=='missing':readme.unlink()
    elif problem=='linked':
        readme.unlink()
        try:readme.symlink_to(source)
        except OSError:pytest.skip('host does not permit test symlinks')
    else:readme.write_text('instructions from another transfer')
    out=tmp_path/'out';out.mkdir()

    joined=subprocess.run(
        ['sh',str(parts/'JOIN-NCT.sh'),str(out)],capture_output=True,text=True,
    )

    assert joined.returncode!=0
    assert 'READ-ME-FIRST.txt' in joined.stderr
    assert not list(out.iterdir())


@pytest.mark.parametrize('problem',['missing','corrupt','linked'])
def test_missing_or_corrupt_piece_cannot_publish_zip(tmp_path,problem):
    source=original(tmp_path);result=transfer.split_package(source,part_bytes=24)
    parts=Path(result['directory']);piece=parts/result['parts'][0]['file']
    if problem=='missing':piece.unlink()
    elif problem=='corrupt':piece.write_bytes(b'damaged transfer')
    else:
        piece.unlink()
        try:piece.symlink_to(source)
        except OSError:pytest.skip('host does not permit test symlinks')
    out=tmp_path/'out';out.mkdir()
    result=subprocess.run(['sh',str(parts/'JOIN-NCT.sh'),str(out)],capture_output=True,text=True)
    assert result.returncode and not list(out.iterdir())
    if problem in {'missing','linked'}:assert 'missing or is not a regular file' in result.stderr
    assert transfer.digest(source)==hashlib.sha256(source.read_bytes()).hexdigest()


@pytest.mark.parametrize('extra_name',['NCT-test.zip.part99','Older-NCT.zip.part01'])
def test_join_refuses_piece_from_another_transfer_set(tmp_path,extra_name):
    source=original(tmp_path);result=transfer.split_package(source,part_bytes=24)
    parts=Path(result['directory'])
    (parts/extra_name).write_bytes(b'older release')
    out=tmp_path/'out';out.mkdir()

    joined=subprocess.run(
        ['sh',str(parts/'JOIN-NCT.sh'),str(out)],capture_output=True,text=True,
    )

    assert joined.returncode!=0
    assert 'Unexpected transfer piece from another set' in joined.stderr
    assert not list(out.iterdir())


def test_repeat_rechecks_parts_before_trusting_existing_zip(tmp_path):
    source=original(tmp_path);result=transfer.split_package(source,part_bytes=24)
    parts=Path(result['directory']);out=tmp_path/'out';out.mkdir()
    command=['sh',str(parts/'JOIN-NCT.sh'),str(out)]
    assert subprocess.run(command,capture_output=True,text=True).returncode==0
    rebuilt=out/source.name
    before=rebuilt.read_bytes()
    (parts/result['parts'][0]['file']).write_bytes(b'changed after successful join')

    repeated=subprocess.run(command,capture_output=True,text=True)

    assert repeated.returncode!=0
    assert rebuilt.read_bytes()==before==source.read_bytes()
    assert '[4/4] PASS' not in repeated.stdout


def test_publish_race_cannot_write_inside_new_destination_directory(tmp_path):
    source=original(tmp_path);result=transfer.split_package(source,part_bytes=24)
    parts=Path(result['directory']);out=tmp_path/'out';out.mkdir()
    wrappers=tmp_path/'wrappers';wrappers.mkdir()
    fake_ln=wrappers/'ln'
    fake_ln.write_text(
        '#!/bin/sh\nlast=\nfor value in "$@"; do last=$value; done\n'
        'mkdir "$last"\nexec /bin/ln "$@"\n'
    )
    fake_ln.chmod(0o755)
    environment={**os.environ,'PATH':str(wrappers)+os.pathsep+os.environ['PATH']}

    joined=subprocess.run(
        ['sh',str(parts/'JOIN-NCT.sh'),str(out)],
        capture_output=True,text=True,env=environment,
    )

    destination=out/source.name
    assert joined.returncode!=0
    assert 'output name became occupied' in joined.stderr
    assert destination.is_dir() and not list(destination.iterdir())
    assert not list(out.glob('.nct-transfer-join.*'))


def test_refuses_bad_checksum_or_reusing_a_transfer_folder(tmp_path):
    source=original(tmp_path);sidecar=source.with_suffix('.zip.sha256')
    sidecar.write_text('0'*64+'  '+source.name+'\n')
    with pytest.raises(ValueError,match='checksum'):transfer.split_package(source)
    sidecar.write_text(transfer.digest(source)+'  '+source.name+'\n')
    transfer.split_package(source)
    with pytest.raises(FileExistsError):transfer.split_package(source)
    with pytest.raises(ValueError,match='48 MiB'):transfer.split_package(source,part_bytes=transfer.PART_BYTES+1)


@pytest.mark.parametrize(
    'sidecar',
    ['', 'not-a-checksum', '0'*64+'  another.zip', '0'*64+'  NCT-test.zip\n'+'1'*64+'  NCT-test.zip'],
)
def test_refuses_missing_ambiguous_or_misnamed_checksum_record(tmp_path,sidecar):
    source=tmp_path/'NCT-test.zip';source.write_bytes(b'sealed package')
    source.with_suffix('.zip.sha256').write_text(sidecar)
    with pytest.raises(ValueError,match='checksum|record'):
        transfer.split_package(source)
