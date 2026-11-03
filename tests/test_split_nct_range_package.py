import hashlib
import importlib.util
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
    assert all(p['bytes']<=24 and transfer.digest(parts/p['file'])==p['sha256'] for p in result['parts'])
    def join():return subprocess.run(['sh',str(parts/'JOIN-NCT.sh'),str(out)],capture_output=True,text=True)
    assert join().returncode==0
    restored=out/source.name;assert restored.read_bytes()==source.read_bytes()
    before=restored.stat().st_ino;assert join().returncode==0 and restored.stat().st_ino==before
    restored.write_bytes(b'preserve different ZIP')
    assert join().returncode and restored.read_bytes()==b'preserve different ZIP'
    assert not list(out.glob('.nct-transfer-join.*'))


@pytest.mark.parametrize('problem',['missing','corrupt'])
def test_missing_or_corrupt_piece_cannot_publish_zip(tmp_path,problem):
    source=original(tmp_path);result=transfer.split_package(source,part_bytes=24)
    parts=Path(result['directory']);piece=parts/result['parts'][0]['file']
    if problem=='missing':piece.unlink()
    else:piece.write_bytes(b'damaged transfer')
    out=tmp_path/'out';out.mkdir()
    result=subprocess.run(['sh',str(parts/'JOIN-NCT.sh'),str(out)],capture_output=True,text=True)
    assert result.returncode and not list(out.iterdir())
    assert transfer.digest(source)==hashlib.sha256(source.read_bytes()).hexdigest()


def test_refuses_bad_checksum_or_reusing_a_transfer_folder(tmp_path):
    source=original(tmp_path);sidecar=source.with_suffix('.zip.sha256')
    sidecar.write_text('0'*64+'  '+source.name+'\n')
    with pytest.raises(ValueError,match='checksum'):transfer.split_package(source)
    sidecar.write_text(transfer.digest(source)+'  '+source.name+'\n')
    transfer.split_package(source)
    with pytest.raises(FileExistsError):transfer.split_package(source)
    with pytest.raises(ValueError,match='48 MiB'):transfer.split_package(source,part_bytes=transfer.PART_BYTES+1)
