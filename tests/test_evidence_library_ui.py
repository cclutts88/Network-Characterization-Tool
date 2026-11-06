import shutil
import subprocess
from pathlib import Path

import pytest

from app.evidence_library_ui import evidence_library_page
from app.how_nct_works_ui import how_nct_works_page
from app.shell_ui import SHELL_SCRIPT


def test_library_guide_theme_and_static_table_contract():
    page=evidence_library_page().body.decode()
    assert 'data-nct-table-mode="static"' in page
    assert 'overflow-y:visible' in page and 'max-height:' not in page
    assert 'var(--panel)' in page and 'var(--text)' in page
    assert '<thead>' in page and page.index('<thead>')<page.index('<tbody')
    assert '</form>' in page and '\x0c' not in page
    assert 'Only the manifest is retained' in page
    assert 'href="/evidence-library"' in SHELL_SCRIPT
    guide=how_nct_works_page().body.decode()
    assert 'Open analysis shows an explanation and an Open Scan History link' in guide
    assert 'Opening the link does not compute analysis or launch a scan' in guide
    for text in ['Evidence Library','literal text','temporary runtime','each import encounter','Library reads never rebuild','selected encounter','retiring one does not hide an active same-content sibling','retirement audit record']:
        assert text.lower() in guide.lower()


def test_deferred_filter_response_does_not_mix_cursors():
    node=shutil.which('node')
    if node is None: pytest.skip('Node.js not available')
    result=subprocess.run([node,'tests/evidence_library_ui_runtime.mjs'],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stdout+result.stderr
