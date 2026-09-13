from __future__ import annotations

from fastapi.responses import Response


VIEW_PREFERENCES_SCRIPT = r"""
(() => {
  const page = location.pathname === '/hunting' ? 'hunt' : location.pathname === '/analysis' ? 'analyze' : null;
  if (!page) return;
  const filterIds = page === 'hunt'
    ? ['search','osFilter','subnetFilter','deviceTypeFilter','category','capability','protocol','nonstandard','matchedOnly','cveFilter','cveYearFilter','cveStatusFilter']
    : ['hostSearch','osFilter'];
  const tableBodies = page === 'hunt'
    ? ['hostRows','findingSummaryRows','findingRows']
    : ['analysisHostRows'];
  let workspace = null, preferenceVersion = null, applying = false, saveTimer = null, pendingSnapshot = null;
  let canWrite = false, toolbar = null;
  const pageIndexes = new Map();

  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const api = async (url, options) => {
    const response = await fetch(url, {credentials:'same-origin', ...options});
    const data = await response.json();
    if (!response.ok) { const error = new Error(data.detail || 'The personal view change could not be completed'); error.status = response.status; throw error; }
    return data;
  };
  const control = id => document.getElementById(id);
  const status = (message, kind='') => { const node = toolbar?.querySelector('[data-view-status]'); if (node) { node.textContent = message; node.className = `nct-view-status ${kind}`; } };

  function installStyle() {
    const style = document.createElement('style');
    style.textContent = `
      .nct-view-toolbar{display:grid;grid-template-columns:minmax(180px,1.3fr) minmax(150px,1fr) auto auto auto minmax(115px,.7fr) minmax(150px,.9fr);gap:8px;align-items:end;margin:0 0 18px;padding:12px 14px;border:1px solid var(--line,#315367);border-radius:11px;background:rgba(12,26,35,.97);box-shadow:0 9px 28px #0004}
      .nct-view-toolbar label{margin:0;color:var(--muted,#9eb0b8);font-size:10px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}.nct-view-toolbar input,.nct-view-toolbar select,.nct-view-toolbar button{min-height:36px;padding:7px 9px;font-size:12px}.nct-view-toolbar button{white-space:nowrap}.nct-view-toolbar .danger{border-color:#81505a;background:transparent;color:#ffb1b8}.nct-view-toolbar .nct-view-status{grid-column:1/-1;min-height:0;color:var(--muted,#9eb0b8);font-size:11px}.nct-view-toolbar .nct-view-status.good{color:var(--good,#61d095)}.nct-view-toolbar .nct-view-status.bad{color:var(--bad,#ff837a)}
      .nct-page-hidden{display:none!important}.nct-table-pager{display:flex;justify-content:flex-end;align-items:center;gap:8px;margin-top:9px;color:var(--muted,#9eb0b8);font-size:11px}.nct-table-pager button{min-height:30px;padding:4px 9px;font-size:11px}.nct-table-pager[hidden]{display:none}
      @media(max-width:1050px){.nct-view-toolbar{grid-template-columns:repeat(4,minmax(0,1fr))}}@media(max-width:700px){.nct-view-toolbar{grid-template-columns:1fr 1fr}.nct-view-toolbar .nct-view-status{grid-column:1/-1}}
    `;
    document.head.append(style);
  }

  function installToolbar() {
    toolbar = document.createElement('section');
    toolbar.className = 'nct-view-toolbar';
    toolbar.setAttribute('aria-label', 'Personal investigation view');
    toolbar.innerHTML = `
      <label>Personal preset<select data-preset><option value="">Current working view</option></select></label>
      <label>Preset name<input data-preset-name maxlength="100" placeholder="Example: Windows servers"></label>
      <button type="button" data-save-new>Save new</button><button type="button" data-update disabled>Update</button><button type="button" class="danger" data-delete disabled>Delete</button>
      <label>Rows per table<select data-page-size><option value="all">All rows</option><option value="25">25</option><option value="50">50</option><option value="100">100</option></select></label>
      <label>Table sorting<select data-sort><option value="ip-asc">IP · low to high</option><option value="ip-desc">IP · high to low</option><option value="hostname">Hostname</option></select></label>
      <div class="nct-view-status" data-view-status>Private to this analyst account.</div>`;
    const main = document.querySelector('main');
    const anchor = page === 'analyze' ? main.querySelector('.analysis-tabs') : main.firstElementChild;
    if (anchor) anchor.insertAdjacentElement('afterend', toolbar); else main.prepend(toolbar);
    toolbar.querySelector('[data-save-new]').onclick = saveNewPreset;
    toolbar.querySelector('[data-update]').onclick = updatePreset;
    toolbar.querySelector('[data-delete]').onclick = deletePreset;
    toolbar.querySelector('[data-preset]').onchange = selectPreset;
    for (const selector of ['[data-page-size]','[data-sort]']) toolbar.querySelector(selector).onchange = () => { pageIndexes.clear(); applyPresentation(readPresentation()); scheduleSave(); };
  }

  function captureFilters() {
    const values = {};
    for (const id of filterIds) { const node = control(id); if (node) values[id] = node.type === 'checkbox' ? node.checked : node.value; }
    return values;
  }
  function captureCards() {
    const values = {};
    document.querySelectorAll('details[data-workspace-card]').forEach(node => values[node.dataset.workspaceCard] = node.open);
    return values;
  }
  function readPresentation() {
    return {
      pageSize: toolbar?.querySelector('[data-page-size]').value || 'all',
      sort: toolbar?.querySelector('[data-sort]').value || 'ip-asc'
    };
  }
  const captureView = () => ({filters:captureFilters(), cards:captureCards(), presentation:readPresentation()});

  function dispatch(node) {
    node.dispatchEvent(new Event(node.type === 'search' || node.tagName === 'INPUT' && node.type === 'text' ? 'input' : 'change', {bubbles:true}));
  }
  function applyFilters(filters={}) {
    let unresolved = false;
    for (const [id, value] of Object.entries(filters)) {
      const node = control(id); if (!node) { unresolved = true; continue; }
      if (node.type === 'checkbox') node.checked = Boolean(value);
      else if (node.tagName === 'SELECT' && value && ![...node.options].some(option => option.value === value)) { unresolved = true; continue; }
      else node.value = value ?? '';
      dispatch(node);
    }
    return unresolved;
  }
  function applyCards(cards={}) {
    for (const [key, open] of Object.entries(cards)) { const node = document.querySelector(`details[data-workspace-card="${CSS.escape(key)}"]`); if (node) node.open = Boolean(open); }
  }
  function applyPresentation(value={}) {
    const presentation = {pageSize:'all', sort:'ip-asc', ...value};
    if (toolbar) {
      toolbar.querySelector('[data-page-size]').value = presentation.pageSize;
      toolbar.querySelector('[data-sort]').value = presentation.sort;
    }
    requestAnimationFrame(applyTablePresentation);
  }
  function ipParts(value) {
    const match = String(value || '').match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/); return match ? match[1].split('.').map(Number) : [999,999,999,999];
  }
  function rowCompare(a,b,mode) {
    if (mode === 'hostname') {
      const result = String(a.dataset.hostname || '').localeCompare(String(b.dataset.hostname || ''), undefined, {numeric:true, sensitivity:'base'});
      if (result) return result;
    }
    const left = ipParts(a.dataset.ip || a.cells?.[0]?.textContent), right = ipParts(b.dataset.ip || b.cells?.[0]?.textContent);
    for (let index=0; index<4; index++) if (left[index] !== right[index]) return (left[index]-right[index]) * (mode === 'ip-desc' ? -1 : 1);
    return 0;
  }
  function applyTablePresentation() {
    if (!toolbar) return;
    const {pageSize, sort} = readPresentation(), limit = pageSize === 'all' ? Infinity : Number(pageSize);
    for (const id of tableBodies) {
      const body = control(id); if (!body) continue;
      const rows = [...body.querySelectorAll(':scope > tr')], sorted = [...rows].sort((a,b) => rowCompare(a,b,sort));
      if (sorted.some((row,index) => row !== rows[index])) sorted.forEach(row => body.append(row));
      sorted.forEach(row => row.classList.remove('nct-page-hidden'));
      const visible = sorted.filter(row => !row.classList.contains('hidden-row') && row.style.display !== 'none');
      const pageCount = Number.isFinite(limit) ? Math.max(1, Math.ceil(visible.length / limit)) : 1;
      const pageIndex = Math.min(pageIndexes.get(id) || 0, pageCount - 1); pageIndexes.set(id, pageIndex);
      const start = Number.isFinite(limit) ? pageIndex * limit : 0, end = Number.isFinite(limit) ? start + limit : Infinity;
      visible.forEach((row,index) => row.classList.toggle('nct-page-hidden', index < start || index >= end));
      let pager = body.closest('.table-wrap')?.querySelector(`.nct-table-pager[data-for="${id}"]`);
      if (!pager && body.closest('.table-wrap')) { pager = document.createElement('div'); pager.className='nct-table-pager'; pager.dataset.for=id; pager.innerHTML='<button type="button" data-prev>Previous</button><span data-page></span><button type="button" data-next>Next</button>'; body.closest('.table-wrap').append(pager); pager.querySelector('[data-prev]').onclick=()=>{pageIndexes.set(id,Math.max(0,(pageIndexes.get(id)||0)-1));applyTablePresentation()}; pager.querySelector('[data-next]').onclick=()=>{pageIndexes.set(id,(pageIndexes.get(id)||0)+1);applyTablePresentation()}; }
      if (pager) { const pageLabel=`${visible.length ? start+1 : 0}–${Math.min(end,visible.length)} of ${visible.length}`, pageNode=pager.querySelector('[data-page]'); pager.hidden=!Number.isFinite(limit)||visible.length<=limit; if(pageNode.textContent!==pageLabel)pageNode.textContent=pageLabel; pager.querySelector('[data-prev]').disabled=pageIndex===0; pager.querySelector('[data-next]').disabled=pageIndex>=pageCount-1; }
    }
  }
  function applySnapshot(snapshot, keepPending=true) {
    if (!snapshot) return;
    applying = true;
    if (snapshot.presentation) applyPresentation(snapshot.presentation);
    if (snapshot.cards) applyCards(snapshot.cards);
    const unresolved = snapshot.filters ? applyFilters(snapshot.filters) : false;
    pendingSnapshot = keepPending && unresolved ? snapshot : null;
    setTimeout(() => { applying = false; applyTablePresentation(); }, 0);
  }

  function renderPresets(selected='') {
    const select = toolbar.querySelector('[data-preset]');
    select.innerHTML = '<option value="">Current working view</option>' + (workspace.presets || []).map(item => `<option value="${escapeHtml(item.preset_id)}">${escapeHtml(item.name)}</option>`).join('');
    select.value = selected;
    selectPresetButtons();
  }
  function selectedPreset() { const id = toolbar.querySelector('[data-preset]').value; return (workspace.presets || []).find(item => item.preset_id === id); }
  function selectPresetButtons() { const item = selectedPreset(); toolbar.querySelector('[data-update]').disabled = !item || !canWrite; toolbar.querySelector('[data-delete]').disabled = !item || !canWrite; if (item) toolbar.querySelector('[data-preset-name]').value = item.name; }
  function selectPreset() { const item = selectedPreset(); selectPresetButtons(); if (!item) return; applySnapshot(item.snapshot, true); status(`Loaded “${item.name}”. Changes remain private to this account.`, 'good'); }

  async function saveNewPreset() {
    const name = toolbar.querySelector('[data-preset-name]').value.trim(); if (!name) { status('Enter a preset name first.', 'bad'); return; }
    status('Saving preset…');
    try {
      const item = await api(`/api/workspaces/views/${page}/presets`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name, snapshot:{filters:captureFilters()}})});
      workspace.presets.push(item); workspace.presets.sort((a,b)=>a.name.localeCompare(b.name)); renderPresets(item.preset_id); status(`Saved “${item.name}”.`, 'good');
    } catch (error) { status(error.message, 'bad'); }
  }
  async function updatePreset() {
    const item = selectedPreset(); if (!item) return; const name = toolbar.querySelector('[data-preset-name]').value.trim();
    status('Updating preset…');
    try {
      const saved = await api(`/api/workspaces/views/${page}/presets`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({preset_id:item.preset_id, expected_version:item.version, name, snapshot:{filters:captureFilters()}})});
      workspace.presets = workspace.presets.map(value => value.preset_id === saved.preset_id ? saved : value); workspace.presets.sort((a,b)=>a.name.localeCompare(b.name)); renderPresets(saved.preset_id); status(`Updated “${saved.name}”.`, 'good');
    } catch (error) { status(error.message, 'bad'); await reloadWorkspace(false); }
  }
  async function deletePreset() {
    const item = selectedPreset(); if (!item || !confirm(`Delete the personal preset “${item.name}”?`)) return;
    status('Deleting preset…');
    try {
      await api(`/api/workspaces/views/${page}/presets/${encodeURIComponent(item.preset_id)}?expected_version=${item.version}`, {method:'DELETE'});
      workspace.presets = workspace.presets.filter(value => value.preset_id !== item.preset_id); renderPresets(); toolbar.querySelector('[data-preset-name]').value=''; status('Preset deleted.', 'good');
    } catch (error) { status(error.message, 'bad'); await reloadWorkspace(false); }
  }

  function scheduleSave() { if (!canWrite || applying) return; clearTimeout(saveTimer); saveTimer = setTimeout(savePreference, 450); }
  async function savePreference(retry=true) {
    try {
      const saved = await api(`/api/workspaces/views/${page}`, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({snapshot:captureView(), expected_version:preferenceVersion})});
      preferenceVersion = saved.version; status('Personal working view saved.', 'good');
    } catch (error) {
      if (error.status === 409 && retry) { await reloadWorkspace(false); await savePreference(false); return; }
      status(error.message, 'bad');
    }
  }
  async function reloadWorkspace(apply=true) {
    workspace = await api(`/api/workspaces/views/${page}`); preferenceVersion = workspace.preference?.version ?? null; renderPresets(); if (apply && workspace.preference?.snapshot) applySnapshot(workspace.preference.snapshot, true);
  }

  function bindChanges() {
    document.addEventListener('input', event => { if (filterIds.includes(event.target.id)) { pageIndexes.clear(); scheduleSave(); setTimeout(applyTablePresentation,0); } });
    document.addEventListener('change', event => { if (filterIds.includes(event.target.id)) { pageIndexes.clear(); scheduleSave(); setTimeout(applyTablePresentation,0); } });
    document.addEventListener('toggle', event => { if (event.target.matches?.('details[data-workspace-card]')) scheduleSave(); }, true);
    const observer = new MutationObserver(records => { const pagerOnly=records.every(record=>(record.target.nodeType===1?record.target:record.target.parentElement)?.closest?.('.nct-table-pager')); if(pagerOnly)return; if (pendingSnapshot) applySnapshot(pendingSnapshot, true); applyTablePresentation(); });
    observer.observe(document.querySelector('main'), {subtree:true, childList:true});
  }

  async function start() {
    try {
      const me = await api('/api/auth/me'); if (!me.authentication_enabled || !me.analyst) return;
      canWrite = me.analyst.role !== 'viewer'; installStyle(); installToolbar();
      if (!canWrite) { toolbar.querySelectorAll('button,input[data-preset-name]').forEach(node => node.disabled = true); status('Read-only account. Existing personal presets can be loaded.'); }
      await reloadWorkspace(true); bindChanges();
    } catch (error) { if (toolbar) status(error.message, 'bad'); }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once:true}); else start();
})();
"""


def view_preferences_script() -> Response:
    return Response(
        VIEW_PREFERENCES_SCRIPT,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store"},
    )
