from __future__ import annotations

from fastapi.responses import HTMLResponse


def device_config_page() -> HTMLResponse:
    return HTMLResponse(
        r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Nmap Terrain Analyzer · Device Configurations</title>
  <style>
    :root { color-scheme:dark; --bg:#08141d; --panel:#0f1d27; --line:#243b47; --text:#e7eef8; --muted:#9eb0b8; --accent:#57d6bf; --good:#61d095; --warn:#f4c95d; --bad:#ff7b7b; }
    * { box-sizing:border-box; } body { margin:0; background:linear-gradient(135deg,#08141d,#10242e); color:var(--text); font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif; }
    header,main { max-width:1044px; margin:0 auto; } header { padding:26px 0 20px; border-bottom:1px solid var(--line); } h1 { margin:0 0 4px; font-size:27px; } h2 { margin:0 0 13px; font-size:18px; } .sub { color:var(--muted); margin:0; } .eyebrow { color:var(--accent); font-weight:700; letter-spacing:.08em; text-transform:uppercase; font-size:11px; }
    .nav { display:flex; flex-wrap:wrap; gap:8px; margin-top:18px; } .nav a { display:inline-flex; border:1px solid #315264; background:#142d38; color:#b9cadc; border-radius:7px; padding:9px 13px; text-decoration:none; font-weight:700; } .nav a:hover { background:#1b4b57; color:#fff; } .nav a.active { background:#57d6bf; border-color:#57d6bf; color:#07171b; }
    main { padding:24px 0 60px; } .grid { display:grid; grid-template-columns:minmax(0,1fr) minmax(360px,1fr); gap:18px; align-items:start; } .panel { background:rgba(15,29,39,.94); border:1px solid var(--line); border-radius:12px; padding:18px; box-shadow:0 10px 35px rgba(0,0,0,.18); } .wide { grid-column:1/-1; }
    label { display:block; color:var(--muted); font-size:12px; font-weight:650; margin:11px 0 5px; } input,select,textarea { width:100%; background:#0b161c; color:var(--text); border:1px solid #315264; border-radius:7px; padding:9px 10px; font:inherit; } textarea { min-height:150px; resize:vertical; } input:focus,select:focus,textarea:focus { outline:2px solid rgba(87,214,191,.35); border-color:var(--accent); } .two { display:grid; grid-template-columns:1fr 1fr; gap:12px; } .three { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; }
    .actions { display:flex; flex-wrap:wrap; gap:9px; margin-top:17px; } button { border:1px solid #315264; background:#155064; color:#fff; border-radius:7px; padding:9px 13px; font:inherit; font-weight:700; cursor:pointer; } button:hover { background:#1b6870; } button.secondary { background:transparent; border-color:#49617d; } button:disabled { opacity:.55; cursor:not-allowed; } .hint,.meta { color:var(--muted); font-size:12px; } .hint { margin:7px 0 0; } #notice { min-height:22px; color:var(--muted); } #notice.good { color:var(--good); } #notice.bad { color:var(--bad); } #notice.warn { color:var(--warn); } pre { white-space:pre-wrap; overflow:auto; max-height:310px; background:#091318; border:1px solid #263f49; border-radius:7px; padding:10px; color:#cce7f5; font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; } .footer { margin-top:18px; color:var(--muted); font-size:12px; } .hidden { display:none; }
    .section-head { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; } .section-head button { flex:0 0 auto; } .history-list { display:grid; gap:10px; margin-top:14px; } details.device-history,details.run-card { border:1px solid #294552; border-radius:9px; background:#0b1820; } details.device-history>summary,details.run-card>summary { cursor:pointer; list-style:none; } details.device-history>summary::-webkit-details-marker,details.run-card>summary::-webkit-details-marker { display:none; } .device-summary { display:flex; align-items:center; justify-content:space-between; gap:14px; padding:13px 15px; } .device-address { color:#dff7ff; font:700 15px ui-monospace,SFMono-Regular,Consolas,monospace; } .history-latest { color:var(--muted); font-size:12px; text-align:right; } .run-count { display:inline-block; margin-left:8px; color:#07171b; background:var(--accent); border-radius:999px; padding:2px 7px; font:700 11px system-ui,sans-serif; } .preset { margin-left:10px; padding:5px 9px; font-size:11px; } .run-list { display:grid; gap:8px; padding:0 12px 12px; } .run-card { padding:0; } .run-summary { display:flex; justify-content:space-between; gap:12px; padding:10px 12px; color:#cce7f5; } .run-body { padding:0 12px 12px; border-top:1px solid #233b46; } .run-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px 16px; margin-top:10px; } .run-field { color:var(--muted); font-size:12px; } .run-field strong { display:block; color:var(--text); font-weight:650; overflow-wrap:anywhere; } .artifacts { display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; } .artifacts a { border:1px solid #315264; border-radius:6px; padding:6px 9px; color:#bfe8f4; text-decoration:none; font-size:12px; } .artifacts a:hover { background:#173744; color:#fff; }
    dialog { width:min(470px,calc(100vw - 28px)); border:1px solid #3d6575; border-radius:12px; padding:0; color:var(--text); background:#0f1d27; box-shadow:0 24px 90px rgba(0,0,0,.72); } dialog::backdrop { background:rgba(1,8,12,.78); backdrop-filter:blur(4px); } .dialog-body { padding:20px; } .dialog-body h2 { margin-bottom:5px; } .secure-note { border-left:3px solid var(--accent); padding:8px 10px; margin:14px 0; color:#cce7f5; background:#0b1820; font-size:12px; } .security-blocked { color:var(--warn); }
    @media (max-width:1080px) { header,main { padding-left:5vw; padding-right:5vw; } } @media (max-width:900px) { .grid { grid-template-columns:1fr; } .wide { grid-column:auto; } .two,.three,.run-grid { grid-template-columns:1fr; } .device-summary,.run-summary,.section-head { align-items:flex-start; flex-direction:column; } .history-latest { text-align:left; } }
    header { position:sticky; top:0; z-index:100; padding-top:16px; padding-bottom:14px; background:rgba(8,20,29,.96); backdrop-filter:blur(14px); box-shadow:0 9px 24px rgba(0,0,0,.38); } header h1 { font-size:25px; } .nav { margin-top:12px; }
  </style>
</head>
<body>
  <header><div class="eyebrow">Proof of concept · no authentication</div><h1>Device Configurations</h1><p class="sub">Generate accountable, read-only collection commands for authorized network devices.</p><nav class="nav" aria-label="Primary"><a href="/scans">Nmap Scans</a><a href="/analysis">Analyze Results</a><a class="active" href="/device-config" aria-current="page">Device Configurations</a><a href="/network-map">Network Map</a></nav></header>
  <main>
    <div id="notice"></div>
    <div class="grid">
      <section class="panel">
        <h2>Build a collection plan</h2>
        <p class="hint">Commands are selected from a fixed vendor template. The password is used only to open a short-lived SSH session and is never saved.</p>
        <div class="two"><div><label for="operator">Operator name</label><input id="operator" placeholder="Analyst name"></div><div><label for="origin">Originating host</label><input id="origin" placeholder="kali-blue"></div></div>
        <label for="reason">Reason / authorization note</label><input id="reason" placeholder="Authorized configuration baseline…">
        <div class="two"><div><label for="vendor">Vendor</label><select id="vendor"><option value="vyos">VyOS</option><option value="cisco">Cisco</option><option value="juniper">Juniper</option><option value="pfsense">pfSense</option></select></div><div><label for="type">Device type</label><select id="type"><option value="router">Router</option><option value="firewall">Firewall</option></select></div></div>
        <div class="three"><div><label for="address">Device address</label><input id="address" placeholder="192.0.2.1"></div><div><label for="username">SSH username</label><input id="username" placeholder="operator"></div><div><label for="port">SSH port</label><input id="port" type="number" min="1" max="65535" value="22"></div></div>
        <label for="captureInterface">Accountability capture interface</label><select id="captureInterface"><option value="">Loading analyzer interfaces…</option></select><p class="hint">Required: tcpdump starts on this interface before every SSH access check and configuration pull. The resulting PCAP is retained as accountability evidence.</p>
        <div class="actions"><button id="preview">Generate command set</button><button id="startSsh" class="secondary" disabled>Start SSH and collect</button></div>
      </section>
      <section class="panel">
        <h2>Command preview</h2>
        <div id="empty" class="meta">Enter the device details and generate a preview.</div>
        <div id="previewBox" class="hidden"><label>Read-only command set</label><pre id="commands"></pre><label>Mandatory tcpdump accountability command</label><pre id="captureCommand"></pre><label>Initial SSH command</label><pre id="ssh"></pre><label>Automated copy-back command</label><pre id="scp"></pre><p class="hint">After the password prompt succeeds, the tool collects the output, copies it back through the same temporary SSH control session, removes any supported remote temporary file, and closes the connection.</p></div>
      </section>
      <section class="panel wide"><h2>Execution result</h2><div id="result" class="meta">No command set executed yet.</div><pre id="output" class="hidden"></pre><div id="liveArtifacts" class="artifacts hidden"></div></section>
    </div>
    <section class="panel wide" style="margin-top:18px"><h2>Upload existing configuration results</h2><p class="hint">Import a router or firewall configuration result collected elsewhere. The operator, reason, originating host, vendor, device type, and address are taken from the collection plan above. This local upload does not contact the device and therefore does not start tcpdump.</p><label for="uploadFile">Configuration result file (maximum 5 MB)</label><input id="uploadFile" type="file"><div class="actions"><button id="uploadResult" class="secondary">Upload result</button></div></section>
    <section class="panel wide" style="margin-top:18px"><div class="section-head"><div><h2>Previously collected network devices</h2><p class="hint">Select <strong>Use preset</strong> to restore the address, vendor, device type, SSH username, and port from the latest successful record. Operator and authorization fields remain blank for each accountable rerun.</p></div><button id="refreshHistory" class="secondary">Refresh history</button></div><div id="historyStatus" class="meta">Loading device collection history…</div><div id="historyList" class="history-list"></div></section>
    <section class="panel wide" style="margin-top:18px"><h2>Interactive SSH workflow</h2><ol class="hint"><li>Review the initial <code>ssh admin@device</code> command and fixed read-only command set.</li><li>Start SSH. A private password dialog appears only after the device requests a password.</li><li>The tool keeps the authenticated connection only in memory, gathers evidence, copies the output back, removes any temporary device file it created, and closes the SSH session.</li><li>The password is never written to a manifest, history record, command line, environment variable, file, or application log.</li></ol><p class="hint"><strong>HTTPS is mandatory:</strong> password collection is disabled on plain HTTP so the password cannot cross the network unencrypted. Cisco and Juniper devices that do not provide a general-purpose temporary filesystem are collected directly over the authenticated SSH stream; no remote file is created on those devices.</p></section>
    <div class="footer">Device collection is limited to fixed templates in this proof of concept. Review every command before execution.</div>
  </main>
  <dialog id="passwordDialog" aria-labelledby="passwordTitle"><div class="dialog-body"><h2 id="passwordTitle">SSH password required</h2><p id="passwordTarget" class="meta"></p><div class="secure-note">This one-time value goes directly to the waiting SSH process over HTTPS. It is cleared immediately and is not stored.</div><label for="sessionPassword">Device password</label><input id="sessionPassword" type="password" autocomplete="new-password" autocapitalize="none" spellcheck="false"><div class="actions"><button id="submitPassword">Connect and collect</button><button id="cancelPassword" class="secondary" type="button">Cancel and close SSH</button></div></div></dialog>
<script>
const $ = id => document.getElementById(id);
let current = null;
let activeSshSession = null;
function notice(message, kind='') { $('notice').textContent=message; $('notice').className=kind; }
function apiError(data, fallback) {
  const detail=data&&data.detail;
  if(typeof detail==='string') return detail;
  if(Array.isArray(detail)) return detail.map(item=>{
    const field=Array.isArray(item.loc)?item.loc.filter(part=>part!=='body').join('.') : '';
    return `${field?field+': ':''}${item.msg||'Invalid value'}`;
  }).join('; ');
  if(detail&&typeof detail==='object') return detail.message||JSON.stringify(detail);
  return fallback;
}
function payload() {
  const captureInterface=$('captureInterface').value;
  if(!captureInterface) throw new Error('Choose an accountability capture interface before contacting the device.');
  return {operator:$('operator').value.trim(),originating_host:$('origin').value.trim()||location.hostname,reason:$('reason').value.trim(),vendor:$('vendor').value,device_type:$('type').value,device_address:$('address').value.trim(),username:$('username').value.trim(),ssh_port:Number($('port').value),key_path:null,authentication_mode:'password_prompt',accountability_interface:captureInterface};
}
function showPreview(data) { current=data; $('empty').classList.add('hidden'); $('previewBox').classList.remove('hidden'); $('commands').textContent=data.commands.join('\n'); $('captureCommand').textContent=data.capture_command; $('ssh').textContent=data.ssh_command; $('scp').textContent=data.scp_command; $('startSsh').disabled=!window.isSecureContext; if(!window.isSecureContext) notice('Preview ready. HTTPS must be enabled before a password can be entered.','warn'); }
function element(tag,className,text) { const node=document.createElement(tag); if(className) node.className=className; if(text!==undefined) node.textContent=text; return node; }
function formatTime(value) { if(!value) return 'Unknown time'; const date=new Date(value); return Number.isNaN(date.getTime())?value:date.toLocaleString(); }
function formatBytes(value) { if(value<1024) return `${value} B`; if(value<1024*1024) return `${(value/1024).toFixed(1)} KB`; return `${(value/1024/1024).toFixed(1)} MB`; }
function runField(label,value) { const box=element('div','run-field'); box.append(element('span','',label),element('strong','',value||'—')); return box; }
function showLiveArtifacts(artifacts) { const box=$('liveArtifacts'); box.replaceChildren(); for(const artifact of (artifacts||[])) { const link=element('a','',`${artifact.name} · ${formatBytes(artifact.size||0)}`); link.href=artifact.url; link.setAttribute('download',''); box.append(link); } box.classList.toggle('hidden',!box.childElementCount); }
function applyPreset(run) {
  $('vendor').value=run.vendor||'vyos'; $('type').value=run.device_type||'router'; $('address').value=run.device_address||''; $('username').value=run.username||''; $('port').value=run.ssh_port||22;
  current=null; $('startSsh').disabled=true; $('previewBox').classList.add('hidden'); $('empty').classList.remove('hidden');
  notice(`Preset loaded for ${run.device_address}. Add the operator and authorization note, then generate the command set.`,'good');
  document.querySelector('main').scrollIntoView({behavior:'smooth',block:'start'}); $('operator').focus();
}
function renderHistory(records) {
  const list=$('historyList'); list.replaceChildren();
  const groups=new Map();
  for(const record of records) { const key=record.device_address||'Unknown device'; if(!groups.has(key)) groups.set(key,[]); groups.get(key).push(record); }
  if(!groups.size) { $('historyStatus').textContent='No network-device configuration records have been saved yet.'; return; }
  for(const runs of groups.values()) runs.sort((a,b)=>new Date(b.completed_at||b.created_at||0)-new Date(a.completed_at||a.created_at||0));
  $('historyStatus').textContent=`${groups.size} network device${groups.size===1?'':'s'} · ${records.length} configuration record${records.length===1?'':'s'}`;
  for(const [address,runs] of groups) {
    const device=element('details','device-history');
    const summary=element('summary','device-summary');
    const latest=runs[0]; const presetRecord=runs.find(run=>run.vendor&&run.device_type&&run.username)||latest;
    const left=element('div'); left.append(element('span','device-address',address),element('span','run-count',`${runs.length} run${runs.length===1?'':'s'}`)); const preset=element('button','preset','Use preset'); preset.type='button'; preset.onclick=event=>{event.preventDefault();event.stopPropagation();applyPreset(presetRecord);}; left.append(preset);
    summary.append(left,element('div','history-latest',`Latest: ${formatTime(latest.completed_at||latest.created_at)} · ${latest.status||'unknown'}`)); device.append(summary);
    const runList=element('div','run-list');
    for(const run of runs) {
      const card=element('details','run-card'); const runSummary=element('summary','run-summary');
      runSummary.append(element('span','',formatTime(run.completed_at||run.created_at)),element('span','',`${run.status||'unknown'} · ${run.vendor||''} ${run.device_type||''}`)); card.append(runSummary);
      const body=element('div','run-body'); const fields=element('div','run-grid');
      fields.append(runField('Operator',run.operator),runField('Originating host',run.originating_host),runField('Reason / authorization',run.reason),runField('Exit code',run.exit_code===undefined?'—':String(run.exit_code)),runField('Username',run.username),runField('Run ID',run.run_id)); body.append(fields);
      if(run.operation==='manual_upload') body.append(runField('Imported file',run.source_filename));
      if(Array.isArray(run.commands)&&run.commands.length) { body.append(element('label','','Commands executed'),element('pre','',run.commands.join('\n'))); }
      const artifacts=element('div','artifacts');
      for(const artifact of (run.artifacts||[])) { const link=element('a','',`${artifact.name} · ${formatBytes(artifact.size||0)}`); link.href=artifact.url; link.setAttribute('download',''); artifacts.append(link); }
      if(artifacts.childElementCount) body.append(element('label','','Saved files'),artifacts); card.append(body); runList.append(card);
    }
    device.append(runList); list.append(device);
  }
}
async function loadHistory() { $('refreshHistory').disabled=true; $('historyStatus').textContent='Loading device collection history…'; try { const r=await fetch('/api/device-configs?limit=100'); const data=await r.json(); if(!r.ok) throw new Error(apiError(data,'Device collection history could not be loaded')); renderHistory(data); } catch(e) { $('historyStatus').textContent=e.message; } finally { $('refreshHistory').disabled=false; } }
async function loadCaptureInterfaces() { try { const r=await fetch('/api/scan-runs/interfaces'); const data=await r.json(); if(!r.ok) throw new Error(apiError(data,'Analyzer interfaces could not be loaded')); const select=$('captureInterface'); select.replaceChildren(); for(const name of (data.interfaces||[])) { const option=element('option','',name); option.value=name; select.append(option); } if(!select.options.length) { const option=element('option','','No capture interfaces found'); option.value=''; select.append(option); } } catch(e) { notice(e.message,'bad'); } }
async function generate() { $('preview').disabled=true; notice('Generating command set…'); try { const r=await fetch('/api/device-configs/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload())}); const data=await r.json(); if(!r.ok) throw new Error(apiError(data,'Preview could not be generated')); showPreview(data); notice(window.isSecureContext?'Preview ready. Review the commands before execution.':'Preview ready. HTTPS must be enabled before a password can be entered.',window.isSecureContext?'good':'warn'); } catch(e) { notice(e.message,'bad'); } finally { $('preview').disabled=false; } }
function displayCollection(data) { $('result').textContent=`${data.status} · ${data.vendor||''} ${data.device_type||''} · ${data.device_address||''} · ${data.completed_at||''}`; $('output').classList.remove('hidden'); const stderr=(data.stderr||'').trim(); $('output').textContent=`COLLECTED OUTPUT\n${data.stdout||''}${stderr?`\n\nSTATUS DETAILS\n${stderr}`:'\n\nNo errors reported.'}`; showLiveArtifacts(data.artifacts); const completed=data.status==='completed'; notice(completed?'Collection, copy-back, cleanup, session closure, and accountability capture completed.':'The SSH workflow did not complete. Review the status details.',completed?'good':'bad'); loadHistory(); }
async function startInteractiveSsh() { if(!current||!window.isSecureContext) return; $('startSsh').disabled=true; notice('Opening SSH and waiting for the device password prompt…','warn'); $('result').textContent='Starting accountable SSH session…'; try { const r=await fetch('/api/device-configs/interactive/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload())}); const data=await r.json(); if(!r.ok) throw new Error(apiError(data,'SSH session could not be started')); if(data.status!=='waiting_for_password') { displayCollection(data); return; } activeSshSession=data.session_id; $('passwordTarget').textContent=`${data.username}@${data.device_address}:${data.ssh_port} · prompt expires in ${data.expires_in_seconds} seconds`; $('sessionPassword').value=''; $('passwordDialog').showModal(); $('sessionPassword').focus(); notice('SSH is waiting for the operator password.','warn'); } catch(e) { $('result').textContent=e.message; notice(e.message,'bad'); $('startSsh').disabled=false; } }
async function submitPassword() { if(!activeSshSession) return; const input=$('sessionPassword'); let password=input.value; if(!password) { input.focus(); return; } input.value=''; $('submitPassword').disabled=true; $('cancelPassword').disabled=true; $('passwordDialog').close(); notice('Authenticating, collecting evidence, copying it back, and cleaning up…','warn'); let requestBody=JSON.stringify({password}); password=''; try { const r=await fetch(`/api/device-configs/interactive/${activeSshSession}/password`,{method:'POST',headers:{'Content-Type':'application/json','Cache-Control':'no-store'},cache:'no-store',body:requestBody}); requestBody=''; const data=await r.json(); activeSshSession=null; if(!r.ok) throw new Error(apiError(data,'SSH authentication or collection failed')); displayCollection(data); } catch(e) { activeSshSession=null; $('result').textContent=e.message; notice(e.message,'bad'); } finally { requestBody=''; $('submitPassword').disabled=false; $('cancelPassword').disabled=false; $('startSsh').disabled=!window.isSecureContext; } }
async function cancelPassword() { const sessionId=activeSshSession; activeSshSession=null; $('sessionPassword').value=''; if($('passwordDialog').open) $('passwordDialog').close(); if(sessionId) { try { await fetch(`/api/device-configs/interactive/${sessionId}/cancel`,{method:'POST'}); } catch(_) {} } $('startSsh').disabled=!window.isSecureContext; notice('SSH session closed without storing a password.','warn'); }
async function uploadResult() { const file=$('uploadFile').files[0]; if(!file) { notice('Choose a configuration result file to upload.','warn'); return; } const required={operator:$('operator').value.trim(),reason:$('reason').value.trim(),originating_host:$('origin').value.trim()||location.hostname,vendor:$('vendor').value,device_type:$('type').value,device_address:$('address').value.trim()}; if(!required.operator||!required.reason||!required.device_address) { notice('Operator, reason, and device address are required before uploading.','warn'); return; } const form=new FormData(); for(const [key,value] of Object.entries(required)) form.append(key,value); form.append('result_file',file,file.name); $('uploadResult').disabled=true; notice('Uploading the existing configuration result…','warn'); try { const r=await fetch('/api/device-configs/upload',{method:'POST',body:form}); const data=await r.json(); if(!r.ok) throw new Error(apiError(data,'Result upload failed')); showLiveArtifacts(data.artifacts); $('result').textContent=`uploaded · ${data.vendor} ${data.device_type} · ${data.device_address} · ${data.completed_at}`; $('uploadFile').value=''; notice('Configuration result uploaded and added to device history.','good'); await loadHistory(); } catch(e) { notice(e.message,'bad'); } finally { $('uploadResult').disabled=false; } }
$('origin').value=location.hostname; $('preview').onclick=generate; $('startSsh').onclick=startInteractiveSsh; $('submitPassword').onclick=submitPassword; $('cancelPassword').onclick=cancelPassword; $('refreshHistory').onclick=loadHistory; $('uploadResult').onclick=uploadResult;
$('passwordDialog').addEventListener('cancel',event=>{event.preventDefault();cancelPassword();}); $('sessionPassword').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();submitPassword();}});
if(!window.isSecureContext) notice('Interactive SSH password entry is disabled until this analyzer is served over HTTPS.','warn');
loadHistory();
loadCaptureInterfaces();
</script>
</body></html>'''
    )
