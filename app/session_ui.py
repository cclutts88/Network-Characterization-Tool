from fastapi.responses import HTMLResponse, Response


SESSION_SCRIPT = r"""
(() => {
  async function installAccountControls() {
    const header = document.querySelector('body > header');
    if (!header || header.querySelector('.nct-account')) return;
    try {
      const response = await fetch('/api/auth/me', {credentials: 'same-origin'});
      if (!response.ok) return;
      const data = await response.json();
      if (!data.authentication_enabled || !data.analyst) return;
      const analyst = data.analyst;
      const controls = document.createElement('div');
      controls.className = 'nct-account';
      const identity = document.createElement('span');
      identity.className = 'nct-account-identity';
      identity.textContent = `${analyst.display_name || analyst.username} · ${analyst.role}`;
      identity.title = `Signed in as ${analyst.username}`;
      controls.append(identity);
      for (const id of ['operator', 'noStrikeOperator', 'fallbackApprover']) {
        const field = document.getElementById(id);
        if (!field) continue;
        field.value = analyst.username;
        field.readOnly = true;
        field.title = 'Bound to the signed-in analyst';
      }
      if (analyst.role === 'admin') {
        const admin = document.createElement('a');
        admin.href = '/admin/users';
        admin.textContent = 'Accounts';
        controls.append(admin);
      }
      const logout = document.createElement('button');
      logout.type = 'button';
      logout.textContent = 'Sign out';
      logout.onclick = async () => {
        logout.disabled = true;
        await fetch('/api/auth/logout', {method: 'POST', credentials: 'same-origin'});
        location.href = '/login';
      };
      controls.append(logout);
      const style = document.createElement('style');
      style.textContent = '.nct-account{position:absolute;right:18px;top:14px;display:flex;align-items:center;gap:8px;color:#a9c3cf;font:650 12px system-ui;z-index:110}.nct-account a,.nct-account button{width:auto;margin:0;padding:5px 8px;border:1px solid #315367;border-radius:6px;background:#0d2633;color:#dcecf2;font:inherit;text-decoration:none;cursor:pointer}.nct-account button:disabled{opacity:.55;cursor:wait}@media(max-width:850px){.nct-account{position:static;justify-content:center;margin:7px auto 0;flex-wrap:wrap}}';
      document.head.append(style);
      header.append(controls);
    } catch (_) {
      // Authentication is intentionally optional in the local Test workflow.
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', installAccountControls, {once: true});
  } else {
    installAccountControls();
  }
})();
"""


def session_script() -> Response:
    return Response(
        SESSION_SCRIPT,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store"},
    )


def analyst_admin_page() -> HTMLResponse:
    return HTMLResponse(
        r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NCT · Analyst accounts</title>
<style>:root{color-scheme:dark;--bg:#07121a;--panel:#0d1c26;--line:#315367;--text:#eaf4f8;--muted:#a9c3cf;--accent:#57d6bf}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px system-ui}header{position:sticky;top:0;z-index:100;padding:10px 24px;border-bottom:1px solid var(--line);background:#07121af5}.sr-only{position:absolute;width:1px;height:1px;margin:-1px;overflow:hidden;clip:rect(0,0,0,0)}.nct-brand{display:flex;width:max-content;flex-direction:column;align-items:center;margin:0 auto;line-height:1}.nct-brand>strong{padding-left:.24em;font-size:40px;letter-spacing:.24em}.nct-brand span{margin-top:3px;padding-top:3px;border-top:1px solid var(--accent);color:var(--muted);font-size:9px;font-weight:650;letter-spacing:.09em;text-transform:uppercase}.nct-brand span b{color:var(--accent)}.nav{display:flex;justify-content:center;gap:10px;margin-top:8px}.nav a{padding:6px 12px;border:1px solid var(--line);border-radius:7px;background:#102b38;color:var(--text);font-weight:750;text-decoration:none}.nav a.active{background:var(--accent);color:#06201d}main{width:min(1120px,calc(100% - 32px));margin:22px auto}.panel{padding:22px;border:1px solid var(--line);border-radius:12px;background:var(--panel)}h2{margin-top:0}.hint,.status{color:var(--muted)}form{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:18px}label{display:grid;gap:6px;font-weight:750}input,select,button{padding:11px;border:1px solid #3c6072;border-radius:7px;background:#091722;color:inherit;font:inherit}button{align-self:end;background:var(--accent);color:#06201d;font-weight:850;cursor:pointer}.wide{grid-column:1/-1}.table-wrap{margin-top:20px;overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #263f4d;text-align:left}th{color:#b9d5df}.bad{color:#ff9f9f}.good{color:#77e3b5}.account-actions{display:flex;gap:6px;flex-wrap:wrap}.account-actions button{padding:6px 8px;background:#102b38;color:var(--text);font-size:12px}.account-actions .danger{border-color:#8e4a55;color:#ffb0b9}.disabled-account{opacity:.58}details{margin-top:22px}dialog{width:min(480px,calc(100% - 32px));padding:22px;border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--text)}dialog::backdrop{background:#000b}dialog form{grid-template-columns:1fr}.dialog-actions{display:flex;gap:8px;justify-content:flex-end}.dialog-actions button{width:auto}@media(max-width:760px){form{grid-template-columns:1fr}.wide{grid-column:auto}}</style><script src="/assets/nct-session.js" defer></script></head><body>
<header><h1 class="sr-only">Analyst accounts</h1><div class="nct-brand" aria-label="NCT, Network Characterization Tool"><strong>NCT</strong><span><b>N</b>etwork <b>C</b>haracterization <b>T</b>ool</span></div><nav class="nav" aria-label="Primary"><a href="/device-config">Device</a><a href="/scans">Nmap</a><a href="/analysis">Analyze</a><a href="/hunting">Hunt</a><a href="/network-map">Map</a><a class="active" href="/admin/users" aria-current="page">Accounts</a></nav></header>
<main><section class="panel"><h2>Analyst accounts</h2><p class="hint">Administrators create named accounts here. Passwords are stored as hardened hashes and are never displayed again.</p>
<form id="createUser"><label>Username<input id="username" required minlength="2" maxlength="64" autocomplete="off"></label><label>Display name<input id="displayName" required maxlength="100" autocomplete="off"></label><label>Role<select id="role"><option value="analyst">Analyst</option><option value="viewer">Viewer</option><option value="admin">Administrator</option></select></label><label>Initial password<input id="password" type="password" required minlength="12" maxlength="256" autocomplete="new-password"></label><button class="wide" type="submit">Create account</button></form><p id="status" class="status" role="status"></p>
<div class="table-wrap"><table><thead><tr><th>Account</th><th>Display name</th><th>Role</th><th>Status</th><th>Created</th><th>Created by</th><th>Actions</th></tr></thead><tbody id="accounts"></tbody></table></div>
<details><summary>Account audit history</summary><div class="table-wrap"><table><thead><tr><th>Time</th><th>Account</th><th>Action</th><th>Administrator</th></tr></thead><tbody id="audit"></tbody></table></div></details></section></main>
<dialog id="passwordDialog"><h2>Reset account password</h2><p id="passwordTarget" class="hint"></p><form id="resetPassword"><input id="resetUsername" type="hidden"><label>New password<input id="newPassword" type="password" required minlength="12" maxlength="256" autocomplete="new-password"></label><div class="dialog-actions"><button id="cancelReset" type="button">Cancel</button><button type="submit">Reset password</button></div><p id="resetStatus" class="status" role="status"></p></form></dialog>
<script>
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(url,options){const response=await fetch(url,options),data=await response.json();if(!response.ok)throw new Error(data.detail||'The account change could not be completed');return data}
async function loadAccounts(){const items=await api('/api/auth/users');accounts.innerHTML=items.map(item=>`<tr class="${item.disabled?'disabled-account':''}"><td><strong>${esc(item.username)}</strong></td><td>${esc(item.display_name)}</td><td>${esc(item.role)}</td><td>${item.disabled?'Disabled':'Active'}</td><td>${esc(item.created_at)}</td><td>${esc(item.created_by)}</td><td><div class="account-actions"><button type="button" data-reset="${esc(item.username)}">Reset password</button><button type="button" class="${item.disabled?'':'danger'}" data-state="${esc(item.username)}" data-disabled="${item.disabled?'false':'true'}">${item.disabled?'Enable':'Disable'}</button></div></td></tr>`).join('')}
async function loadAudit(){const items=await api('/api/auth/audit?limit=200');audit.innerHTML=items.map(item=>`<tr><td>${esc(item.changed_at)}</td><td>${esc(item.username)}</td><td>${esc(item.action.replaceAll('_',' '))}</td><td>${esc(item.actor)}</td></tr>`).join('')}
createUser.onsubmit=async event=>{event.preventDefault();status.textContent='Creating account…';status.className='status';try{const data=await api('/api/auth/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:username.value.trim(),display_name:displayName.value.trim(),role:role.value,password:password.value})});createUser.reset();status.textContent=`Created ${data.username}.`;status.className='status good';await Promise.all([loadAccounts(),loadAudit()])}catch(error){status.textContent=error.message;status.className='status bad'}};
accounts.onclick=async event=>{const reset=event.target.closest('[data-reset]'),stateButton=event.target.closest('[data-state]');if(reset){resetUsername.value=reset.dataset.reset;passwordTarget.textContent=`Set a new password for ${reset.dataset.reset}. All of that account's current sessions will be signed out.`;newPassword.value='';resetStatus.textContent='';passwordDialog.showModal();newPassword.focus();return}if(!stateButton)return;const disabled=stateButton.dataset.disabled==='true',username=stateButton.dataset.state;if(!confirm(`${disabled?'Disable':'Enable'} ${username}?${disabled?' All current sessions will be signed out.':''}`))return;try{await api(`/api/auth/users/${encodeURIComponent(username)}/state`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({disabled})});status.textContent=`${username} is now ${disabled?'disabled':'active'}.`;status.className='status good';await Promise.all([loadAccounts(),loadAudit()])}catch(error){status.textContent=error.message;status.className='status bad'}};
cancelReset.onclick=()=>passwordDialog.close();resetPassword.onsubmit=async event=>{event.preventDefault();resetStatus.textContent='Resetting password…';try{await api(`/api/auth/users/${encodeURIComponent(resetUsername.value)}/password`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:newPassword.value})});passwordDialog.close();status.textContent=`Password reset for ${resetUsername.value}; existing sessions were signed out.`;status.className='status good';await loadAudit()}catch(error){resetStatus.textContent=error.message;resetStatus.className='status bad'}};
Promise.all([loadAccounts(),loadAudit()]).catch(error=>{status.textContent=error.message;status.className='status bad'});
</script></body></html>'''
    )
