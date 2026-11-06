from fastapi.responses import Response


RETIREMENT_SCRIPT = r'''(() => {
'use strict';
const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({
  '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
}[char]));
let dialog=null,active=null,busy=false;
function ensureDialog(){
  if(dialog)return dialog;
  document.head.insertAdjacentHTML('beforeend',`<style>
  .nct-retirement-dialog{width:min(720px,calc(100vw - 28px));max-height:calc(100vh - 28px);overflow:auto;border:1px solid var(--line,#304955);border-radius:11px;background:var(--panel,#112330);color:var(--text,#e8f2f6);padding:0;box-shadow:0 18px 60px #0009}
  .nct-retirement-dialog::backdrop{background:#000b}.nct-retirement-body{padding:20px}.nct-retirement-body h2{margin-top:0}.nct-retirement-impact{padding:12px 16px;border:1px solid var(--line,#304955);border-radius:8px;background:color-mix(in srgb,var(--panel,#112330) 68%,var(--bg,#09131c))}.nct-retirement-body label{display:grid;gap:5px;margin:12px 0}.nct-retirement-body input,.nct-retirement-body textarea{width:100%;padding:9px;border:1px solid var(--line,#304955);border-radius:6px;background:var(--bg,#09131c);color:var(--text,#e8f2f6);font:inherit}.nct-retirement-body textarea{min-height:90px;resize:vertical}.nct-retirement-actions{display:flex;gap:9px;justify-content:flex-end;flex-wrap:wrap}.nct-retirement-status{min-height:24px;color:var(--muted,#abc0cb)}.nct-retirement-status.bad{color:var(--bad,#ff837a)}.nct-retirement-status.good{color:var(--good,#61d095)}
  </style>`);
  document.body.insertAdjacentHTML('beforeend',`<dialog class="nct-retirement-dialog" id="nctRetirementDialog"><form method="dialog" class="nct-retirement-body"><h2>Retire this evidence encounter</h2><p id="nctRetirementSource"></p><div class="nct-retirement-impact"><strong>What changes after confirmation</strong><ul id="nctRetirementImpact"></ul></div><p><strong>What does not happen:</strong> NCT does not delete the original files and does not contact the network.</p><label>Reason for retirement<textarea id="nctRetirementReason" maxlength="500" required placeholder="Explain why this retained encounter should leave ordinary analysis."></textarea></label><p>Type this exact confirmation phrase:</p><p><code id="nctRetirementChallenge"></code></p><label>Confirmation<input id="nctRetirementConfirmation" autocomplete="off" spellcheck="false" required></label><p class="nct-retirement-status" id="nctRetirementStatus" role="status" aria-live="assertive"></p><div class="nct-retirement-actions"><button type="button" class="secondary" id="nctRetirementCancel">Cancel</button><button type="button" class="danger" id="nctRetirementConfirm">Retire from ordinary use</button></div></form></dialog>`);
  dialog=document.getElementById('nctRetirementDialog');
  document.getElementById('nctRetirementCancel').onclick=()=>{if(!busy)dialog.close()};
  document.getElementById('nctRetirementConfirm').onclick=confirmRetirement;
  dialog.addEventListener('cancel',event=>{if(busy)event.preventDefault()});
  return dialog;
}
async function responseJson(response){
  const data=await response.json().catch(()=>({}));
  if(!response.ok)throw Error(typeof data.detail==='string'?data.detail:'Evidence retirement could not be completed.');
  return data;
}
async function review(options){
  if(busy)return false;
  const sourceFamily=String(options?.sourceFamily||''),encounterId=String(options?.encounterId||'');
  if(!sourceFamily||!encounterId)throw Error('Exact evidence encounter identity is unavailable.');
  const button=options.button||null;if(button)button.disabled=true;
  try{
    const data=await responseJson(await fetch('/api/evidence-retirements/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source_family:sourceFamily,encounter_id:encounterId})}));
    ensureDialog();active={...options,sourceFamily,encounterId,confirmation:data.confirmation,reviewToken:data.review_token};
    document.getElementById('nctRetirementSource').innerHTML=`<strong>${esc(options.label||sourceFamily)}</strong><br><code>${esc(encounterId)}</code><br><span class="meta">${Number(data.identity_count||0)} exact protected identit${Number(data.identity_count||0)===1?'y':'ies'} will be recorded in the audit receipt.</span>`;
    document.getElementById('nctRetirementImpact').innerHTML=(data.impact||[]).map(item=>`<li>${esc(item)}</li>`).join('');
    document.getElementById('nctRetirementChallenge').textContent=data.confirmation;
    document.getElementById('nctRetirementReason').value='';document.getElementById('nctRetirementConfirmation').value='';
    const status=document.getElementById('nctRetirementStatus');status.textContent='Review the impact, then enter a reason and the exact phrase.';status.className='nct-retirement-status';
    dialog.showModal();document.getElementById('nctRetirementReason').focus();return true;
  }catch(error){if(typeof options?.onError==='function')options.onError(error);else window.alert(error.message);return false}
  finally{if(button)button.disabled=false}
}
async function confirmRetirement(){
  if(busy||!active)return;
  const reason=document.getElementById('nctRetirementReason').value.trim(),confirmation=document.getElementById('nctRetirementConfirmation').value.trim(),status=document.getElementById('nctRetirementStatus'),submit=document.getElementById('nctRetirementConfirm');
  if(reason.length<3){status.textContent='Enter a clear reason of at least three characters.';status.className='nct-retirement-status bad';return}
  if(confirmation!==active.confirmation){status.textContent='The confirmation phrase does not match the exact encounter shown above.';status.className='nct-retirement-status bad';return}
  busy=true;submit.disabled=true;document.getElementById('nctRetirementCancel').disabled=true;status.textContent='Recording the retirement decision and rechecking the source…';status.className='nct-retirement-status';
  try{
    const result=await responseJson(await fetch('/api/evidence-retirements',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source_family:active.sourceFamily,encounter_id:active.encounterId,reason,confirmation,review_token:active.reviewToken})}));
    status.textContent=`Retired from ordinary use at audit revision ${result.revision}. Original files remain retained.`;status.className='nct-retirement-status good';
    const finished=active;setTimeout(()=>{dialog.close();active=null;if(typeof finished.after==='function')finished.after(result)},500);
  }catch(error){status.textContent=error.message;status.className='nct-retirement-status bad'}
  finally{busy=false;submit.disabled=false;document.getElementById('nctRetirementCancel').disabled=false}
}
window.NCTRetirement={review};
})();'''


def retirement_script() -> Response:
    return Response(
        RETIREMENT_SCRIPT,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store"},
    )
