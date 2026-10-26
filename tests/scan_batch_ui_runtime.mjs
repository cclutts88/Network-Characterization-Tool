import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");

function functionLine(name) {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/ui.py`);
  return match[0];
}

function fakeElement() {
  return {
    value: "",
    disabled: false,
    textContent: "",
    className: "",
    innerHTML: "",
    dataset: {},
    classList: { add() {}, remove() {}, toggle() {} },
    replaceChildren() { this.innerHTML = ""; },
  };
}

await eval(`(async () => {
  let batchPreview=null,batchReviewInFlight=false,batchSubmitInFlight=false,batchEditorLocked=false,batchSubmissionUncertain=false,batchOperationRevision=0,batchRequestToken=null,batchPendingSubmission=null,batchSelectionOrder=['alpha','bravo'];
  let activeCollectionEnabled=true,sessionAnalyst={role:'analyst'};
  const controls=new Map(),lockedNodes=[fakeElement(),fakeElement()];
  const $=id=>{if(!controls.has(id))controls.set(id,fakeElement());return controls.get(id)};
  const document={querySelectorAll(){return lockedNodes}};
  const storage=new Map(),localStorage={getItem:key=>storage.get(key)||null,setItem:(key,value)=>storage.set(key,value),removeItem:key=>storage.delete(key)};
  const BATCH_ATTEMPT_KEY='attempt';
  const collectionContactBlocked=()=>false,updateSchedulePin=()=>{};
  const batchPayloadBase=()=>({name_template:'Mission $subnet',selections:[1,2]});
  const batchFingerprint=value=>JSON.stringify(value),batchToken=()=> 'scan-batch-owned-request';
  const refreshSafetySummary=async()=>true,saveDraft=async()=>true;
  let resolvePreview;
  const fetch=()=>new Promise(resolve=>{resolvePreview=resolve});
  let rendered=0;
  const renderBatchPreview=data=>{rendered+=1;batchPreview=data};
  const renderBatchOrder=()=>{},renderNetworkScopeReview=()=>{},scheduleDraftSave=()=>{};
  ${functionLine("updateMissionActionState")}
  ${functionLine("setBatchEditorLocked")}
  ${functionLine("clearStoredBatchAttempt")}
  ${functionLine("storeBatchAttempt")}
  ${functionLine("invalidateBatchPreview")}
  ${functionLine("moveBatchSelection")}
  ${functionLine("reviewBatch")}
  const pending=reviewBatch();
  await Promise.resolve();
  assert.equal(batchEditorLocked,true,'review must lock the draft while its request is pending');
  moveBatchSelection('alpha',1);
  assert.deepEqual(batchSelectionOrder,['alpha','bravo'],'reorder controls must not mutate a pending review');
  invalidateBatchPreview('A newer draft now owns the page.');
  resolvePreview({ok:true,json:async()=>({preview_digest:'obsolete',runs:[]})});
  await pending;
  assert.equal(rendered,0,'a late preview response must not replace a newer draft');
  assert.equal(batchPreview,null);
  assert.equal(storage.has(BATCH_ATTEMPT_KEY),false);
})()`);

await eval(`(async () => {
  let batchPreview={preview_digest:'digest-one',global_no_strike_revision:4,runs:[{selection_order:1}]},batchReviewInFlight=false,batchSubmitInFlight=false,batchEditorLocked=false,batchSubmissionUncertain=false,batchOperationRevision=0,batchRequestToken='scan-batch-stable-token',batchPendingSubmission=null,batchSelectionOrder=['alpha','bravo'];
  let activeCollectionEnabled=true,sessionAnalyst={role:'analyst'};
  const controls=new Map(),lockedNodes=[fakeElement(),fakeElement()];
  const $=id=>{if(!controls.has(id))controls.set(id,fakeElement());return controls.get(id)};
  $('scopeMode').value='batch';
  const document={querySelectorAll(){return lockedNodes}};
  const storage=new Map(),localStorage={getItem:key=>storage.get(key)||null,setItem:(key,value)=>storage.set(key,value),removeItem:key=>storage.delete(key)};
  const BATCH_ATTEMPT_KEY='attempt';
  const collectionContactBlocked=()=>false,updateSchedulePin=()=>{};
  const base={name_template:'Mission $subnet',selections:[{saved_network_id:'alpha'},{saved_network_id:'bravo'}]};
  const batchPayloadBase=()=>structuredClone(base),batchFingerprint=value=>JSON.stringify(value);
  storage.set(BATCH_ATTEMPT_KEY,JSON.stringify({state:'reviewed',fingerprint:batchFingerprint(base),request_token:batchRequestToken,preview:batchPreview}));
  const requests=[];
  let failConnection=true;
  const fetch=async(_url,options)=>{requests.push(options.body);if(failConnection)throw new Error('connection lost');return{ok:true,json:async()=>({accepted_count:2,requested_count:2,batch_id:'batch-one',request_replayed:true,dispatch_pending:false,runs:[]})}};
  let receipt=null;
  const renderBatchReceipt=data=>{receipt=data};
  const renderBatchPreview=data=>{batchPreview=data};
  const status=()=>{};
  const renderBatchOrder=()=>{},renderNetworkScopeReview=()=>{},scheduleDraftSave=()=>{};
  ${functionLine("updateMissionActionState")}
  ${functionLine("setBatchEditorLocked")}
  ${functionLine("clearStoredBatchAttempt")}
  ${functionLine("storeBatchAttempt")}
  ${functionLine("moveBatchSelection")}
  ${functionLine("queueReviewedBatch")}
  ${functionLine("restoreBatchAttempt")}
  await queueReviewedBatch();
  const saved=JSON.parse(storage.get(BATCH_ATTEMPT_KEY));
  assert.equal(saved.state,'submitting','an uncertain submission must retain an independent pending attempt');
  assert.equal(saved.request_token,'scan-batch-stable-token');
  assert.equal(batchSubmissionUncertain,true);
  assert.equal(batchEditorLocked,true,'the reviewed draft must remain frozen while acceptance is uncertain');
  moveBatchSelection('alpha',1);
  assert.deepEqual(batchSelectionOrder,['alpha','bravo'],'reorder must stay blocked after a lost response');

  batchPreview=null;batchPendingSubmission=null;batchSubmissionUncertain=false;batchEditorLocked=false;batchRequestToken=null;
  restoreBatchAttempt();
  assert.equal(batchSubmissionUncertain,true,'reload must restore the uncertain attempt');
  assert.equal(batchEditorLocked,true,'reload must keep its exact inputs frozen');
  assert.equal($('queueBatch').textContent,'Retry saved submission');

  failConnection=false;
  await queueReviewedBatch();
  assert.equal(requests.length,2);
  assert.equal(requests[1],requests[0],'retry must send the byte-identical reviewed payload');
  assert.equal(receipt.batch_id,'batch-one');
  assert.equal(batchSubmissionUncertain,false);
  assert.equal(batchEditorLocked,false);
  assert.equal(batchPreview,null);
  assert.equal(storage.has(BATCH_ATTEMPT_KEY),false,'accepted receipt must clear only its completed pending attempt');
})()`);

console.log("Scan batch UI request ownership regressions passed");
