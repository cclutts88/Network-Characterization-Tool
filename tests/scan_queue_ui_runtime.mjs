import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");
const activeScanWorkspace = () => true;

function handler(name) {
  const match = source.match(new RegExp(`^async function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/ui.py`);
  return match[0];
}

function functionBlock(name, nextName) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `Could not find ${name} in app/ui.py`);
  const end = source.indexOf(`\nfunction ${nextName}(`, start);
  assert.notEqual(end, -1, `Could not find function after ${name} in app/ui.py`);
  return source.slice(start, end);
}

await eval(`(async () => {
  let queueLoadRevision=0,queueTimer=null,queueAssignmentConflictHold=false,currentLive=false,currentId=null,activeStatusRequestRevision=0,activeStatusAppliedRevision=0,activeCollectionEnabled=true;
  const esc=value=>String(value??'');
  let resolveFetch,openedDuringFetch=false,renderedItem=null;
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{textContent:'',className:'',_html:'',set innerHTML(value){this._html=value;renderedItem={dataset:{queueRun:'pending'},open:false}},get innerHTML(){return this._html}});return controls.get(id)};
  const document={querySelectorAll(selector){
    if(selector==='.queue-item[open][data-queue-run]')return openedDuringFetch?[{dataset:{queueRun:'pending'}}]:[];
    if(selector==='.queue-item[data-queue-run]')return renderedItem?[renderedItem]:[];
    return [];
  }};
  const fetch=()=>new Promise(resolve=>{resolveFetch=resolve});
  const clearTimeout=()=>{};
  const setTimeout=()=>1;
  const queueItem=()=>'<details class="queue-item" data-queue-run="pending"></details>';
  const startActiveView=()=>{};
  const showActiveEmpty=()=>{};
  const cancelQueuedRun=()=>{};
  const reassignQueuedRun=()=>{};
  const claimActiveStatus=revision=>{if(revision<activeStatusAppliedRevision)return false;activeStatusAppliedRevision=revision;return true};
  ${handler("loadQueue")}
  const pending=loadQueue();
  openedDuringFetch=true;
  resolveFetch({ok:true,status:200,json:async()=>({runs:[{run_id:'pending',status:'queued',queue_position:1}]})});
  await pending;
  assert.equal(renderedItem.open,true,'opening a row while fetch is pending must survive render');
})()`);

await eval(`(async () => {
  let queueLoadRevision=0,queueTimer=null,queueAssignmentConflictHold=false,currentLive=false,currentId=null,activeStatusRequestRevision=0,activeStatusAppliedRevision=0,activeCollectionEnabled=true;
  const esc=value=>String(value??'');
  const requests=[];
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{textContent:'',className:'',innerHTML:''});return controls.get(id)};
  const document={querySelectorAll(){return[]}};
  const fetch=()=>new Promise(resolve=>requests.push(resolve));
  const clearTimeout=()=>{};
  const setTimeout=()=>1;
  const queueItem=()=>'';
  const shown=[],empty=[];
  const startActiveView=run=>shown.push(run.run_id);
  const showActiveEmpty=()=>empty.push(true);
  const cancelQueuedRun=()=>{};
  const reassignQueuedRun=()=>{};
  const claimActiveStatus=revision=>{if(revision<activeStatusAppliedRevision)return false;activeStatusAppliedRevision=revision;return true};
  ${handler("loadQueue")}
  const older=loadQueue(),newer=loadQueue();
  requests[1]({ok:true,status:200,json:async()=>({runs:[{run_id:'active-now',status:'running'}]})});
  await newer;
  requests[0]({ok:true,status:200,json:async()=>({runs:[]})});
  await older;
  assert.deepEqual(shown,['active-now']);
  assert.equal(empty.length,0,'an obsolete queue response must not replace the active run');
})()`);

await eval(`(async () => {
  let queueLoadRevision=0,queueTimer=99,queueAssignmentConflictHold=false,currentLive=false,currentId=null,activeStatusRequestRevision=0,activeStatusAppliedRevision=0,activeCollectionEnabled=true;
  const queueAssignmentFeedback=new Map(),CSS={escape:value=>value},esc=value=>String(value??'');
  const select={value:'bravo',dataset:{expectedOwner:'alpha',assignmentRevision:'0'},disabled:false};
  const button={disabled:false};
  const assignmentStatus={textContent:'',className:'',focus(){this.focused=true}};
  const controls=new Map([['queueList',{_html:'stale-controls',set innerHTML(value){this._html=value},get innerHTML(){return this._html}}]]);
  const $=id=>{if(!controls.has(id))controls.set(id,{textContent:'',className:'',innerHTML:''});return controls.get(id)};
  const document={
    querySelector(selector){if(selector.includes('data-owner-for'))return select;if(selector.includes('data-reassign'))return button;if(selector.includes('data-assignment-status'))return assignmentStatus;return null},
    querySelectorAll(){return[]},
  };
  let resolveDelayed,statusCalls=0,timerScheduled=false;
  const fetch=url=>{
    if(url.includes('/owner'))return Promise.resolve({ok:false,status:409,json:async()=>({detail:'This waiting scan changed. The assignment was not saved. Reload Active Scans.'})});
    statusCalls+=1;
    if(statusCalls===1)return new Promise(resolve=>{resolveDelayed=resolve});
    return Promise.resolve({ok:true,status:200,json:async()=>({runs:[{run_id:'pending',status:'queued',queue_position:1}]})});
  };
  const clearTimeout=()=>{};
  const setTimeout=()=>{timerScheduled=true;return 42};
  const queueItem=()=>'<details class="queue-item" data-queue-run="pending">fresh-controls</details>';
  const startActiveView=()=>{},showActiveEmpty=()=>{},cancelQueuedRun=()=>{};
  const claimActiveStatus=revision=>{if(revision<activeStatusAppliedRevision)return false;activeStatusAppliedRevision=revision;return true};
  ${handler("loadQueue")}
  ${handler("reassignQueuedRun")}
  const delayed=loadQueue();
  await reassignQueuedRun('pending');
  assert.equal(queueAssignmentConflictHold,true,'a conflict must hold the reviewed assignment');
  assert.equal(queueLoadRevision,2,'a conflict must invalidate an in-flight queue response');
  assert.equal(select.disabled,true,'the stale assignment must stay frozen until explicit refresh');
  assert.equal(button.disabled,true,'the stale save action must stay frozen until explicit refresh');
  assert.equal(select.dataset.expectedOwner,'alpha');
  assert.equal(select.dataset.assignmentRevision,'0');
  resolveDelayed({ok:true,status:200,json:async()=>({runs:[{run_id:'pending',status:'queued',owner:'charlie',queue_assignment_revision:2}]})});
  await delayed;
  assert.equal($('queueList').innerHTML,'stale-controls','a late queue response must not replace stale controls');
  assert.equal(timerScheduled,false,'a conflict must keep automatic polling paused');
  await loadQueue();
  assert.equal(statusCalls,1,'held state must refuse implicit queue refreshes');
  queueAssignmentConflictHold=false;queueAssignmentFeedback.clear();
  await loadQueue();
  assert.equal(statusCalls,2,'explicit refresh must release the hold');
  assert.match($('queueList').innerHTML,/fresh-controls/);
})()`);

await eval(`(async () => {
  let activeViewRevision=0,currentId=null,currentLive=false,pollTimer=null,activeStatusRequestRevision=0,activeStatusAppliedRevision=0;
  const requests=[];
  const fetch=()=>new Promise(resolve=>requests.push(resolve));
  const clearTimeout=()=>{};
  const shown=[],empty=[];
  const startActiveView=run=>{shown.push(run.run_id);currentId=run.run_id;currentLive=true};
  const showActiveEmpty=()=>empty.push(true);
  const claimActiveStatus=revision=>{if(revision<activeStatusAppliedRevision)return false;activeStatusAppliedRevision=revision;return true};
  const status=message=>{throw new Error(message)};
  ${handler("loadActiveRun")}
  const older=loadActiveRun(),newer=loadActiveRun();
  requests[1]({ok:true,json:async()=>({runs:[{run_id:'active-now',status:'running'}]})});
  await newer;
  requests[0]({ok:true,json:async()=>({runs:[]})});
  await older;
  assert.deepEqual(shown,['active-now']);
  assert.equal(empty.length,0,'an obsolete active lookup must not replace the active run with idle');
})()`);

await eval(`(async () => {
  let queueLoadRevision=0,queueTimer=null,queueAssignmentConflictHold=false,currentId=null,currentLive=false,pollTimer=null,activeViewRevision=0,activeStatusRequestRevision=0,activeStatusAppliedRevision=0,activeCollectionEnabled=true;
  const esc=value=>String(value??'');
  const requests=[];
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{textContent:'',className:'',innerHTML:''});return controls.get(id)};
  const document={querySelectorAll(){return[]}};
  const fetch=()=>new Promise(resolve=>requests.push(resolve));
  const clearTimeout=()=>{};
  const setTimeout=()=>1;
  const queueItem=()=>'';
  const shown=[],empty=[];
  const startActiveView=run=>{shown.push(run.run_id);currentId=run.run_id;currentLive=true;activeViewRevision++};
  const showActiveEmpty=()=>{empty.push(true);currentId=null;currentLive=false};
  const cancelQueuedRun=()=>{};
  const reassignQueuedRun=()=>{};
  const status=()=>{};
  const claimActiveStatus=revision=>{if(revision<activeStatusAppliedRevision)return false;activeStatusAppliedRevision=revision;return true};
  ${handler("loadQueue")}
  ${handler("loadActiveRun")}
  const olderQueue=loadQueue(),newerLookup=loadActiveRun();
  requests[1]({ok:true,status:200,json:async()=>({runs:[{run_id:'new-active',status:'running'}]})});
  await newerLookup;
  requests[0]({ok:true,status:200,json:async()=>({runs:[]})});
  await olderQueue;
  assert.deepEqual(shown,['new-active']);
  assert.equal(empty.length,0,'an older queue response must not clear a newer active lookup');
  assert.equal(currentId,'new-active');
})()`);

await eval(`(async () => {
  let queueLoadRevision=0,queueTimer=null,queueAssignmentConflictHold=false,currentId='active-A',currentLive=true,pollTimer=null,activeViewRevision=1,activeStatusRequestRevision=0,activeStatusAppliedRevision=0,activeCollectionEnabled=true;
  const esc=value=>String(value??'');
  const requests=[];
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{textContent:'',className:'',innerHTML:''});return controls.get(id)};
  const document={querySelectorAll(){return[]}};
  const fetch=()=>new Promise(resolve=>requests.push(resolve));
  const clearTimeout=()=>{};
  const setTimeout=()=>1;
  const queueItem=()=>'';
  const shown=[],empty=[];
  const startActiveView=run=>shown.push(run.run_id);
  const showActiveEmpty=()=>{empty.push(true);currentId=null;currentLive=false};
  const cancelQueuedRun=()=>{};
  const reassignQueuedRun=()=>{};
  const status=()=>{};
  const claimActiveStatus=revision=>{if(revision<activeStatusAppliedRevision)return false;activeStatusAppliedRevision=revision;return true};
  ${handler("loadQueue")}
  ${handler("loadActiveRun")}
  const olderQueue=loadQueue(),newerConfirmation=loadActiveRun();
  requests[1]({ok:true,status:200,json:async()=>({runs:[{run_id:'active-A',status:'running'}]})});
  await newerConfirmation;
  requests[0]({ok:true,status:200,json:async()=>({runs:[]})});
  await olderQueue;
  assert.equal(currentId,'active-A','a newer no-op confirmation must own the active status');
  assert.equal(currentLive,true);
  assert.equal(empty.length,0,'an older empty queue response must not clear a confirmed active scan');
  assert.deepEqual(shown,[],'confirming the same active scan must not restart its view');
})()`);

await eval(`(async () => {
  let currentId='live-run',currentLive=true;
  const detail={classList:{hidden:true,contains(name){return name==='hidden'&&this.hidden},add(name){if(name==='hidden')this.hidden=true},remove(name){if(name==='hidden')this.hidden=false}},innerHTML:''};
  const button={closest:()=>({querySelector:()=>detail})};
  const document={querySelectorAll:()=>[detail]};
  const fetch=async()=>({ok:true,json:async()=>({run_id:'retained-run',status:'completed',created_at:'2026-10-04T00:00:00Z',artifacts:[],execution_phases:[]})});
  const esc=value=>String(value??'');
  const scanRef=()=>({primary:'Retained scan',detail:'Retained scan details'});
  const scanTime=value=>value;
  const scanArtifactMarkup=()=>'';
  ${handler("selectRun")}
  await selectRun('retained-run',button);
  assert.equal(currentId,'live-run','opening history must not replace the active scan identity');
  assert.equal(currentLive,true,'opening history must not stop active scan polling');
  assert.match(detail.innerHTML,/Retained scan/,'retained details should render inside Scan History');
})()`);

await eval(`(async () => {
  let currentId='run-one',activeViewRevision=1,liveDiscoveryController=null,liveDiscoveryInFlight=null,liveDiscoveryRunId=null;
  const requests=[];
  const fetch=(url,options)=>new Promise(resolve=>requests.push({url,options,resolve}));
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{textContent:'',className:''});return controls.get(id)};
  const rendered=[];
  const renderLiveDiscoveries=data=>rendered.push(data.run);
  ${functionBlock("cancelLiveDiscoveryRequest", "renderCurrentProgress")}
  const first=loadLiveDiscoveries('run-one',1);
  const duplicate=loadLiveDiscoveries('run-one',1);
  assert.equal(first,duplicate,'a delayed live request must be reused for the same run');
  assert.equal(requests.length,1,'polling must not pile up live discovery reads');
  currentId='run-two';activeViewRevision=2;
  const second=loadLiveDiscoveries('run-two',2);
  assert.equal(requests.length,2,'a new run must start one new live read');
  assert.equal(requests[0].options.signal.aborted,true,'changing runs must abort the old live read');
  requests[0].resolve({ok:true,json:async()=>({run:'obsolete'})});
  requests[1].resolve({ok:true,json:async()=>({run:'current'})});
  await Promise.all([first,duplicate,second]);
  assert.deepEqual(rendered,['current'],'an obsolete live response must not replace the current run');
  currentId='run-three';activeViewRevision=3;
  const terminalPending=loadLiveDiscoveries('run-three',3);
  assert.equal(requests.length,3);
  cancelLiveDiscoveryRequest();
  assert.equal(requests[2].options.signal.aborted,true,'ending a run must abort its pending live read');
  requests[2].resolve({ok:true,json:async()=>({run:'ended'})});
  await terminalPending;
  assert.deepEqual(rendered,['current'],'an ended run must not render a late live response');
})()`);

await eval(`(async () => {
  const scanDataLoaded=new Set(),scanDataLoading=new Map();
  let attempts=0;
  const loader=async()=>{attempts+=1;return attempts>1};
  ${handler("ensureScanData")}
  assert.equal(await ensureScanData('retryable',loader),false);
  assert.equal(scanDataLoaded.has('retryable'),false,'a failed task read must not be cached');
  assert.equal(await ensureScanData('retryable',loader),true);
  assert.equal(scanDataLoaded.has('retryable'),true,'the successful retry must be cached');
  await ensureScanData('retryable',loader);
  assert.equal(attempts,2,'a successful task read should be reused on return');
})()`);

console.log("Scan queue UI runtime regressions passed");
