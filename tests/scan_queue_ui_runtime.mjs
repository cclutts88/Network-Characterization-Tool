import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^async function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/ui.py`);
  return match[0];
}

await eval(`(async () => {
  let queueLoadRevision=0,queueTimer=null,currentLive=false,currentId=null,activeStatusRequestRevision=0,activeStatusAppliedRevision=0;
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
  let queueLoadRevision=0,queueTimer=null,currentLive=false,currentId=null,activeStatusRequestRevision=0,activeStatusAppliedRevision=0;
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
  let queueLoadRevision=0,queueTimer=null,currentId=null,currentLive=false,pollTimer=null,activeViewRevision=0,activeStatusRequestRevision=0,activeStatusAppliedRevision=0;
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
  let queueLoadRevision=0,queueTimer=null,currentId='active-A',currentLive=true,pollTimer=null,activeViewRevision=1,activeStatusRequestRevision=0,activeStatusAppliedRevision=0;
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

console.log("Scan queue UI runtime regressions passed");
