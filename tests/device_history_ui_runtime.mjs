import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/device_ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^async function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/device_ui.py`);
  return match[0];
}

await eval(`(async () => {
  const newest=Array.from({length:25},(_,index)=>({run_id:'new-'+index,summary_processing_state:'completed'}));
  const olderRunning={run_id:'older-active',summary_processing_state:'running'};
  const olderCompleted={...olderRunning,summary_processing_state:'completed'};
  let historyRecords=[...newest],historyOffset=25,historyBusy=false,historyPipelineTimer=null;
  let scheduledCallback=null,rendered=[],requested=[];
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{disabled:false,textContent:'',classList:{toggle:()=>{}}});return controls.get(id)};
  const clearTimeout=()=>{};
  const clearInterval=()=>{};
  const setInterval=()=>1;
  const setTimeout=callback=>{scheduledCallback=callback;return 1};
  const renderHistory=records=>{rendered=records.map(item=>item.run_id)};
  const updateWanCollectionOptions=()=>{};
  const historyJSON=async url=>{
    requested.push(url);
    if(url==='/api/device-configs?limit=25&offset=25')return [olderRunning];
    if(url==='/api/device-configs?limit=26&offset=0')return [...newest,olderCompleted];
    throw new Error('Unexpected URL '+url);
  };
  ${handler("refreshLoadedHistory")}
  ${handler("loadHistory")}
  await loadHistory(false);
  assert.equal(historyRecords.length,26);
  assert.ok(rendered.includes('older-active'));
  assert.ok(scheduledCallback);
  const poll=scheduledCallback;scheduledCallback=null;await poll();
  assert.equal(historyRecords.length,26);
  assert.ok(rendered.includes('older-active'));
  assert.equal(historyRecords.find(item=>item.run_id==='older-active').summary_processing_state,'completed');
  assert.deepEqual(requested,[
    '/api/device-configs?limit=25&offset=25',
    '/api/device-configs?limit=26&offset=0'
  ]);
  assert.equal(scheduledCallback,null);
})()`);

assert.ok(source.includes("openDevices=new Set"));
assert.ok(source.includes("openRuns=new Set"));
assert.ok(source.includes("device.dataset.deviceAddress=address"));
assert.ok(source.includes("card.dataset.runId=run.run_id"));

console.log("Device History UI runtime regressions passed");
