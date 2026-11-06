import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");

function functionLine(name) {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name}`);
  return match[0];
}

function functionBlock(name, nextName) {
  const match = source.match(new RegExp(`^async function ${name}\\(\\)\\{[\\s\\S]*?(?=^async function ${nextName}\\()`, "m"));
  assert.ok(match, `Could not find ${name}`);
  return match[0].trim();
}

function fakeElement(value = "") {
  return {value, checked:false, disabled:false, textContent:"", className:""};
}

const functions = `
  ${functionLine("setScheduleStatus")}
  ${functionLine("clearStoredScheduleBatchAttempt")}
  ${functionLine("storeScheduleBatchAttempt")}
  ${functionLine("setScheduleBatchEditorLocked")}
  ${functionLine("restoreScheduleBatchAttempt")}
  ${functionLine("submitScheduleBatchAttempt")}
  ${functionBlock("saveSchedule", "loadSchedules")}
`;

function harness(fetchImplementation) {
  return eval(`(() => {
    let scheduleBatchSubmitInFlight=false,scheduleBatchSubmissionUncertain=false,scheduleBatchPendingSubmission=null;
    const controls=new Map(),$=id=>{if(!controls.has(id))controls.set(id,fakeElement());return controls.get(id)};
    $('scopeMode').value='batch';
    $('scheduleName').value='Baseline $subnet';
    $('scheduleFirstRun').value='2030-01-02T03:04';
    $('scheduleCadence').value='daily';
    $('scheduleCadenceHours').value='2';
    $('scheduleEnabled').checked=false;
    const storage=new Map(),localStorage={getItem:key=>storage.get(key)||null,setItem:(key,value)=>storage.set(key,value),removeItem:key=>storage.delete(key)};
    const SCHEDULE_BATCH_ATTEMPT_KEY='schedule-attempt';
    const scheduleProfile=()=>({profile_id:'profile-one',version:1,settings:{discovery_mode:'nmap'}});
    const validateCommon=()=>({created_by:'analyst',reviewed_mission_scopes:[],no_strike:[],interface:'eth0',reason:'reviewed',originating_host:'nct',targets:['10.0.1.0/24','10.0.2.0/24'],manual_targets:[],saved_network_ids:['one','two'],reviewed_scope_associations:[]});
    const timeoutSeconds=()=>60,chunkingPayload=()=>({chunking_enabled:false,chunk_size:256,chunk_delay_seconds:0});
    const batchSelections=()=>[{saved_network_id:'one',expected_updated_at:'one-time',expected_association_id:'assoc-one',expected_association_revision:1},{saved_network_id:'two',expected_updated_at:'two-time',expected_association_id:'assoc-two',expected_association_revision:1}];
    const updateSchedulePin=()=>{},apiMessage=(data,fallback)=>data?.detail||fallback;
    let scheduleLoads=0;const loadSchedules=async()=>{scheduleLoads+=1;return true};
    const fetch=fetchImplementation;
    ${functions}
    return {controls,storage,get state(){return {scheduleBatchSubmitInFlight,scheduleBatchSubmissionUncertain,scheduleBatchPendingSubmission,scheduleLoads}},saveSchedule,restoreScheduleBatchAttempt};
  })()`);
}

let firstResolve, firstRequests=[];
const doubleClick = harness((_url, options) => {
  firstRequests.push(options.body);
  return new Promise(resolve => { firstResolve = resolve; });
});
const first = doubleClick.saveSchedule();
const second = doubleClick.saveSchedule();
await Promise.resolve();
assert.equal(firstRequests.length, 1, "double click must make only one request");
const firstPayload = JSON.parse(firstRequests[0]);
firstResolve({ok:true,status:201,json:async()=>({
  contract:"nct-scan-schedule-batch:1",request_token:firstPayload.request_token,
  requested_count:2,accepted_count:2,all_accepted:true,request_replayed:false,
  schedules:[
    {selection_order:1,schedule_id:"schedule-one",generated_name:"Baseline One"},
    {selection_order:2,schedule_id:"schedule-two",generated_name:"Baseline Two"},
  ],
})});
await Promise.all([first, second]);
assert.equal(doubleClick.state.scheduleLoads, 1);
assert.equal(doubleClick.storage.size, 0);

let lostRequests=[], loseResponse=true;
const lostResponse = harness(async (_url, options) => {
  lostRequests.push(options.body);
  const payload=JSON.parse(options.body);
  if(loseResponse)throw new TypeError("connection lost after commit");
  return {ok:true,status:201,json:async()=>({
    contract:"nct-scan-schedule-batch:1",request_token:payload.request_token,
    requested_count:2,accepted_count:2,all_accepted:true,request_replayed:true,
    schedules:[
      {selection_order:1,schedule_id:"schedule-one",generated_name:"Baseline One"},
      {selection_order:2,schedule_id:"schedule-two",generated_name:"Baseline Two"},
    ],
  })};
});
await lostResponse.saveSchedule();
assert.equal(lostResponse.state.scheduleBatchSubmissionUncertain, true);
assert.equal(lostResponse.storage.size, 1, "ambiguous result must preserve the exact request");
lostResponse.restoreScheduleBatchAttempt();
assert.equal(lostResponse.controls.get("saveSchedule").textContent, "Retry saved schedule submission");
loseResponse=false;
await lostResponse.saveSchedule();
assert.equal(lostRequests.length, 2);
assert.equal(lostRequests[1], lostRequests[0], "retry must send the byte-identical payload and token");
assert.equal(lostResponse.state.scheduleBatchSubmissionUncertain, false);
assert.equal(lostResponse.storage.size, 0);

console.log("Scheduled multi-network double-click and lost-response regressions passed");
