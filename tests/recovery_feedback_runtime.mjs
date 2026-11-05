import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../app/update_ui.py', import.meta.url), 'utf8');
const consoleSource = source.slice(source.indexOf('def console_page'));
const script = consoleSource.match(/<script>([\s\S]*?)<\/script>/)[1];
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    hidden: false, textContent: '', value: '', files: [{}], children: [],
    removeAttribute(name) {delete this[name];}, replaceChildren() { this.children = []; }, append(child) { this.children.push(child); },
  });
  return elements.get(id);
}
const state = {actor: 'fixture', application_url: '/nct', operation: {phase: 'idle'}};
let poll;
const context = vm.createContext({
  document: {getElementById: element, querySelectorAll: () => [], createElement: () => ({children: [], append(child) {this.children.push(child);}})},
  location: {hash: '', pathname: '/', assign() {}}, history: {replaceState() {}},
  URLSearchParams, sessionStorage: {getItem() {}, setItem() {}}, CSS: {supports: () => false},
  fetch: async () => ({ok: true, json: async () => state}), setInterval(callback) {poll = callback;},
  XMLHttpRequest: class {
    upload = {}; status = 409; responseText = JSON.stringify({detail: 'Choose a GUI update, not a ZIP'});
    open() {} setRequestHeader() {}
    send() { this.upload.onprogress({lengthComputable: true, loaded: 10, total: 10}); this.onload(); }
  },
});
vm.runInContext(script, context);
await vm.runInContext('refresh()', context);
await element('uploadForm').onsubmit({preventDefault() {}});
// The event callback delegates to action; wait until its promise has settled.
await new Promise(resolve => setImmediate(resolve));
assert.match(element('uploadStatus').textContent, /failed: Choose a GUI update/);
assert.equal(element('actionError').hidden, false);
await vm.runInContext('refresh()', context);
await vm.runInContext('refresh()', context);
assert.match(element('actionError').textContent, /not a ZIP/);
assert.equal(element('actionError').hidden, false, 'polling must preserve the action error');
await vm.runInContext("action(async()=>{throw Error('Restore refused: backup changed')})", context);
await vm.runInContext('refresh()', context);
assert.match(element('actionError').textContent, /backup changed/);
await vm.runInContext('action(async()=>{})', context);
assert.equal(element('actionError').hidden, true, 'a deliberate next action clears the previous error');
state.operation = {phase: 'failed', detail: 'Candidate could not start'};
await vm.runInContext('refresh()', context);
assert.match(JSON.stringify(element('checks').children), /Update failed/);
assert.match(consoleSource, /Collection and processing remain paused until verification succeeds/);
for (const phase of ['validated', 'repair_review', 'awaiting_sign_in']) {
  state.operation = {phase};
  context.fetch = async () => ({ok: true, json: async () => state});
  await vm.runInContext('refresh()', context);
  const previous = JSON.stringify(element('checks').children);
  const calls = [];
  context.fetch = async (url, options) => {calls.push([url, options.method]); throw Error('Offline fixture');};
  await vm.runInContext('refresh()', context);
  assert.equal(element('access').hidden, true, 'connection loss must not ask for a code');
  assert.equal(element('workspace').hidden, false, 'keep the last reviewed state');
  assert.equal(element('workspaceControls').disabled, true);
  assert.equal(element('retryStatus').hidden, false);
  assert.equal(JSON.stringify(element('checks').children), previous);
  poll(); await new Promise(resolve => setImmediate(resolve));
  assert.ok(calls.every(([url, method]) => url === '/api/status' && method === 'GET'), 'reconnect cannot replay a mutation');
  context.fetch = async () => ({ok: true, json: async () => state});
  await vm.runInContext('refresh()', context);
  assert.equal(element('workspaceControls').disabled, false);
  assert.equal(element('connectionStatus').hidden, true);
}
for (const bad of [null, [], {}, {operation: []}]) {
  context.fetch = async () => ({ok: true, json: async () => bad});
  await vm.runInContext('refresh()', context);
  assert.equal(element('access').hidden, true);
  assert.equal(element('workspaceControls').disabled, true);
}
context.fetch = async () => ({ok: true, json: async () => state});
await vm.runInContext('refresh()', context);
const reviewed = JSON.stringify(element('checks').children);
for (const badSummary of [true, 'bad', [], {categories:[{actions:[]}],blockers:[],affected_count:0,preserved_scan_queue:0,safe_to_apply:false}]) {
  context.fetch = async () => ({ok: true, json: async () => ({...state, operation:{phase:'repair_review',repair_summary:badSummary}})});
  await vm.runInContext('refresh()', context);
  assert.equal(JSON.stringify(element('checks').children), reviewed, 'malformed summary must not replace the last reviewed display');
  assert.equal(element('workspaceControls').disabled, true);
}
context.fetch = async () => ({ok: true, json: async () => state});
await vm.runInContext('refresh()', context);
const failureReviewed = JSON.stringify(element('checks').children);
for (const badFailure of [null, true, [], {}, {phase:'fence_intent',detail:'saved',recorded_at:'now'}]) {
  context.fetch = async () => ({ok: true, json: async () => ({...state, operation:{phase:'restored',apply_failure:badFailure}})});
  await vm.runInContext('refresh()', context);
  assert.equal(JSON.stringify(element('checks').children), failureReviewed, 'malformed saved failure must not replace the last reviewed display');
  assert.equal(element('workspaceControls').disabled, true);
}
context.fetch = async () => ({ok: false, status: 409, json: async () => ({detail: 'Ordinary refusal'})});
await vm.runInContext('refresh()', context);
assert.equal(element('access').hidden, true);
context.fetch = async () => ({ok: false, status: 403, json: async () => ({detail: 'Access expired', access_required: true})});
await vm.runInContext('refresh()', context);
assert.equal(element('access').hidden, false);
assert.equal(element('workspace').hidden, true);
assert.equal(element('workspaceControls').disabled, true);
assert.equal(element('retryStatus').hidden, true);
await vm.runInContext("current={}; $('workspace').hidden=true; $('access').hidden=true", context);
context.fetch = async () => {throw Error('Initially offline');};
await vm.runInContext('refresh()', context);
assert.equal(element('access').hidden, true);
assert.equal(element('workspace').hidden, true);
assert.equal(element('retryStatus').hidden, false);
context.fetch = async () => ({ok: true, json: async () => state});
poll(); await new Promise(resolve => setImmediate(resolve));
assert.equal(element('workspace').hidden, false, 'initial failure automatically retries status');
const handoffCalls=[];
context.fetch = async (url, options) => {handoffCalls.push([url,options.method]); throw Error('Handoff connection lost');};
await vm.runInContext("action(()=>exchange('fixture-only-code'))", context);
assert.equal(element('access').hidden, true);
assert.equal(element('retryStatus').hidden, false);
poll(); await new Promise(resolve=>setImmediate(resolve));
assert.equal(handoffCalls.filter(([url])=>url==='/api/exchange').length,1, 'status retry must not replay a one-use handoff');
// A delayed account check must explain the cleared field and reject duplicates.
state.operation={phase:'awaiting_sign_in'};
context.fetch=async()=>({ok:true,json:async()=>state});
await vm.runInContext('refresh()',context);
let finishVerification;
const verifyCalls=[];
let destination;
context.location.assign=url=>{destination=url;};
context.fetch=async(url)=>{
  verifyCalls.push(url);
  if(url==='/api/verify-sign-in') return new Promise(resolve=>{finishVerification=resolve;});
  if(url==='/api/status') return {ok:true,json:async()=>({...state,operation:{...state.operation,phase:'release_intent',activity:{active:true,label:'Finishing restart'}}})};
  return {ok:true,json:async()=>({})};
};
element('password').value='synthetic-only';
const pending=element('verifyForm').onsubmit({preventDefault(){}});
await new Promise(resolve=>setImmediate(resolve));
assert.equal(element('password').value,'');
assert.match(element('verifyFeedback').textContent,/Checking sign-in and finishing/);
assert.match(element('verifyFeedback').textContent,/cleared after submission/);
assert.equal(element('verifyProgress').hidden,false);
assert.equal(element('verifyButton').disabled,true);
assert.equal(destination,undefined);
await element('verifyForm').onsubmit({preventDefault(){}});
poll();await new Promise(resolve=>setImmediate(resolve));
assert.deepEqual(verifyCalls,['/api/verify-sign-in','/api/status']);
assert.equal(element('verifySection').hidden,false);
assert.match(element('currentStep').textContent,/Finishing restart/);
finishVerification({ok:true,json:async()=>({url:'/nct',operation:{phase:'complete',controller_sign_in_verified:true}})});
await pending;
assert.equal(destination,'/nct');
assert.match(element('verifyFeedback').textContent,/Sign-in and final restart verified/);
assert.equal(element('verifyProgress').hidden,true);
assert.deepEqual(verifyCalls,['/api/verify-sign-in','/api/status','/api/close']);

for(const problem of ['refused','connection','close']){
  destination=undefined;const calls=[];
  context.fetch=async(url)=>{
    calls.push(url);
    if(url==='/api/status') return {ok:true,json:async()=>state};
    if(problem==='connection') throw Error('Connection lost');
    if(problem==='refused') return {ok:false,json:async()=>({detail:'Account check refused'})};
    if(url==='/api/verify-sign-in') return {ok:true,json:async()=>({url:'/nct',operation:{phase:'complete',controller_sign_in_verified:true}})};
    throw Error('Close failed');
  };
  element('password').value='synthetic-only';
  await element('verifyForm').onsubmit({preventDefault(){}});
  assert.equal(destination,undefined);
  assert.equal(element('password').value,'');
  assert.equal(element('verifyProgress').hidden,true);
  assert.equal(element('verifyButton').disabled,false);
  assert.match(element('verifyFeedback').textContent,problem==='close'?/Sign-in and final restart passed/:/could not be confirmed/);
  const feedback=element('verifyFeedback').textContent;
  await vm.runInContext('refresh()',context);
  assert.equal(element('verifyFeedback').textContent,feedback,'polling must not erase nearby sign-in feedback');
  assert.equal(element('actionError').hidden,false);
  assert.equal(calls.filter(x=>x==='/api/verify-sign-in').length,1);
}
for(const response of [null,{}, {url:'/nct',operation:{phase:'release_intent',controller_sign_in_verified:true}}, {url:'/nct',operation:{phase:'complete',controller_sign_in_verified:false}}]){
  const calls=[];destination=undefined;
  context.fetch=async(url)=>{calls.push(url);return {ok:true,json:async()=>response};};
  await element('verifyForm').onsubmit({preventDefault(){}});
  assert.equal(destination,undefined);
  assert.deepEqual(calls,['/api/verify-sign-in']);
  assert.match(element('verifyFeedback').textContent,/could not be confirmed/);
}
assert.ok(!element('verifyFeedback').textContent.includes('synthetic-only'));
console.log('Recovery feedback persists across polling; upload, restore, connection and account verification checks passed.');

// Progress reports measured work only, and legacy recovery never implies a backup swap.
for(const [activity,expected] of [[{active:true,label:'Saving backup',completed:5,total:10,unit:'bytes'},/5 of 10 bytes/],[{active:true,label:'Checking data'},/no measurable total/],[{active:true,completed:20,total:10,unit:'bytes'},/no measurable total/]]){
  state.operation={phase:'fence_intent',activity};
  context.fetch=async()=>({ok:true,json:async()=>state});await vm.runInContext('refresh()',context);
  assert.match(element('activityMeasurement').textContent,expected);
  assert.match(element('nctObservation').textContent,/unavailable/);
}
state.operation={phase:'interrupted'};await vm.runInContext('refresh()',context);assert.match(element('nextAction').textContent,/administrator/);
state.operation.recovery_guidance='original_reconciliation';await vm.runInContext('refresh()',context);assert.equal(element('rollback').textContent,'Resume original NCT');
state.runtime={available:true,running:false};await vm.runInContext('refresh()',context);assert.match(element('nctObservation').textContent,/stopped/);

const NativeDate=Date;let clock=0;context.Date=class extends NativeDate{static now(){return clock;}};
state.observed_at=100;state.operation={phase:'fence_intent',activity:{active:true,started_at:90,updated_at:95,label:'Slow backup'}};
await vm.runInContext('refresh()',context);clock=60000;await vm.runInContext('updateActivityTimes()',context);
assert.match(element('activityAge').textContent,/Time in this step: 70 seconds/);assert.match(element('activityAge').textContent,/65 seconds ago/);assert.match(element('activityAge').textContent,/not reported a new checkpoint/);
state.operation.activity.active=false;state.operation.phase='complete';await vm.runInContext('refresh()',context);clock+=60000;await vm.runInContext('updateActivityTimes()',context);assert.ok(!element('activityAge').textContent.includes('not reported a new checkpoint'));
