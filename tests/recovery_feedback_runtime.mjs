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
    replaceChildren() { this.children = []; }, append(child) { this.children.push(child); },
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
console.log('Recovery feedback persists across polling; upload, restore and failed-state checks passed.');
