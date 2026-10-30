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
const context = vm.createContext({
  document: {getElementById: element, querySelectorAll: () => [], createElement: () => ({children: [], append(child) {this.children.push(child);}})},
  location: {hash: '', pathname: '/', assign() {}}, history: {replaceState() {}},
  URLSearchParams, sessionStorage: {getItem() {}, setItem() {}}, CSS: {supports: () => false},
  fetch: async () => ({ok: true, json: async () => state}), setInterval() {},
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
console.log('Recovery feedback persists across polling; upload, restore and failed-state checks passed.');
