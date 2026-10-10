import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/storage_ui.py", import.meta.url), "utf8");
const start = source.indexOf("function runtimePercent(");
const end = source.indexOf("document.addEventListener('visibilitychange'", start);
assert.ok(start >= 0 && end > start, "Could not find runtime-health UI functions");
const runtimeCode = source.slice(start, end);

function sample(cpuStatus = "available") {
  const cpu = status => ({
    status,
    percent_of_one_cpu: status === "available" ? 2.5 : undefined,
  });
  return {
    status: cpuStatus === "available" ? "available" : "partial",
    provider: "local",
    sampled_at: "2026-10-10T12:00:00+00:00",
    refresh_after_seconds: 5,
    measurements: {
      process_cpu: cpu(cpuStatus),
      container_cpu: cpu(cpuStatus),
      process_memory: {status: "available", current_bytes: 100, peak_bytes: 120},
      container_memory: {
        status: "available", current_bytes: 200, peak_bytes: 240,
        limit_bytes: 1000,
      },
      data_filesystem: {
        status: "available", used_bytes: 300, available_bytes: 700, total_bytes: 1000,
      },
      database_files: {status: "available", total_bytes: 50, files_present: 1},
    },
    workload: {
      status: "available",
      attempts: {queued: 0, running: 0},
      intake: {waiting: 0, retrying: 0},
    },
    orchestrator: {status: "not_configured"},
  };
}

await eval(`(async () => {
  const controls=new Map();
  const byId=id=>{if(!controls.has(id))controls.set(id,{textContent:'—'});return controls.get(id)};
  const bytes=value=>value==null?'—':value+' B';
  const dateText=value=>value;
  const document={visibilityState:'visible'};
  const timers=[];
  const setTimeout=(callback,ms)=>{const timer={callback,ms,cancelled:false};timers.push(timer);return timer};
  const clearTimeout=timer=>{if(timer)timer.cancelled=true};
  const pending=[];
  class AbortController {
    constructor(){this.signal={aborted:false,reject:null}}
    abort(){this.signal.aborted=true;if(this.signal.reject)this.signal.reject(Object.assign(new Error('Aborted'),{name:'AbortError'}))}
  }
  const fetch=(url,options)=>new Promise((resolve,reject)=>{
    options.signal.reject=reject;pending.push({url,options,resolve,reject});
  });
  ${runtimeCode}

  renderRuntimeHealth((${sample.toString()})('warming_up'));
  assert.equal(byId('runtimeHealthStatus').textContent,'Collecting the second CPU sample. Other live measurements are available.');

  runtimePanelVisible=true;
  const first=refreshRuntimeHealth();
  pending[0].resolve({ok:true,json:async()=>(${sample.toString()})('available')});
  await first;
  assert.equal(byId('runtimeHealthStatus').textContent,'Live local measurements are available.');
  assert.equal(pending[0].options.cache,'no-store');

  const timed=refreshRuntimeHealth();
  const timeout=timers.filter(timer=>!timer.cancelled&&timer.ms===4000).at(-1);
  assert.ok(timeout,'Expected an active four-second timeout');
  timeout.callback();
  await timed;
  assert.match(byId('runtimeHealthStatus').textContent,/refresh timed out/);
  assert.match(byId('runtimeHealthStatus').textContent,/may be out of date/);
  assert.match(byId('runtimeSample').textContent,/last successful sample/);

  byId('runtimeHealthStatus').textContent='Live local measurements are available.';
  byId('runtimeSample').textContent='saved time · current sample';
  const cancelled=refreshRuntimeHealth();
  runtimePanelVisible=false;
  stopRuntimeHealth();
  await cancelled;
  assert.equal(byId('runtimeHealthStatus').textContent,'Live local measurements are available.');
  assert.equal(byId('runtimeSample').textContent,'saved time · current sample');
})()`);

console.log("Runtime health UI timeout and cancellation regressions passed");
