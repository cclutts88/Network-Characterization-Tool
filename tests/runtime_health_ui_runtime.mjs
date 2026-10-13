import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/storage_ui.py", import.meta.url), "utf8");
const start = source.indexOf("function runtimeDuration(");
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
    trends: {
      status: "running", near_peak_percent: 95,
      metrics: {
        process_cpu: {status: "available", sampling_attempts: 3, available_samples: 2, current: 2.5, average: 1.5, maximum: 2.5, longest_near_peak_seconds: 5, basis: "Percent of one CPU"},
        container_cpu: {status: "available", sampling_attempts: 3, available_samples: 2, current: 2.0, average: 1.0, maximum: 2.0, longest_near_peak_seconds: 0, basis: "Percent of 2-CPU container allowance"},
        process_memory: {status: "available", sampling_attempts: 3, available_samples: 3, current: 100, average: 90, maximum: 100, longest_near_peak_seconds: 10, basis: "NCT process resident memory"},
        container_memory: {status: "available", sampling_attempts: 3, available_samples: 3, current: 200, average: 180, maximum: 200, longest_near_peak_seconds: 5, basis: "Linux control-group memory"},
      },
    },
    orchestrator: {status: "not_configured"},
  };
}

await eval(`(async () => {
  const controls=new Map();
  const byId=id=>{if(!controls.has(id))controls.set(id,{textContent:'—'});return controls.get(id)};
  const bytes=value=>{if(value==null)return '—';const units=['B','KiB','MiB','GiB','TiB'];let i=0;while(value>=1024&&i<4){value/=1024;i++;}return value.toFixed(i?1:0)+' '+units[i];};
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
  assert.equal(byId('runtimeProcessCpuCurrent').textContent,'2.5%');
  assert.equal(byId('runtimeProcessCpuAverage').textContent,'1.5%');
  assert.equal(byId('runtimeProcessCpuMaximum').textContent,'2.5%');
  assert.equal(byId('runtimeProcessCpuNearMax').textContent,'5 sec');
  assert.equal(byId('runtimeProcessMemoryCurrent').textContent,'100 B');
  assert.equal(byId('runtimeProcessMemoryAverage').textContent,'90 B');
  assert.equal(byId('runtimeProcessMemoryMaximum').textContent,'100 B');
  assert.equal(byId('runtimeProcessMemoryNearMax').textContent,'10 sec');
  assert.equal(byId('runtimeContainerCpuBasis').textContent,'Basis: 2-CPU container allowance');
  assert.equal(byId('runtimeTrendStatus').textContent,'Window: 3 of 720 samples · 5 seconds apart · Near max: at least 95% · Resets on restart');
  assert.match(byId('kubernetesStatus').textContent,/Not configured/);
  assert.equal(byId('kubernetesExpected').textContent,'—');
  assert.equal(byId('kubernetesMetricsUnavailable').hidden,false);

  const cluster=(${sample.toString()})('available');
  cluster.orchestrator={
    status:'partial', sampled_at:'2026-10-12T12:00:00+00:00',
    last_successful_sampled_at:'2026-10-12T12:00:00+00:00',
    deployment:{status:'available',expected_instances:1,instances_found:1,ready_instances:1,starting_or_not_ready:0,ending:0},
    metrics:{status:'unavailable'},
  };
  renderRuntimeHealth(cluster);
  assert.match(byId('kubernetesStatus').textContent,/Partial/);
  assert.equal(byId('kubernetesReady').textContent,'1');
  assert.match(byId('kubernetesMetricsMessage').textContent,/did not provide pod CPU or memory/);
  assert.equal(byId('kubernetesCpuRow').hidden,true);
  cluster.orchestrator.status='available';
  cluster.orchestrator.metrics={status:'available',reported_instances:1,observed_instances:1,cpu_millicores:125,memory_bytes:67108864};
  renderRuntimeHealth(cluster);
  assert.equal(byId('kubernetesCpu').textContent,'125 millicores');
  assert.equal(byId('kubernetesMemory').textContent,'64.0 MiB');
  assert.equal(byId('kubernetesCpuRow').hidden,false);
  assert.equal(byId('kubernetesMetricsUnavailable').hidden,true);

  const failed=(${sample.toString()})('unavailable');
  for(const item of Object.values(failed.trends.metrics))Object.assign(item,{status:'unavailable',available_samples:0,current:null,average:null,maximum:null,longest_near_peak_seconds:0});
  renderRuntimeHealth(failed);
  for(const id of ['runtimeProcessCpuCurrent','runtimeProcessCpuAverage','runtimeProcessCpuMaximum','runtimeProcessCpuNearMax','runtimeContainerCpuCurrent','runtimeContainerCpuAverage','runtimeContainerCpuMaximum','runtimeContainerCpuNearMax','runtimeProcessMemoryCurrent','runtimeProcessMemoryAverage','runtimeProcessMemoryMaximum','runtimeProcessMemoryNearMax','runtimeContainerMemoryCurrent','runtimeContainerMemoryAverage','runtimeContainerMemoryMaximum','runtimeContainerMemoryNearMax'])assert.equal(byId(id).textContent,'Unavailable');

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
