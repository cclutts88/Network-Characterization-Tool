import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");
const analysisSource = fs.readFileSync(new URL("../app/analysis_ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^async function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/ui.py`);
  return match[0];
}

function syncHandler(name) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/ui.py`);
  return match[0];
}

function analysisSyncHandler(name) {
  const match = analysisSource.match(new RegExp(`^\\s*function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/analysis_ui.py`);
  return match[0];
}

await eval(`(async () => {
  let historyGroups=[{group_id:'g',runs:[{
    run_id:'scoped',
    foundation_status:{admission_intent:{state:'pending',activity_state:'waiting'}},
    analysis_job_status:{current_job:null}
  }]}],historyRefreshRevision=0,historyJobTimer=null;
  let scheduled=0,refreshes=0,scheduledCallback=null;
  const clearTimeout=()=>{};
  const setTimeout=callback=>{scheduled+=1;scheduledCallback=callback;return scheduled};
  const currentOpenHistoryGroups=()=>new Set(['g']);
  const renderHistory=()=>{};
  const status=message=>{throw new Error(message)};
  const historyJSON=async()=>{
    refreshes+=1;
    return {runs:[{
      run_id:'scoped',
      foundation_status:refreshes===1
        ? {admission_intent:{state:'admitted',activity_state:'complete'},processing_job:{latest_attempt:{state:'queued'}}}
        : {state:'foundation_complete',admission_intent:{state:'admitted',activity_state:'complete'},processing_job:{latest_attempt:{state:'completed'}}},
      analysis_job_status:{current_job:null}
    }]};
  };
  ${syncHandler("admissionRefreshActive")}
  ${syncHandler("scheduleHistoryJobRefresh")}
  ${handler("refreshVisibleHistoryRuns")}
  scheduleHistoryJobRefresh();
  assert.equal(scheduled,1);
  await scheduledCallback();
  assert.equal(refreshes,1);
  assert.equal(historyGroups[0].runs[0].foundation_status.processing_job.latest_attempt.state,'queued');
  assert.equal(scheduled,2);
  await scheduledCallback();
  assert.equal(refreshes,2);
  assert.equal(historyGroups[0].runs[0].foundation_status.state,'foundation_complete');
  assert.equal(historyGroups[0].runs[0].foundation_status.processing_job.latest_attempt.state,'completed');
  assert.equal(scheduled,2);
})()`);

await eval(`(async () => {
  let historyGroups=[{group_id:'g',runs:[{run_id:'old'}]}],historyRefreshRevision=0;
  let resolveHistoryJSON;
  const historyJSON=()=>new Promise(resolve=>{resolveHistoryJSON=resolve});
  const currentOpenHistoryGroups=()=>new Set(['g']);
  const renderHistory=()=>{};
  const scheduleHistoryJobRefresh=()=>{};
  const status=message=>{throw new Error(message)};
  ${handler("refreshVisibleHistoryRuns")}
  const pending=refreshVisibleHistoryRuns();
  historyGroups[0].runs.push({run_id:'newly-loaded-older'});
  resolveHistoryJSON({runs:[{run_id:'old',status:'completed'}]});
  await pending;
  assert.deepEqual(historyGroups[0].runs.map(run=>run.run_id),['old','newly-loaded-older']);
  assert.equal(historyGroups[0].runs[0].status,'completed');
})()`);

await eval(`(async () => {
  let historyGroups=[
    {group_id:'g',scan_count:3,runs:[
      {run_id:'deleted',status:'running'},
      {run_id:'stays',status:'running'},
      {run_id:'moves',status:'running'}
    ],has_more:false,next_cursor:null},
    {group_id:'h',scan_count:1,runs:[{run_id:'h-stays',status:'completed'}],has_more:false,next_cursor:null}
  ];
  let historyBusy=false,historyJobTimer=null,historyRefreshRevision=0,historyCatalogOffset=0,historyCatalogHasMore=false,presetHistoryRuns=[];
  const requested=[];
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{disabled:false,innerHTML:''});return controls.get(id)};
  const currentOpenHistoryGroups=()=>new Set(['g','h']);
  let renderedOpenGroups=new Set();
  const renderHistory=openGroups=>{renderedOpenGroups=new Set(openGroups)};
  const scheduleHistoryJobRefresh=()=>{};
  const esc=value=>String(value);
  const clearTimeout=()=>{};
  const clearInterval=()=>{};
  const setInterval=()=>1;
  const historyJSON=async url=>{
    requested.push(url);
    if(url.startsWith('/api/scan-history-groups?'))return {groups:[
      {group_id:'g',scan_count:2},
      {group_id:'h',scan_count:2}
    ],has_more:false};
    if(url==='/api/scan-runs-grouped?limit=25&offset=0')return [];
    if(url.startsWith('/api/scan-history-groups/g/runs'))return {
      group:{group_id:'g',scan_count:2},total:2,has_more:false,next_cursor:null,
      runs:[{run_id:'new',status:'completed'},{run_id:'stays',status:'completed'}]
    };
    if(url.startsWith('/api/scan-history-groups/h/runs'))return {
      group:{group_id:'h',scan_count:2},total:2,has_more:false,next_cursor:null,
      runs:[{run_id:'moves',status:'completed'},{run_id:'h-stays',status:'completed'}]
    };
    throw new Error('Unexpected URL '+url);
  };
  ${handler("historyCatalogWindow")}
  ${handler("historyGroupWindow")}
  ${handler("loadHistory")}
  await loadHistory(true);
  assert.ok(requested.some(url=>url.startsWith('/api/scan-history-groups/g/runs')));
  assert.ok(requested.some(url=>url.startsWith('/api/scan-history-groups/h/runs')));
  const g=historyGroups.find(group=>group.group_id==='g');
  const h=historyGroups.find(group=>group.group_id==='h');
  assert.deepEqual(g.runs.map(run=>run.run_id),['new','stays']);
  assert.equal(g.runs.find(run=>run.run_id==='stays').status,'completed');
  assert.equal(g.has_more,false);
  assert.equal(g.next_cursor,null);
  assert.deepEqual(h.runs.map(run=>run.run_id),['moves','h-stays']);
  assert.ok(!historyGroups.flatMap(group=>group.runs).some(run=>run.run_id==='deleted'));
  assert.ok(!g.runs.some(run=>run.run_id==='moves'));
  assert.deepEqual([...renderedOpenGroups].sort(),['g','h']);
})()`);

await eval(`(async () => {
  const initialGroups=Array.from({length:101},(_,index)=>({
    group_id:'g'+index,scan_count:index===100?30:1,
    runs:index===100?Array.from({length:30},(_,run)=>({run_id:'old-'+run,status:'completed'})):[],
    has_more:false,next_cursor:null
  }));
  let historyGroups=initialGroups,historyBusy=false,historyJobTimer=null,historyRefreshRevision=0,historyCatalogOffset=101,historyCatalogHasMore=false,presetHistoryRuns=[];
  const requested=[];
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{disabled:false,innerHTML:''});return controls.get(id)};
  const currentOpenHistoryGroups=()=>new Set(['g100']);
  let renderedOpenGroups=new Set();
  const renderHistory=openGroups=>{renderedOpenGroups=new Set(openGroups)};
  const scheduleHistoryJobRefresh=()=>{};
  const esc=value=>String(value);
  const clearTimeout=()=>{};
  const clearInterval=()=>{};
  const setInterval=()=>1;
  const historyJSON=async url=>{
    requested.push(url);
    if(url==='/api/scan-history-groups?limit=100&offset=0')return {
      groups:Array.from({length:100},(_,index)=>({group_id:'g'+index,scan_count:1})),
      total:101,has_more:true
    };
    if(url==='/api/scan-history-groups?limit=1&offset=100')return {
      groups:[{group_id:'g100',scan_count:30}],total:101,has_more:false
    };
    if(url==='/api/scan-runs-grouped?limit=25&offset=0')return [];
    if(url.startsWith('/api/scan-history-groups/g100/runs'))return {
      group:{group_id:'g100',scan_count:30},total:30,has_more:false,next_cursor:null,
      runs:Array.from({length:30},(_,run)=>({run_id:'fresh-'+run,status:'completed'}))
    };
    throw new Error('Unexpected URL '+url);
  };
  ${handler("historyCatalogWindow")}
  ${handler("historyGroupWindow")}
  ${handler("loadHistory")}
  await loadHistory(true);
  assert.equal(historyGroups.length,101);
  const oldestLoaded=historyGroups.find(group=>group.group_id==='g100');
  assert.ok(oldestLoaded);
  assert.equal(oldestLoaded.runs.length,30);
  assert.equal(oldestLoaded.runs[0].run_id,'fresh-0');
  assert.ok(requested.includes('/api/scan-history-groups?limit=1&offset=100'));
  assert.deepEqual([...renderedOpenGroups],['g100']);
})()`);

await eval(`(async () => {
  let authenticatedAnalyst=null,activeAssignmentScopes=[],nmapAssignmentPoll=null;
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{innerHTML:'',textContent:'',className:'',classList:{toggle:()=>{}}});return controls.get(id)};
  const esc=value=>String(value??'');
  const assignmentState=()=>['Automatic processing retrying','pending'];
  const assignmentWhen=value=>String(value||'now');
  const assignmentForm=()=>'';
  const assignmentHistory=()=>'';
  const bindNmapAssignmentActions=()=>{};
  const setStatus=()=>{};
  const clearTimeout=()=>{};
  let scheduled=0,scheduledCallback=null,loads=0;
  const setTimeout=callback=>{scheduled+=1;scheduledCallback=callback;return scheduled};
  let renderNmapAssignments;
  const loadNmapAssignments=()=>{loads+=1;renderNmapAssignments([{
    observation_id:'o',original_filename:'source.xml',observed_at:'now',actor:'analyst',sha256:'abcdef123456',
    processing_state:'completed',assignment_state:'foundation_complete',admission_intent:{state:'admitted',activity_state:'complete'}
  }],'o')};
  ${analysisSyncHandler("assignmentAdmissionActive")}
  renderNmapAssignments=${analysisSyncHandler("renderNmapAssignments")};
  renderNmapAssignments([{
    observation_id:'o',original_filename:'source.xml',observed_at:'now',actor:'analyst',sha256:'abcdef123456',
    processing_state:null,admission_intent:{state:'pending',activity_state:'retrying',last_error:'temporary queue error'}
  }],'o');
  assert.equal(scheduled,1);
  scheduledCallback();
  assert.equal(loads,1);
  assert.equal(scheduled,1);
  renderNmapAssignments([{
    observation_id:'paused',original_filename:'paused.xml',observed_at:'now',actor:'analyst',sha256:'abcdef123456',
    processing_state:null,admission_intent:{state:'pending',activity_state:'paused',last_error:'storage unavailable'}
  }],'paused');
  assert.equal(scheduled,1);
})()`);

console.log("Scan History UI runtime regressions passed");
