import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/analysis_ui.py", import.meta.url), "utf8");
const match = source.match(/^function renderNetworkChangeScope\(.*$/m);
assert.ok(match, "Could not find renderNetworkChangeScope in app/analysis_ui.py");

const esc = value => String(value ?? "");
const networkChangeScopeLabel = () => "Lab scope";
const scanRef = value => ({selection: value?.selection || "saved source"});
const evidenceLinks = () => "<span>evidence-link</span>";
const renderHostSnapshot = () => "";
const renderChangedHost = () => "";
const comparisonHostName = host => host.ip || host.key || "Unknown address";
const renderNetworkChangeScope = Function(
  "esc", "networkChangeScopeLabel", "scanRef", "evidenceLinks",
  "renderHostSnapshot", "renderChangedHost", "comparisonHostName",
  `return (${match[0]})`,
)(esc, networkChangeScopeLabel, scanRef, evidenceLinks,
  renderHostSnapshot, renderChangedHost, comparisonHostName);

function sourceFunction(name, asynchronous = false) {
  const match = source.match(new RegExp(`^\\s*${asynchronous ? "async " : ""}function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/analysis_ui.py`);
  return match[0].trim();
}

const html = renderNetworkChangeScope({
  status: "comparison_complete",
  before: {selection: "Earlier"},
  after: {selection: "Later"},
  summary: {
    hosts_added: 0,
    hosts_removed: 0,
    hosts_changed: 0,
    routes_not_assessed: 1,
  },
  path_assessments_not_assessed: [{
    key: "192.0.2.10",
    ip: "192.0.2.10",
    route_assessment: {reason: "The later saved source did not retain a complete ordered traceroute path."},
    evidence: {},
  }],
});

assert.match(html, /1 paths not assessed/);
assert.match(html, /Traceroute paths not assessed/);
assert.match(html, /192\.0\.2\.10/);
assert.match(html, /Some traceroute paths were not assessed/);
assert.doesNotMatch(html, /No source-reported host, port, service, product, version, address attribute, MAC, OS, or path changes were detected/);

await eval([
  "(async () => {",
  "let analysisWorkspaceReady=true,analysisActivationRevision=0,preparedComparisonDeepLink='';",
  "const analysisLoadedTasks=new Set(),automatedItems=[{selection_run_id:'run-a'},{selection_run_id:'run-b'}];",
  "const nodes={comparisonBaseline:{value:''},comparisonCurrent:{value:''},networkChangesPanel:{open:false,scrollIntoView(){this.scrolled=true}}};",
  "const $=id=>nodes[id],location={hash:'#networkChangesPanel',search:'?run=run-b&compare=run-b'};",
  "let candidateLoads=0,processedLoads=0,openTaskCalls=0,statusCalls=0;",
  "const loadComparisonCandidates=async()=>{candidateLoads+=1;return true},loadProcessedEvidenceScopes=async()=>{processedLoads+=1;return true};",
  "const loadNetworkOverview=async()=>true,loadNetworkOutliers=async()=>true,loadNmapAssignments=async()=>true,openRun=async()=>true;",
  "const focusRequestedEvidence=()=>{},stopHiddenAnalysisWork=()=>{},syncComparisonButton=()=>{},setStatus=()=>{statusCalls+=1};",
  "const requestAnimationFrame=callback=>callback(),NCTOpenTask=()=>{openTaskCalls+=1};",
  sourceFunction("currentAnalysisTask"),
  sourceFunction("prepareRunComparison"),
  sourceFunction("activateAnalysisTask", true),
  sourceFunction("requestAnalysisTaskActivation", true),
  "await requestAnalysisTaskActivation();",
  "assert.equal(nodes.comparisonCurrent.value,'run-b');assert.equal(nodes.comparisonBaseline.value,'run-a');",
  "assert.equal(candidateLoads,1);assert.equal(processedLoads,1);assert.equal(openTaskCalls,0,'the comparison deep link must not reopen its own task');",
  "nodes.comparisonBaseline.value='operator-choice';await requestAnalysisTaskActivation();",
  "assert.equal(nodes.comparisonBaseline.value,'operator-choice','repeat task activation must preserve the analyst baseline');",
  "assert.equal(candidateLoads,1,'repeat task activation must reuse the successful candidate load');",
  "assert.equal(statusCalls,1,'the deep-link selection notice must appear only once');",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "let location={hash:'#xmlImport'},nmapAssignmentRequest=0,nmapAssignmentPoll=null,activeAssignmentScopes=[],rendered=0,cleared=0;",
  "const nodes={nmapAssignmentList:{innerHTML:''}},$=id=>nodes[id],setStatus=()=>{},clearTimeout=()=>{cleared+=1};",
  "let pending=[];let fetch=url=>new Promise(resolve=>pending.push(()=>resolve({ok:true,json:async()=>url.includes('assignment-scopes')?[]:[]})));",
  "const renderNmapAssignments=()=>{rendered+=1;return true};",
  sourceFunction("currentAnalysisTask"),
  sourceFunction("loadNmapAssignments", true),
  sourceFunction("stopHiddenAnalysisWork"),
  "const departed=loadNmapAssignments();assert.equal(pending.length,2);",
  "location.hash='#networkOverview';stopHiddenAnalysisWork();pending.forEach(resolve=>resolve());",
  "assert.equal(await departed,false,'a response belonging to a departed task must be ignored');",
  "assert.equal(rendered,0,'the departed response must not render hidden assignment work');",
  "location.hash='#xmlImport';fetch=async url=>({ok:true,json:async()=>url.includes('assignment-scopes')?[]:[]});",
  "assert.equal(await loadNmapAssignments(),true,'returning to Import & Investigate must issue a fresh successful read');",
  "assert.equal(rendered,1,'only the fresh re-entry response may render');",
  "assert.ok(cleared>=2,'departure and fresh entry must clear prior polling handles');",
  "})()",
].join("\n"));

await eval([
  "(() => {",
  "let location={hash:'#networkOverview'},nmapAssignmentRequest=7,nmapAssignmentPoll=null,timers=0;",
  "const nodes={manageAssignmentScopes:{classList:{toggle(){}}},nmapAssignmentList:{innerHTML:''}},$=id=>nodes[id];",
  "const authenticatedAnalyst=null,esc=value=>String(value??''),assignmentState=()=>['Processing','pending'],assignmentWhen=()=>'',assignmentForm=()=>'',assignmentHistory=()=>'',assignmentAdmissionActive=()=>false,bindNmapAssignmentActions=()=>{},clearTimeout=()=>{},setStatus=()=>{},loadNmapAssignments=()=>{},setTimeout=()=>{timers+=1;return 1};",
  sourceFunction("currentAnalysisTask"),
  sourceFunction("renderNmapAssignments"),
  "const rendered=renderNmapAssignments([{observation_id:'obs-1',original_filename:'one.xml',actor:'analyst',sha256:'abcdef0123456789',processing_state:'running'}],'',7);",
  "assert.equal(rendered,false,'a late assignment render must be rejected outside its owning task');",
  "assert.equal(timers,0,'a late assignment render must not resurrect hidden polling');",
  "})()",
].join("\n"));
console.log("Network changes path-assessment UI runtime regression passed");
