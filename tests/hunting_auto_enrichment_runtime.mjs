import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/hunting_ui.py", import.meta.url), "utf8");
function handler(name, prefix = "async function") {
  const match = source.match(new RegExp(`^${prefix} ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/hunting_ui.py`);
  return match[0];
}

function syncHandler(name) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/hunting_ui.py`);
  return match[0];
}

await eval(`(async () => {
  let searchsploitRevision=0,huntRevision=0;
  const requests=[];
  const controls=new Map([['comparisonPanel',{classList:{add(){}}}]]);
  const $=id=>{if(!controls.has(id))controls.set(id,{textContent:'',className:'',classList:{add(){}}});return controls.get(id)};
  const encodeURIComponent=value=>String(value);
  const timedJson=(endpoint)=>new Promise(resolve=>requests.push({endpoint,resolve}));
  const setStatus=()=>{};
  const history={replaceState(){}};
  const location={hash:'#huntOverview'};
  const rendered=[],candidates=[];
  const renderHunt=data=>rendered.push(data.view);
  const renderSearchSploit=data=>candidates.push(data.view);
  ${handler("beginHuntSelection", "function")}
  ${handler("loadNetwork")}
  const older=loadNetwork(),newer=loadNetwork();
  assert.deepEqual(requests.map(item=>item.endpoint),['/api/hunting/network','/api/hunting/network']);
  requests[1].resolve({response:{ok:true},data:{view:'newer',searchsploit:{view:'saved-newer'}}});
  await newer;
  requests[0].resolve({response:{ok:true},data:{view:'older',searchsploit:{view:'saved-older'}}});
  await older;
  assert.deepEqual(rendered,['newer'],'an obsolete network response must not replace current Hunt evidence');
  assert.deepEqual(candidates,['saved-newer'],'candidate results must come from the accepted saved response');
})()`);

await eval(`(async () => {
  let searchsploitRevision=0,huntRevision=0;
  const requests=[];
  const controls=new Map([['currentRun',{value:'A'}]]);
  const $=id=>controls.get(id)||{classList:{add(){}},textContent:'',className:''};
  const fetch=url=>new Promise(resolve=>requests.push({url,resolve}));
  const setStatus=()=>{};
  const encodeURIComponent=value=>String(value);
  const location={hash:'#huntOverview'};
  const history={replaceState(){}};
  const rendered=[],candidates=[];
  const renderHunt=data=>rendered.push(data.view);
  const renderSearchSploit=data=>candidates.push(data.view);
  ${handler("beginHuntSelection", "function")}
  ${handler("hunt")}
  const older=hunt();
  controls.get('currentRun').value='B';
  const newer=hunt();
  requests[1].resolve({ok:true,json:async()=>({view:'B',searchsploit:{view:'saved-B'}})});
  await newer;
  requests[0].resolve({ok:true,json:async()=>({view:'A',searchsploit:{view:'saved-A'}})});
  await older;
  assert.deepEqual(rendered,['B'],'an obsolete Hunt evidence response must not replace the newer selection');
  assert.deepEqual(candidates,['saved-B'],'only the current evidence selection may render its saved candidate assessment');
})()`);

await eval(`(() => {
  const controls=new Map([
    ['cveFilter',{value:''}],['cveYearFilter',{value:''}],['cveStatusFilter',{value:''}],['exposureFilter',{value:''}]
  ]);
  const $=id=>controls.get(id);
  const esc=value=>String(value??'');
  ${syncHandler("candidateCves")}
  ${syncHandler("candidateReferenceMarkup")}
  ${syncHandler("candidatePortGroupMarkup")}
  ${syncHandler("candidateMatchesInlineMarkup")}
  ${syncHandler("candidateInlineMarkup")}
  const hostSlots=[
    {dataset:{hostkey:'scope-a|10.0.0.1',ip:'10.0.0.1',hostname:'router'},innerHTML:''},
    {dataset:{hostkey:'scope-b|10.0.0.2',ip:'10.0.0.2',hostname:'router'},innerHTML:''}
  ];
  const inventorySlot={dataset:{hostkey:'scope-a|10.0.0.1'},innerHTML:''};
  const document={querySelectorAll(selector){
    if(selector==='.finding-match-slot')return[];
    if(selector==='.finding-host-match-slot')return hostSlots;
    if(selector==='.host-cve-slot')return[inventorySlot];
    return[];
  }};
  const ensureCandidateColumns=()=>{};
  const matchA={host_key:'scope-a|10.0.0.1',ip:'10.0.0.1',hostname:'router',port:80,protocol:'tcp',product:'alpha',candidates:[
    {edb_id:'1',title:'A-only',codes:'CVE-2025-0001'},
    {edb_id:'2',title:'A-other',codes:'CVE-2024-0002'},
    {edb_id:'4',title:'A-no-cve',codes:''}
  ]};
  const matchASecond={host_key:'scope-a|10.0.0.1',ip:'10.0.0.1',hostname:'router',port:80,protocol:'tcp',product:'alpha-secondary',candidates:[
    {edb_id:'5',title:'A-second-fingerprint',codes:'CVE-2025-0002'}
  ]};
  const matchB={host_key:'scope-b|10.0.0.2',ip:'10.0.0.2',hostname:'router',port:443,protocol:'tcp',product:'bravo',candidates:[
    {edb_id:'3',title:'B-only',codes:'CVE-2023-0003'}
  ]};
  const searchsploitMatches=new Map([['a',matchA],['a2',matchASecond],['b',matchB]]);
  ${syncHandler("renderFindingMatchBadges")}
  ${syncHandler("renderHostCveDropdowns")}
  renderFindingMatchBadges();
  assert.match(hostSlots[0].innerHTML,/A-only/);
  assert.ok(hostSlots[0].innerHTML.includes('80/tcp · alpha / alpha-secondary · 3 CVEs · 4 candidates'));
  assert.match(hostSlots[0].innerHTML,/CVE-2025-0001 · 1 reference/);
  assert.match(hostSlots[0].innerHTML,/Show all CVEs for this port/);
  assert.match(hostSlots[0].innerHTML,/Candidates without CVE · 1 reference/);
  assert.doesNotMatch(hostSlots[0].innerHTML,/B-only/,'same hostname must not cross scoped host identities');
  assert.match(hostSlots[1].innerHTML,/B-only/);
  assert.doesNotMatch(hostSlots[1].innerHTML,/A-only/);
  controls.get('cveFilter').value='CVE-2025-0001';
  renderHostCveDropdowns({matches:[matchA,matchASecond,matchB]});
  assert.match(inventorySlot.innerHTML,/A-only/);
  assert.doesNotMatch(inventorySlot.innerHTML,/A-other/,'Inventory must apply the selected CVE to its visible list');
  renderFindingMatchBadges();
  assert.match(hostSlots[0].innerHTML,/A-only/);
  assert.doesNotMatch(hostSlots[0].innerHTML,/A-other/,'Systems must apply the selected CVE to its visible list');
})()`);

await eval(`(() => {
  const category={value:''};
  const $=id=>id==='category'?category:null;
  let searchsploitData=null,filterCalls=0,enrichmentCalls=0,summaryCalls=0;
  const applyFilters=()=>filterCalls++;
  const applySearchSploitFilters=()=>enrichmentCalls++;
  const updateFilterSummaries=()=>summaryCalls++;
  ${syncHandler("applyDatasetFilter")}
  const button={dataset:{datasetFilter:'File Transfer'}};
  applyDatasetFilter(button);
  assert.equal(category.value,'File Transfer');
  assert.equal(filterCalls,1);
  assert.equal(summaryCalls,1);
  applyDatasetFilter(button);
  assert.equal(category.value,'','selecting the active Dataset badge again must clear the filter');
  searchsploitData={};
  applyDatasetFilter(button);
  assert.equal(enrichmentCalls,1,'active candidate filters must be reapplied with the Dataset selection');
})()`);

console.log("Hunt saved candidate runtime regressions passed");
