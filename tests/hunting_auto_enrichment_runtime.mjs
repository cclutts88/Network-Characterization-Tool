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
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{textContent:'',className:''});return controls.get(id)};
  const encodeURIComponent=value=>String(value);
  const timedJson=(endpoint)=>new Promise(resolve=>requests.push({endpoint,resolve}));
  const rendered=[];
  const renderSearchSploit=data=>rendered.push(data.view);
  ${handler("runSearchSploit")}
  const older=runSearchSploit('older-run'),newer=runSearchSploit('newer-run');
  assert.deepEqual(requests.map(item=>item.endpoint),[
    '/api/searchsploit/hunting/older-run',
    '/api/searchsploit/hunting/newer-run'
  ]);
  requests[1].resolve({response:{ok:true},data:{view:'newer'}});
  await newer;
  requests[0].resolve({response:{ok:true},data:{view:'older'}});
  await older;
  assert.deepEqual(rendered,['newer'],'an obsolete candidate response must not replace the current Hunt evidence');
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
  const rendered=[],enriched=[];
  const renderHunt=data=>rendered.push(data.view);
  const runSearchSploit=(id,revision)=>enriched.push([id,revision]);
  ${handler("beginHuntSelection", "function")}
  ${handler("hunt")}
  const older=hunt();
  controls.get('currentRun').value='B';
  const newer=hunt();
  requests[1].resolve({ok:true,json:async()=>({view:'B'})});
  await newer;
  requests[0].resolve({ok:true,json:async()=>({view:'A'})});
  await older;
  assert.deepEqual(rendered,['B'],'an obsolete Hunt evidence response must not replace the newer selection');
  assert.deepEqual(enriched,[['B',2]],'only the current evidence selection may start candidate enrichment');
})()`);

await eval(`(() => {
  const controls=new Map([
    ['cveFilter',{value:''}],['cveYearFilter',{value:''}],['cveStatusFilter',{value:''}],['exposureFilter',{value:''}]
  ]);
  const $=id=>controls.get(id);
  const esc=value=>String(value??'');
  ${syncHandler("candidateCves")}
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
    {edb_id:'2',title:'A-other',codes:'CVE-2024-0002'}
  ]};
  const matchB={host_key:'scope-b|10.0.0.2',ip:'10.0.0.2',hostname:'router',port:443,protocol:'tcp',product:'bravo',candidates:[
    {edb_id:'3',title:'B-only',codes:'CVE-2023-0003'}
  ]};
  const searchsploitMatches=new Map([['a',matchA],['b',matchB]]);
  ${syncHandler("renderFindingMatchBadges")}
  ${syncHandler("renderHostCveDropdowns")}
  renderFindingMatchBadges();
  assert.match(hostSlots[0].innerHTML,/A-only/);
  assert.doesNotMatch(hostSlots[0].innerHTML,/B-only/,'same hostname must not cross scoped host identities');
  assert.match(hostSlots[1].innerHTML,/B-only/);
  assert.doesNotMatch(hostSlots[1].innerHTML,/A-only/);
  controls.get('cveFilter').value='CVE-2025-0001';
  renderHostCveDropdowns({matches:[matchA,matchB]});
  assert.match(inventorySlot.innerHTML,/A-only/);
  assert.doesNotMatch(inventorySlot.innerHTML,/A-other/,'Inventory must apply the selected CVE to its visible list');
  renderFindingMatchBadges();
  assert.match(hostSlots[0].innerHTML,/A-only/);
  assert.doesNotMatch(hostSlots[0].innerHTML,/A-other/,'Systems must apply the selected CVE to its visible list');
})()`);

console.log("Hunt automatic enrichment runtime regressions passed");
