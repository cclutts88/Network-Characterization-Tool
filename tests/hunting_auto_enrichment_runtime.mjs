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
  let searchsploitRevision=0,huntRevision=0,huntRequestController=null,loadedViewReceipt=null,current=null;
  const requests=[];
  const controls=new Map([['comparisonPanel',{classList:{add(){},contains(){return false}}}]]);
  const $=id=>{if(!controls.has(id))controls.set(id,{textContent:'',className:'',classList:{add(){},contains(){return false}}});return controls.get(id)};
  const encodeURIComponent=value=>String(value);
  const timedJson=(endpoint,options={})=>new Promise(resolve=>requests.push({endpoint,signal:options.signal,resolve}));
  const setStatus=()=>{};
  const startHuntLoadStatus=()=>{};
  const stopHuntLoadStatus=()=>{};
  const history={replaceState(){}};
  const location={hash:'#huntOverview'};
  const rendered=[],candidates=[];
  const renderHunt=data=>rendered.push(data.view);
  const renderSearchSploit=data=>candidates.push(data.view);
  ${handler("beginHuntSelection", "function")}
  ${handler("loadNetwork")}
  const older=loadNetwork(),newer=loadNetwork();
  assert.deepEqual(requests.map(item=>item.endpoint),['/api/hunting/network','/api/hunting/network']);
  assert.equal(requests[0].signal.aborted,true,'a newer network load must cancel the older request');
  assert.equal(requests[1].signal.aborted,false);
  requests[1].resolve({response:{ok:true},data:{view:'newer',searchsploit:{view:'saved-newer'}}});
  await newer;
  requests[0].resolve({response:{ok:true},data:{view:'older',searchsploit:{view:'saved-older'}}});
  await older;
  assert.deepEqual(rendered,['newer'],'an obsolete network response must not replace current Hunt evidence');
  assert.deepEqual(candidates,['saved-newer'],'candidate results must come from the accepted saved response');
})()`);

await eval(`(async () => {
  let searchsploitRevision=0,huntRevision=0,huntRequestController=null;
  const requests=[];
  const controls=new Map([['currentRun',{value:'A'}]]);
  const $=id=>controls.get(id)||{classList:{add(){}},textContent:'',className:''};
  const fetch=url=>new Promise(resolve=>requests.push({url,resolve}));
  const setStatus=()=>{};
  const stopHuntLoadStatus=()=>{};
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

await eval(`(async () => {
  let searchsploitRevision=0,huntRevision=0,huntRequestController=null,loadedViewReceipt=null,current=null,lastTone='',statuses=[];
  const controls=new Map([['comparisonPanel',{classList:{add(){}}}],['refreshNetwork',{disabled:false,textContent:''}],['huntSubtitle',{textContent:''}],['status',{classList:{contains:value=>value===lastTone}}]]);
  const $=id=>controls.get(id);
  const location={search:'?run=retained-run',hash:'#huntOverview'};
  const history={replaceState(){}};
  const loadCandidates=()=>{};
  const loadSearchSploitStatus=async()=>{};
  const requestAnimationFrame=callback=>callback();
  const encodeURIComponent=value=>String(value);
  const renderHunt=data=>{current=data};
  const renderSearchSploit=()=>{};
  const setStatus=(message,tone='')=>{statuses.push(message);lastTone=tone};
  const startHuntLoadStatus=()=>{};
  const stopHuntLoadStatus=()=>{controls.get('refreshNetwork').disabled=false};
  let call=0;
  const timedJson=async endpoint=>{call+=1;if(call===1)return{response:{ok:true},data:{view:'focused'}};throw new Error('network refresh failed')};
  ${handler("beginHuntSelection", "function")}
  ${handler("loadNetwork")}
  ${handler("start")}
  await start();
  assert.equal(loadedViewReceipt?.kind,'focused','initial focused loads must retain their exact view receipt');
  assert.equal(loadedViewReceipt?.label,'focused scan Network Evidence');
  const focusedTime=loadedViewReceipt.at.toLocaleTimeString();
  await loadNetwork();
  assert.match(statuses.at(-1),/network refresh failed/);
  assert.match(statuses.at(-1),/focused scan Network Evidence/);
  assert.ok(statuses.at(-1).includes(focusedTime),'failed refresh must name when the retained focused view loaded');
  assert.match(controls.get('huntSubtitle').textContent,/focused scan Network Evidence/);
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

await eval(`(() => {
  const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const rowData=()=>'';
  const originEvidence=()=>'';
  const macEvidence=()=>'';
  const datasetFilterButton=value=>'<button>'+esc(value)+'</button>';
  const stateChips=()=>'<span>observed</span>';
  const summaryStateChips=()=>'<span>observed</span>';
  const findingTransportMarkup=item=>'<code>'+esc(item.port||'-')+'/'+esc(item.protocol||'-')+'</code>';
  const findingMatchKey=item=>[item.host_key,item.protocol,item.port,item.service,item.product,item.version].join('|');
  const renderMatchBasis=item=>esc((item.match_basis||[]).join('; '));
  ${syncHandler("findingGroupKey")}
  ${syncHandler("findingGroups")}
  ${syncHandler("findingRowMarkup")}
  ${syncHandler("renderFindingSummaries")}
  const findings=[
    {host_key:'scope-a|10.0.0.10',ip:'10.0.0.10',hostname:'web',subnet:'10.0.0.0/24',device_type:'server',category:'Web',evidence_states:['observed'],evidence_kind:'nmap',protocol:'tcp',port:80,service:'http',product:'nginx',version:'1.24',match_basis:['port']},
    {host_key:'scope-a|10.0.0.10',ip:'10.0.0.10',hostname:'web',subnet:'10.0.0.0/24',device_type:'server',category:'Web',evidence_states:['observed'],evidence_kind:'nmap',protocol:'tcp',port:80,service:'http',product:'Apache',version:'2.4',match_basis:['product']},
    {host_key:'scope-a|10.0.0.10',ip:'10.0.0.10',hostname:'web',subnet:'10.0.0.0/24',device_type:'server',category:'Remote',evidence_states:['observed'],evidence_kind:'nmap',protocol:'tcp',port:22,service:'ssh',product:'OpenSSH',version:'9',match_basis:['service']},
    {ip:'10.0.0.99',hostname:'legacy',category:'Legacy A',evidence_states:['observed'],evidence_kind:'nmap',protocol:'tcp',port:1,service:'tcpmux'},
    {ip:'10.0.0.99',hostname:'legacy',category:'Legacy B',evidence_states:['observed'],evidence_kind:'nmap',protocol:'tcp',port:2,service:'compressnet'}
  ];
  const summary=renderFindingSummaries(findings);
  assert.equal((summary.match(/<tr class="finding-summary-row"/g)||[]).length,3,'unkeyed retained rows must remain separate rather than merging by IP or hostname');
  for(const row of summary.split('<tr class="finding-summary-row"').slice(1))assert.equal((row.match(/<td>/g)||[]).length,8,'every combined row must match the eight visible headings');
  assert.match(summary,/nginx/);
  assert.match(summary,/Apache/,'different product facts on the same port must both remain visible');
  assert.ok((summary.match(/80\\/tcp/g)||[]).length>=3,'the transport list shows the port once and each same-port service fingerprint repeats it');
  assert.match(summary,/Each service fingerprint repeats its port/);
  assert.match(summary,/data-hostkey="scope-a\|10\.0\.0\.10"/);
  const detailed=findingRowMarkup(findings[0]);
  assert.equal((detailed.match(/<td>/g)||[]).length,8,'every filtered row must match the eight visible headings');
  assert.match(detailed,/finding-match-slot/);
  assert.ok(detailed.indexOf('finding-match-slot')>detailed.indexOf('nginx'),'the CVE cell must follow the service and product cell');
})()`);

console.log("Hunt saved candidate runtime regressions passed");

await eval(`(async () => {
  const controls=new Map([
    ['currentRun',{value:'',innerHTML:'',disabled:true}],
    ['baselineRun',{value:'',innerHTML:'',disabled:false}],
    ['compare',{disabled:false}],
    ['candidateStatus',{textContent:'',className:''}]
  ]);
  const $=id=>controls.get(id);
  const scanRef=item=>({selection:item.selection_run_id,detail:item.selection_run_id});
  const esc=value=>String(value??'');
  const location={search:''};
  const URLSearchParams=globalThis.URLSearchParams;
  let candidates=[],mainStatusCalls=0;
  const setStatus=()=>mainStatusCalls++;
  const responses=[];
  const fetch=async()=>responses.shift();
  const reply=value=>({ok:true,status:200,url:'/api/scan-comparisons/candidates',redirected:false,text:async()=>JSON.stringify(value)});
  ${syncHandler("comparisonCandidateItems")}
  ${syncHandler("optionRows")}
  ${syncHandler("refreshBaselines")}
  ${handler("responseJson")}
  ${handler("loadCandidates")}
  responses.push(reply({items:[{selection_run_id:'run-2'},{selection_run_id:'run-1'}],unavailable:[],pagination:{total:2}}));
  await loadCandidates();
  assert.deepEqual(candidates.map(item=>item.selection_run_id),['run-2','run-1']);
  assert.match(controls.get('currentRun').innerHTML,/run-2/);
  assert.equal(controls.get('currentRun').disabled,false);
  assert.match(controls.get('candidateStatus').textContent,/2 retained scans are available/);
  assert.equal(mainStatusCalls,0,'scan-list success must not overwrite Network Evidence status');
  responses.push(reply([{selection_run_id:'legacy-run'}]));
  await loadCandidates();
  assert.deepEqual(candidates.map(item=>item.selection_run_id),['legacy-run'],'legacy bare-array responses remain supported');
  responses.push(reply({items:null}));
  await loadCandidates();
  assert.equal(controls.get('currentRun').disabled,true);
  assert.match(controls.get('candidateStatus').textContent,/retained scan list could not be opened/i);
  assert.equal(mainStatusCalls,0,'scan-list failure must stay in its own status area');
})()`);

await eval(`(() => {
  const controls=new Map([['category',{value:''}],['datasetPreview',{innerHTML:''}]]);
  const $=id=>controls.get(id);
  const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let datasetPreviewByName=new Map();
  ${syncHandler("datasetPreviewKey")}
  ${syncHandler("prepareDatasetPreview")}
  ${syncHandler("datasetPreviewText")}
  ${syncHandler("showDatasetPreview")}
  ${syncHandler("resetDatasetPreview")}
  ${syncHandler("datasetFilterButton")}
  ${syncHandler("findingTransport")}
  ${syncHandler("findingTransportMarkup")}
  prepareDatasetPreview([
    {host_key:'scope-a|10.0.0.1',category:'Web Applications & APIs',port:443,protocol:'tcp',service:'https',product:'nginx',version:'1.25'},
    {host_key:'scope-b|10.0.0.2',category:'Web Applications & APIs',port:8080,protocol:'tcp',service:'http',product:'other-server'},
    {host_key:'scope-a|10.0.0.1',category:'Remote Access',port:22,protocol:'tcp',service:'ssh',product:'OpenSSH'}
  ]);
  assert.equal(datasetPreviewText('Web Applications & APIs'),'Web Applications & APIs: 443/tcp · https · nginx 1.25; 8080/tcp · http · other-server');
  assert.equal(datasetPreviewText('Web Applications & APIs',{host_key:'scope-a|10.0.0.1'}),'Web Applications & APIs: 443/tcp · https · nginx 1.25');
  assert.equal(datasetPreviewText('Web Applications & APIs',{host_key:'scope-b|10.0.0.2'}),'Web Applications & APIs: 8080/tcp · http · other-server');
  const button=datasetFilterButton('Web Applications & APIs',{host_key:'scope-a|10.0.0.1'});
  assert.match(button,/aria-describedby="datasetPreview"/);
  assert.match(button,/data-dataset-preview=/);
  assert.match(button,/443\\/tcp/);
  assert.doesNotMatch(button,/8080\\/tcp/,"a host badge must not disclose another host's matching service");
  showDatasetPreview('Remote Access',datasetPreviewText('Remote Access',{host_key:'scope-a|10.0.0.1'}));
  assert.match(controls.get('datasetPreview').innerHTML,/22\\/tcp/);
  const marked=findingTransportMarkup({port:8443,protocol:'tcp',service:'https',nonstandard_port:true});
  assert.match(marked,/nonstandard-port-evidence/);
  assert.match(marked,/◆ 8443\\/tcp/);
  assert.equal(findingTransportMarkup({port:443,protocol:'tcp',nonstandard_port:false}),'<code>443/tcp</code>');
})()`);
