import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/reachability_ui.py", import.meta.url), "utf8");

function asyncHandler(name) {
  const match = source.match(new RegExp(`^async function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/reachability_ui.py`);
  return match[0].replaceAll("{{", "{").replaceAll("}}", "}");
}

function handler(name) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/reachability_ui.py`);
  return match[0].replaceAll("{{", "{").replaceAll("}}", "}");
}

function node() {
  const values = new Set();
  return {
    textContent: "", innerHTML: "", disabled: false, className: "", dataset: {},
    classList: {
      add: value => values.add(value),
      remove: value => values.delete(value),
      toggle: (value, force) => force ? values.add(value) : values.delete(value),
      contains: value => values.has(value),
    },
    appendChild(child) { child.parent = this; },
    setAttribute() {},
  };
}

await eval(`(async () => {
  let exposureReport={target:{name:'Old report'}},activeReportNetworkId='',reportRequestRevision=0,reportGenerationRevision=0;
  const controls=new Map();
  for(const id of ['exposureReports','reportWorkspace','reportTargetTitle','reportTargetMeta','reportFreshness','reportSummary','reportFilters','reportFilterCount','exportReport','reportStatus','reportLoadingText','reportLoading','reportCatalogStatus','regenerateReport'])controls.set(id,node());
  const $=id=>{assert.ok(controls.has(id),'unknown DOM id: '+id);return controls.get(id)};
  $('exposureReports').innerHTML='STALE REPORT CONTENT';
  const requests=[];
  const fetch=url=>new Promise(resolve=>requests.push({url,resolve}));
  const responseData=async response=>response.data;
  const encodeURIComponent=value=>String(value);
  const esc=value=>String(value??'');
  const formatReportTime=value=>String(value||'');
  const CSS={escape:value=>String(value)};
  const rendered=[];
  const renderExposureReport=data=>rendered.push(data.target.name);
  const catalogLoads=[];
  const loadReportCatalog=id=>{catalogLoads.push(id)};
  const busy=[];
  const setReportBusy=(active,message)=>busy.push([active,message]);
  const workspace=$('reportWorkspace');
  const makeRow=name=>({
    querySelector(selector){
      if(selector==='.exposure-network-body')return {appendChild(child){child.parent=name}};
      if(selector==='summary strong')return {textContent:name};
      return null;
    }
  });
  const rowA=makeRow('Network A'),rowB=makeRow('Network B');
  ${handler("clearExposureWorkspace")}
  ${asyncHandler("loadExposureReport")}
  ${asyncHandler("generateExposureReport")}
  const older=loadExposureReport('A',rowA);
  assert.equal($('exposureReports').innerHTML,'','old report details must clear before the request finishes');
  const newer=loadExposureReport('B',rowB);
  assert.match($('reportStatus').textContent,/Network B/);
  requests[1].resolve({ok:true,data:{report:{target:{name:'Network B'}},summary:{}}});
  await newer;
  requests[0].resolve({ok:true,data:{report:{target:{name:'Network A'}},summary:{}}});
  await older;
  assert.deepEqual(rendered,['Network B'],'an older response must not replace the active network report');
  assert.equal(activeReportNetworkId,'B');
  assert.equal(busy.filter(item=>item[0]===false).length,1,'only the active request may clear the busy state');

  const generationButton=node();
  const generatedA=generateExposureReport('A',generationButton);
  const openedBAfterGeneration=loadExposureReport('B',rowB);
  requests[3].resolve({ok:true,data:{report:{target:{name:'Network B current'}},summary:{}}});
  await openedBAfterGeneration;
  requests[2].resolve({ok:true,data:{report:{target:{name:'Network A generated'}},summary:{}}});
  await generatedA;
  assert.deepEqual(catalogLoads,[],'an obsolete generation must not reopen its network catalog row');
  assert.equal(activeReportNetworkId,'B');
})()`);

await eval(`(async () => {
  let exposureReport=null,activeReportNetworkId='',reportCatalogLoaded=false,reportRequestRevision=0,reportGenerationRevision=0;
  const controls=new Map();
  for(const id of ['reportWorkspace','exposureReportPanel','reportLoadingText','reportLoading','reportCatalogStatus','reportCatalog','regenerateReport','reportTargetTitle','reportTargetMeta','reportFreshness','reportSummary','reportFilters','reportFilterCount','exposureReports','exportReport','reportStatus'])controls.set(id,node());
  const $=id=>{assert.ok(controls.has(id),'unknown DOM id: '+id);return controls.get(id)};
  const requests=[];
  const fetch=url=>new Promise(resolve=>requests.push({url,resolve}));
  const responseData=async response=>response.data;
  const encodeURIComponent=value=>String(value);
  const rendered=[];
  const renderExposureReport=data=>rendered.push(data.target.name);
  const setReportBusy=()=>{};
  const rowB={querySelector(selector){
    if(selector==='.exposure-network-body')return {appendChild(){}};
    if(selector==='summary strong')return {textContent:'Network B'};
    return null;
  }};
  ${handler("clearExposureWorkspace")}
  ${asyncHandler("loadExposureReport")}
  ${asyncHandler("loadReportCatalog")}
  const olderCatalog=loadReportCatalog('A');
  const currentReport=loadExposureReport('B',rowB);
  requests[1].resolve({ok:true,data:{report:{target:{name:'Network B'}},summary:{}}});
  await currentReport;
  $('reportCatalog').innerHTML='CURRENT CATALOG';
  requests[0].resolve({ok:true,data:{reports:[{name:'Old A'}]}});
  await olderCatalog;
  assert.equal(controls.get('reportCatalog').innerHTML,'CURRENT CATALOG','an obsolete catalog response must not replace current content');
  assert.deepEqual(rendered,['Network B']);
  assert.equal(activeReportNetworkId,'B');
})()`);

await eval(`(async () => {
  let exposureReport=null,activeReportNetworkId='',reportCatalogLoaded=false,reportRequestRevision=0,reportGenerationRevision=0;
  const controls=new Map();
  for(const id of ['reportWorkspace','exposureReportPanel','reportLoadingText','reportLoading','reportCatalogStatus','reportCatalog','regenerateReport','reportTargetTitle','reportTargetMeta','reportFreshness','reportSummary','reportFilters','reportFilterCount','exposureReports','exportReport','reportStatus'])controls.set(id,node());
  const $=id=>{assert.ok(controls.has(id),'unknown DOM id: '+id);return controls.get(id)};
  $('reportWorkspace').classList.add('hidden');
  const requests=[];
  const fetch=(url,options={})=>new Promise(resolve=>requests.push({url,options,resolve}));
  const responseData=async response=>response.data;
  const encodeURIComponent=value=>String(value);
  const esc=value=>String(value??'');
  const formatReportTime=value=>String(value||'');
  const CSS={escape:value=>String(value)};
  const rendered=[];
  const renderExposureReport=data=>rendered.push(data.target.name);
  const bindReportCatalog=()=>{};
  const rowA={open:false,querySelector(selector){
    if(selector==='.exposure-network-body')return {appendChild(child){child.parent='A'}};
    if(selector==='summary strong')return {textContent:'Network A'};
    return null;
  }};
  const document={querySelector(selector){return selector.includes('A')?rowA:null}};
  ${handler("clearExposureWorkspace")}
  ${handler("reportCatalogRow")}
  ${handler("setReportBusy")}
  ${asyncHandler("loadReportCatalog")}
  ${asyncHandler("loadExposureReport")}
  ${asyncHandler("generateExposureReport")}

  const button=$('regenerateReport');
  const firstGeneration=generateExposureReport('A',button);
  assert.equal(button.disabled,true);
  assert.equal(requests[0].options.method,'POST');
  requests[0].resolve({ok:true,data:{report:{target:{name:'Generated A'}}}});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(requests.length,2,'successful generation must refresh the catalog');
  requests[1].resolve({ok:true,data:{reports:[{has_report:true,freshness:'current',saved_network_id:'A',name:'Network A',cidr:'10.0.0.0/24'}]}});
  await firstGeneration;
  assert.equal(button.disabled,false,'catalog refresh must release the generation button');
  assert.equal(rowA.open,true,'generated network is reopened in the refreshed catalog');

  const opened=loadExposureReport('A',rowA);
  requests[2].resolve({ok:true,data:{report:{target:{name:'Network A current'}},summary:{}}});
  await opened;
  assert.deepEqual(rendered,['Network A current']);

  const secondGeneration=generateExposureReport('A',button);
  assert.equal(button.disabled,true,'the same report can be regenerated again');
  requests[3].resolve({ok:true,data:{report:{target:{name:'Generated A twice'}}}});
  await new Promise(resolve=>setImmediate(resolve));
  requests[4].resolve({ok:true,data:{reports:[{has_report:true,freshness:'current',saved_network_id:'A',name:'Network A',cidr:'10.0.0.0/24'}]}});
  await secondGeneration;
  assert.equal(button.disabled,false,'second regeneration must also release the button');
})()`);

await eval(`(() => {
  const esc=value=>String(value??'');
  const formatReportTime=value=>String(value||'');
  ${handler("reportCatalogRow")}
  const retained=reportCatalogRow({
    has_report:true,freshness:'out_of_date',saved_network_id:'n1',name:'Users',
    cidr:'10.0.0.0/24',service_count:4,generated_at:'then',changes:{added_count:1,removed_count:0}
  });
  assert.equal((retained.match(/Regenerate report/g)||[]).length,1);
  assert.equal((retained.match(/generate-network-report/g)||[]).length,0,'retained rows use the one workspace regenerate action');
  const missing=reportCatalogRow({has_report:false,saved_network_id:'n2',name:'Servers',cidr:'10.1.0.0/24'});
  assert.equal((missing.match(/generate-network-report/g)||[]).length,1,'a network with no report still offers Generate report');
})()`);

console.log("Exposure Report UI runtime regressions passed");

await eval(`(() => {
  const esc=value=>String(value??'');
  const outcomeClass=value=>String(value||'unknown');
  const reportPath=()=>'<div class="path"></div>';
  const reportEvidence=()=>'<div class="evidence"></div>';
  const candidateMarkup=()=>'<p class="meta">saved candidates</p>';
  ${handler("reportResult")}
  ${handler("reportDestinationGroups")}
  const services=new Map([
    ['svc-443',{service_key:'svc-443',ip:'10.0.0.10',hostname:'web',port:443,protocol:'tcp',service:'https',searchsploit:{candidate_count:2}}],
    ['svc-53-udp',{service_key:'svc-53-udp',ip:'10.0.0.10',hostname:'web',port:53,protocol:'udp',service:'domain'}],
    ['svc-53-tcp',{service_key:'svc-53-tcp',ip:'10.0.0.11',hostname:'dns',port:53,protocol:'tcp',service:'domain'}]
  ]);
  const results=[
    {service_key:'svc-443',outcome:'Allowed',retained_objects:{}},
    {service_key:'svc-53-udp',outcome:'Routed',retained_objects:{}},
    {service_key:'svc-53-tcp',outcome:'Blocked',retained_objects:{}}
  ];
  const html=reportDestinationGroups(results,services,'source-a');
  assert.equal((html.match(/class="report-destination"/g)||[]).length,2,'results must group by exact destination address');
  assert.equal((html.match(/class="report-result"/g)||[]).length,3,'every evaluated path must remain present');
  assert.ok(html.indexOf('10.0.0.10')<html.indexOf('10.0.0.11'));
  assert.ok(html.indexOf('53\/udp')<html.indexOf('443\/tcp'),'ports must sort numerically within a destination');
  assert.match(html,/53\\/tcp/,'TCP and UDP identities must remain distinct');
  assert.match(html,/data-reach-source="source-a"/);
  assert.match(html,/data-reach-service="svc-443"/);
})()`);

await eval(`(() => {
  const hiddenState=()=>{const values=new Set();return{toggle:(name,force)=>force?values.add(name):values.delete(name),contains:name=>values.has(name)}};
  const row=(outcome,candidates)=>({dataset:{outcome,candidates},classList:hiddenState()});
  const allowedCandidate=row('Allowed','yes'),blocked=row('Blocked','no'),otherSource=row('Allowed','no');
  const destination=rows=>({classList:hiddenState(),querySelectorAll:selector=>selector==='.report-result'?rows:[]});
  const destinationA=destination([allowedCandidate,blocked]),destinationB=destination([otherSource]);
  const source=(id,destinations)=>{const count={textContent:''};return{dataset:{source:id},classList:hiddenState(),count,querySelectorAll:selector=>selector==='.report-destination'?destinations:[],querySelector:selector=>selector==='.visible-count'?count:null}};
  const sourceA=source('source-a',[destinationA]),sourceB=source('source-b',[destinationB]);
  const controls=new Map([
    ['reportSource',{value:'source-a'}],['reportOutcome',{value:'Allowed'}],['reportCandidates',{checked:true}],['reportFilterCount',{textContent:''}]
  ]);
  const $=id=>controls.get(id);
  const document={querySelectorAll:selector=>selector==='.report-source'?[sourceA,sourceB]:[]};
  const exposureReport={evaluated_path_count:3};
  ${handler("applyReportFilters")}
  applyReportFilters();
  assert.equal(allowedCandidate.classList.contains('hidden'),false);
  assert.equal(blocked.classList.contains('hidden'),true);
  assert.equal(otherSource.classList.contains('hidden'),true);
  assert.equal(destinationA.classList.contains('hidden'),false);
  assert.equal(destinationB.classList.contains('hidden'),true);
  assert.equal(sourceA.classList.contains('hidden'),false);
  assert.equal(sourceB.classList.contains('hidden'),true);
  assert.equal(sourceA.count.textContent,'1 shown');
  assert.equal(controls.get('reportFilterCount').textContent,'1 of 3 evaluated paths shown.');
})()`);
