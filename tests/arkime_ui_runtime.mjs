import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/arkime_ui.py", import.meta.url), "utf8");
assert.ok(source.includes("top:100%"), "the value-action menu must touch its trigger so the pointer does not cross a dead gap");
assert.ok(source.includes("visibility 0s linear .22s"), "the value-action menu must remain available briefly while the pointer enters it");
assert.ok(source.includes("background:var(--nct-surface-muted,var(--panel))"), "the expression builder must inherit the active NCT theme");
assert.ok(source.includes("Plain-language field guide: source address = ip.src"), "the typed expression control must explain Arkime fields in plain language");
assert.ok(source.includes("ip.src == 10.50.15.10 &amp;&amp; port.dst == 443"), "the typed expression example must remain fully visible outside the input placeholder");

function handler(name) {
  const match = source.match(new RegExp(`^async function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/arkime_ui.py`);
  return match[0];
}

function syncHandler(name) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/arkime_ui.py`);
  return match[0];
}

function multilineHandler(name, asyncFunction = true) {
  const prefix = `${asyncFunction ? "async " : ""}function ${name}(`;
  const start = source.indexOf(prefix);
  assert.notEqual(start, -1, `Could not find ${name} in app/arkime_ui.py`);
  const tail = source.slice(start + prefix.length);
  const candidates = ["\nasync function ", "\nfunction "]
    .map(marker => tail.indexOf(marker))
    .filter(index => index >= 0);
  const end = candidates.length ? start + prefix.length + Math.min(...candidates) : source.length;
  return source.slice(start, end).trim();
}

await eval([
  "(async () => {",
  "let offset=0,total=0,revision='',historyRequest=0;const limit=25;",
  "const controls={filterScope:{value:'scope-a'},historyProgress:{hidden:true},historyStatus:{textContent:'',className:''},previous:{disabled:false},next:{disabled:false},rows:{innerHTML:''}};",
  "const $=id=>controls[id];",
  "const busy=(id,on)=>{controls[id].hidden=!on};",
  "const renders=[],pending=[];",
  "const render=data=>renders.push(data.marker);",
  "const api=url=>new Promise((resolve,reject)=>pending.push({url,resolve,reject}));",
  handler("load"),
  "const older=load(0,false);",
  "controls.filterScope.value='scope-b';",
  "const newer=load(0,false);",
  "pending[1].resolve({marker:'scope-b'});await newer;",
  "pending[0].resolve({marker:'scope-a'});await older;",
  "assert.deepEqual(renders,['scope-b'],'a delayed older scope response must not replace the selected scope');",
  "assert.equal(controls.historyStatus.textContent,'Showing saved receipts only. Opening this page does not re-read the JSON source.');",
  "assert.equal(controls.historyProgress.hidden,true);",
  "assert.ok(pending[0].url.includes('scope_id=scope-a'));assert.ok(pending[1].url.includes('scope_id=scope-b'));",
  "})()",
].join("\n"));

{
  const match = source.match(/\$\('historyRefresh'\)\.onclick=(\(\)=>loadLatestHistory\(\))/);
  assert.ok(match, "Refresh must wrap loadLatestHistory instead of forwarding the click event");
  let argumentCount = -1;
  const loadLatestHistory = (...args) => { argumentCount = args.length; };
  const click = eval(match[1]);
  click({type: "click"});
  assert.equal(argumentCount, 0, "the actual Refresh handler must not pass the browser event as a selection revision");
}

await eval([
  "(async () => {",
  "let communicationHistoryFilter='',communicationHistorySelectionRevision=0;",
  "const options=[{value:'run-a',dataset:{streamIdentity:'stream-a'}},{value:'run-b',dataset:{streamIdentity:'stream-b'}}],select={value:'run-a',options,get selectedOptions(){return options.filter(item=>item.value===this.value)}};",
  "const controls={historyStream:select,historyCalculationProgress:{hidden:true},historyCalculate:{disabled:false},historyCalculationStatus:{textContent:'',className:''},arkimeCommunicationHistory:{scrollIntoView(){}}};",
  "const $=id=>controls[id],busy=(id,on)=>{controls[id].hidden=!on},renders=[],pending=[];",
  "const renderHistory=data=>renders.push(data.marker),loadLatestHistory=async()=>{},location={hash:''},api=()=>new Promise((resolve,reject)=>pending.push({resolve,reject}));",
  multilineHandler("calculateHistory"),
  "const stale=calculateHistory();",
  "select.value='run-b';communicationHistorySelectionRevision+=1;busy('historyCalculationProgress',false);",
  "pending[0].resolve({marker:'stream-a'});await stale;",
  "assert.deepEqual(renders,[],'a calculation for a prior selection must not replace the newly selected stream');",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "const esc=value=>String(value??''),controls={coverageRecommendationResult:{innerHTML:'',textContent:''}},$=id=>controls[id];",
  syncHandler("recommendationSourceLinks"),
  syncHandler("renderCoverageRecommendation"),
  "renderCoverageRecommendation({status:'recommended',window:{start:'2030-01-01T05:55:00+00:00',end:'2030-01-01T09:00:00+00:00'},detail:'Forward only.',overlap_minutes:5,cutoff_basis:'operator_selected_utc_cutoff',generated_at:'2030-01-01T09:05:00+00:00',anchor_sources:[{import_id:'source-1',raw_url:'/api/source-1'}],later_noncomparable_sources:[{import_id:'partial-1'}],row_limit_warning:'Time cannot guarantee a complete result.'});",
  "const html=controls.coverageRecommendationResult.innerHTML;",
  "assert.ok(html.includes('Recommended next forward window'));",
  "assert.ok(html.includes('Later incomplete or noncomparable receipts exist'));",
  "assert.ok(html.includes('no Arkime contact'));",
  "assert.ok(html.includes('no traffic deduplication'));",
  "assert.ok(html.includes('download=\"arkime-source-source-1.json\"'));",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "let trafficFilters=[{field:'ip.src',operator:'==',value:'192.0.2.1'}],trafficMatchMode='all',trafficImportId='import-1',trafficRequest=0,trafficPathOffset=0;",
  "const input={attributes:{},setAttribute(name,value){this.attributes[name]=value}};",
  "const controls={trafficAnalysisProgress:{hidden:true},trafficAnalysisStatus:{textContent:'',className:''},trafficExpressionInput:input};",
  "const $=id=>controls[id],busy=(id,on)=>{controls[id].hidden=!on};",
  "const api=async()=>{throw new Error('unsupported field')},renderTrafficAnalysis=()=>assert.fail('invalid typed input must not replace prior results');",
  "const location={hash:''};",
  handler("loadTrafficAnalysis"),
  "await loadTrafficAnalysis('import-1',false,'bad.field == value');",
  "assert.equal(input.attributes['aria-invalid'],'true');",
  "assert.ok(controls.trafficAnalysisStatus.textContent.includes('Typed expression was not applied: unsupported field'));",
  "assert.ok(controls.trafficAnalysisStatus.textContent.includes('last applied clauses and results remain unchanged'));",
  "assert.equal(controls.trafficAnalysisStatus.className,'status bad');",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "let trafficFilters=[{field:'ip.src',operator:'==',value:'192.0.2.1'}],trafficMatchMode='any',trafficImportId='',trafficRequest=0,trafficPathOffset=0;",
  "const location={hash:'#arkimeCoverageWindows'},controls={trafficAnalysisProgress:{hidden:true},trafficAnalysisStatus:{textContent:'',className:''},arkimeTrafficAnalysis:{scrolled:false,scrollIntoView(){this.scrolled=true}}};",
  "const $=id=>controls[id],busy=(id,on)=>{controls[id].hidden=!on},rendered=[];",
  "const api=async url=>({url}),renderTrafficAnalysis=data=>rendered.push(data.url);",
  handler("loadTrafficAnalysis"),
  "await loadTrafficAnalysis('import-1',true);",
  "assert.equal(location.hash,'arkimeTrafficAnalysis','Analyze traffic must open the visible Traffic Patterns panel');",
  "assert.equal(trafficFilters.length,0);assert.equal(trafficMatchMode,'all');",
  "assert.equal(controls.arkimeTrafficAnalysis.scrolled,true);",
  "assert.ok(rendered[0].includes('filters=%5B%5D'));",
  "await loadTrafficAnalysis('import-1',false,'ip.src == 10.0.0.5 && port.dst == 53');",
  "assert.ok(rendered[1].includes('expression=ip.src+%3D%3D+10.0.0.5+%26%26+port.dst+%3D%3D+53'),'typed expressions must be sent as bounded expression input');",
  "assert.ok(!rendered[1].includes('filters='),'typed requests must not also send the structured filter shape');",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "function node(tag='div'){return {tag,className:'',dataset:{},children:[],textContent:'',disabled:false,hidden:false,append(...items){this.children.push(...items)},replaceChildren(...items){this.children=[...items]}}}",
  "const document={createElement(tag){const item=node(tag);if(tag==='table'){Object.defineProperty(item,'innerHTML',{set(){item.tBodies=[node('tbody')]}})}return item}};",
  "const esc=value=>String(value??''),requested=[];",
  "const pages=new Map([[100,{sessions:[{source_ordinal:100,session_id:'session-101',source_ip:'192.0.2.1',source_port:1,destination_ip:'198.51.100.1',destination_port:2,transport:'tcp',applications:[],first_packet:'2030-01-01T00:00:00Z',last_packet:'2030-01-01T00:00:01Z',packet_count:1,byte_count:2,source_node:'sensor',vlans:[]}],pagination:{offset:100,total:205,has_more:true}}],[200,{sessions:[{source_ordinal:204,session_id:'session-205',source_ip:'192.0.2.1',source_port:1,destination_ip:'198.51.100.1',destination_port:2,transport:'tcp',applications:[],first_packet:'2030-01-01T00:00:00Z',last_packet:'2030-01-01T00:00:01Z',packet_count:1,byte_count:2,source_node:'sensor',vlans:[]}],pagination:{offset:200,total:205,has_more:false}}]]);",
  "const api=async url=>{requested.push(url);const value=Number(new URL(url,'http://nct').searchParams.get('offset'));return pages.get(value)};",
  syncHandler("sessionTable"),
  handler("loadSessionPage"),
  "const host=node();const first={sessions:[{source_ordinal:0,session_id:'session-1',source_ip:'192.0.2.1',source_port:1,destination_ip:'198.51.100.1',destination_port:2,transport:'tcp',applications:[],first_packet:'2030-01-01T00:00:00Z',last_packet:'2030-01-01T00:00:01Z',packet_count:1,byte_count:2,source_node:'sensor',vlans:[]}],pagination:{offset:0,total:205,has_more:true}};",
  "sessionTable(first,host,'import-1');",
  "let next=host.children[1].children[1].children[1];await next.onclick();",
  "next=host.children[1].children[1].children[1];await next.onclick();",
  "assert.ok(requested[0].includes('offset=100'),'the first continuation must reach session 101');",
  "assert.ok(requested[1].includes('offset=200'),'the second continuation must reach session 205');",
  "assert.equal(host.children[1].children[0].textContent,'Sessions 201–201 of 205');",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "let coverageOffset=0,coverageTotal=0,coverageRevision='',coverageRequest=0;const limit=25;",
  "const controls={coverageFilterScope:{value:'scope-a'},coverageProgress:{hidden:true},coverageStatus:{textContent:'',className:''},coveragePrevious:{disabled:false},coverageNext:{disabled:false},coverageRows:{innerHTML:''}};",
  "const $=id=>controls[id];",
  "const busy=(id,on)=>{controls[id].hidden=!on};",
  "const renders=[],pending=[];",
  "const renderCoverage=data=>renders.push(data.marker);",
  "const api=url=>new Promise((resolve,reject)=>pending.push({url,resolve,reject}));",
  handler("loadCoverage"),
  "const older=loadCoverage(0,false);",
  "controls.coverageFilterScope.value='scope-b';",
  "const newer=loadCoverage(0,false);",
  "pending[1].resolve({marker:'scope-b'});await newer;",
  "pending[0].resolve({marker:'scope-a'});await older;",
  "assert.deepEqual(renders,['scope-b'],'a delayed older coverage response must not replace the selected scope');",
  "assert.equal(controls.coverageStatus.textContent,'Read-only retained evidence. Gaps never prove an Arkime sensor outage or an absence of traffic.');",
  "assert.equal(controls.coverageProgress.hidden,true);",
  "assert.ok(pending[0].url.includes('scope_id=scope-a'));assert.ok(pending[1].url.includes('scope_id=scope-b'));",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "let coverageRevision='coverage-r1',coverageRecommendationRequest=0;",
  "const controls={coverageRecommendationStream:{value:'stream-a'},coverageRecommendationOverlap:{value:'5'},coverageRecommendationCutoff:{value:''},coverageRecommendationDelay:{value:'60'},coverageFilterScope:{value:'scope-a'},coverageRecommendationProgress:{hidden:true},coverageRecommend:{disabled:false},coverageRecommendationResult:{textContent:'',innerHTML:''}};",
  "const $=id=>controls[id],busy=(id,on)=>{controls[id].hidden=!on},esc=value=>String(value??'');",
  "const renders=[],pending=[];",
  "const renderCoverageRecommendation=item=>{renders.push(item?.marker??item?.status??null);controls.coverageRecommendationResult.innerHTML=item?.marker??item?.detail??'Choose an exact retained API stream.'};",
  "const api=url=>new Promise((resolve,reject)=>pending.push({url,resolve,reject}));",
  syncHandler("coverageRecommendationSelection"),
  syncHandler("invalidateCoverageRecommendation"),
  handler("loadCoverageRecommendation"),
  "const older=loadCoverageRecommendation();",
  "assert.ok(pending[0].url.includes('scope_id=scope-a'),'a recommendation must keep the coverage table scope');",
  "assert.ok(pending[0].url.includes('revision=coverage-r1'));",
  "controls.coverageRecommendationStream.value='stream-b';invalidateCoverageRecommendation();",
  "const newer=loadCoverageRecommendation();",
  "pending[1].resolve({source_revision:'coverage-r2',recommendation:{marker:'stream-b'}});await newer;",
  "pending[0].resolve({source_revision:'coverage-r3',recommendation:{marker:'stream-a'}});await older;",
  "assert.deepEqual(renders,[null,'stream-b'],'a delayed response for the prior stream must not replace the newer recommendation');",
  "assert.equal(coverageRevision,'coverage-r1','recommendation responses must not change the coverage table revision');",
  "controls.coverageRecommendationStream.value='stream-c';invalidateCoverageRecommendation();const staleError=loadCoverageRecommendation();",
  "controls.coverageRecommendationStream.value='stream-d';invalidateCoverageRecommendation();const latest=loadCoverageRecommendation();",
  "pending[3].resolve({source_revision:'ignored',recommendation:{marker:'stream-d'}});await latest;",
  "pending[2].reject(new Error('stale failure'));await staleError;",
  "assert.equal(controls.coverageRecommendationResult.innerHTML,'stream-d','a stale error must not overwrite the latest recommendation');",
  "controls.coverageRecommendationOverlap.value='7';invalidateCoverageRecommendation();",
  "assert.equal(controls.coverageRecommendationResult.innerHTML,'Choose an exact retained API stream.','changing a planning input must clear the prior result');",
  "assert.equal(controls.coverageRecommendationProgress.hidden,true);",
  "})()",
].join("\n"));

assert.ok(source.includes("$('coverageRecommendationStream').onchange=invalidateCoverageRecommendation"), "changing the exact stream must invalidate its recommendation");
assert.ok(source.includes("$('coverageRecommendationOverlap').oninput=invalidateCoverageRecommendation"), "changing overlap must invalidate its recommendation");
assert.ok(source.includes("$('coverageRecommendationCutoff').oninput=invalidateCoverageRecommendation"), "changing cutoff must invalidate its recommendation");
assert.ok(source.includes("$('coverageRecommendationDelay').oninput=invalidateCoverageRecommendation"), "changing delay must invalidate its recommendation");
assert.ok(source.includes("$('coverageFilterScope').onchange=()=>{invalidateCoverageRecommendation();loadCoverage(0,false)}"), "changing scope must invalidate the recommendation before reloading coverage");

await eval([
  "(async () => {",
  "let coverageOffset=0,coverageTotal=0,coverageRevision='';",
  "function node(tag='div'){return {tag,children:[],textContent:'',disabled:false,append(...items){this.children.push(...items)},replaceChildren(...items){this.children=[...items]}}}",
  "const controls={coverageRows:node('tbody'),coveragePrevious:{disabled:false},coverageNext:{disabled:false},coveragePage:{textContent:''}};",
  "const $=id=>controls[id],esc=value=>String(value??''),badge=value=>`<span>${value}</span>`,coverageContinuity=()=>'<strong>Not comparable</strong>',renderRecommendationStreams=()=>{},loadTrafficAnalysis=()=>{};",
  "const document={createElement(tag){const item=node(tag);if(tag==='tr'){item.cells=Array.from({length:7},()=>node('td'));Object.defineProperty(item,'innerHTML',{set(value){item.rendered=value},get(){return item.rendered||''}})}return item}};",
  syncHandler("renderCoverage"),
  "renderCoverage({source_revision:'r1',pagination:{total:1,offset:0,has_more:false},exact_api_streams:[],items:[{import_id:'summary-1',source_kind:'summary_csv',source_method:'manual_summary',connector_id:null,connector_contract:null,parser_version:'summary:1',scope:{label:'Range',version:1},operator_sensor:'declared sensor',query_start:'2030-01-01T00:00:00Z',query_end:'2030-01-01T01:00:00Z',bounding_mode:'both',query_expression:'',stream_basis:'operator declaration',export_completeness:'complete',operator_export_assessment:'complete',capture_coverage:'unknown',returned_count:2,raw_url:'/api/summary/raw'}]});",
  "const html=controls.coverageRows.children[0].innerHTML;",
  "assert.ok(html.includes('Recorded export declaration complete'),'summary completeness must be labeled as a recorded declaration');",
  "assert.ok(!html.includes('Calculated export complete'),'summary completeness must not be presented as independently calculated');",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "const esc=value=>String(value??'');",
  syncHandler("trafficPredicate"),
  syncHandler("trafficValueActions"),
  syncHandler("trafficMetricTable"),
  syncHandler("trafficFilterValue"),
  syncHandler("trafficEndpointLink"),
  syncHandler("trafficActiveContext"),
  syncHandler("trafficUtc"),
  syncHandler("trafficTimeReceipts"),
  syncHandler("trafficApplications"),
  syncHandler("trafficPathTable"),
  "const exact='18000000000000000000';",
  "const html=trafficMetricTable('Top source addresses',[{label:'10.0.0.5',filter_clauses:[{field:'ip.src',operator:'==',value:'10.0.0.5'}],retained_session_rows:2,known_packet_total:exact,packet_rows_missing:0,known_byte_total:'0',byte_rows_missing:1,receipt_ordinals:[0,1],receipt_references_truncated:false}],'empty');",
  "assert.ok(html.includes(exact),'traffic analytics must render exact decimal totals without Number conversion');",
  "assert.ok(html.includes('1 row Unknown'),'missing values must remain visibly Unknown');",
  "assert.ok(html.includes('class=\"metric-value\"'),'value actions must live in the compact hover or focus control');",
  "assert.ok(html.includes('Click to filter for this value'),'the main value must explain its one-click include behavior');",
  "const grouped=trafficPredicate({filter_clauses:[{field:'ipProtocol',operator:'==',value:'tcp'},{field:'port.dst',operator:'==',value:53}]},true);",
  "assert.equal(grouped.negated,true);assert.equal(grouped.match_mode,'all');assert.equal(grouped.clauses.length,2);",
  "const pathHtml=trafficPathTable({correlated_paths:[{source_ip:'10.0.0.5',destination_ip:'8.8.8.8',destination_port:53,transport:'udp',first_packet:'2030-01-01T00:01:00Z',last_packet:'2030-01-01T00:02:30Z',first_packet_receipt_ordinals:Array.from({length:100},(_,i)=>i),first_packet_receipt_count:101,first_packet_receipt_references_truncated:true,last_packet_receipt_ordinals:[1],last_packet_receipt_count:1,last_packet_receipt_references_truncated:false,detected_applications:[{label:'dns',receipt_ordinals:[0,1],receipt_count:2,receipt_references_truncated:false}],retained_session_rows:2,known_packet_total:'12',packet_rows_missing:1,known_byte_total:'400',byte_rows_missing:0,receipt_ordinals:[0,1],receipt_references_truncated:false,filter_clauses:[{field:'ip.src',operator:'==',value:'10.0.0.5'},{field:'ip.dst',operator:'==',value:'8.8.8.8'},{field:'ipProtocol',operator:'==',value:'udp'},{field:'port.dst',operator:'==',value:53}],active_context:{label:'Observed / Scan Mismatch',passive_observation:{status:'passively_observed',label:'Passively observed',reason:'Exact retained Arkime source reported this path.'},active_validation:{status:'not_actively_validated',label:'Not actively validated',reason:'No defensible exact service assessment.'},reported_state:'closed',reason:'The reports differ.',selection_revision:'1234567890abcdef',active_sources:[{source_url:'/api/imports/source/raw'}],source_endpoint:{detail_url:'/api/foundation-evidence/source',workspace_url:'/analysis#networkChangesPanel'},destination_endpoint:{detail_url:'/api/foundation-evidence/destination',workspace_url:'/analysis#networkChangesPanel'},evidence_windows:{passive:{start:'2030-01-01',end:'2030-01-02'},active:{start:{utc:'2029-12-01'},end:{utc:'2029-12-02'}},note:'These are reports from different times.'}}}],correlated_path_count:30,correlated_paths_truncated:true,path_pagination:{offset:0,limit:25,total:30,has_more:true},correlation_note:'One-source correlation.',active_context_note:'Same-scope context.'});",
  "assert.ok(pathHtml.includes('Communication paths in this retained source'));assert.ok(pathHtml.includes('10.0.0.5'));assert.ok(pathHtml.includes('8.8.8.8'));assert.ok(pathHtml.includes('53 / udp'));assert.ok(pathHtml.includes('2030-01-01T00:01:00Z'));assert.ok(pathHtml.includes('2030-01-01T00:02:30Z'));assert.ok(pathHtml.includes('dns'));assert.ok(pathHtml.includes('Application evidence'));assert.ok(pathHtml.includes('first 100 of 101 shown'));assert.ok(pathHtml.includes('1 row Unknown'));assert.ok(pathHtml.includes('Filter exact path'));assert.ok(pathHtml.includes('Passively observed'));assert.ok(pathHtml.includes('Not actively validated'));assert.ok(pathHtml.includes('Observed / Scan Mismatch'));assert.ok(pathHtml.includes('Nmap source 1'));assert.ok(pathHtml.includes('These are reports from different times.'));assert.ok(pathHtml.includes('Processed Nmap endpoint'));assert.ok(pathHtml.includes('/api/foundation-evidence/'));assert.ok(pathHtml.includes('Analyze workspace'));assert.ok(pathHtml.includes('Arkime window (UTC)'));assert.ok(pathHtml.includes('Nmap window (UTC)'));assert.ok(pathHtml.includes('Start:'));assert.ok(pathHtml.includes('End:'));assert.ok(pathHtml.includes('Paths 1–1 of 30'));assert.ok(pathHtml.includes('Next paths'));assert.equal((pathHtml.match(/class=\"evidence-window\"/g)||[]).length,2);",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "let summaryOffset=0,summaryTotal=0,summaryRevision='',summaryHistoryRequest=0;const limit=25;",
  "const controls={summaryFilterScope:{value:'scope-a'},summaryHistoryProgress:{hidden:true},summaryHistoryStatus:{textContent:'',className:''},summaryPrevious:{disabled:false},summaryNext:{disabled:false},summaryRows:{innerHTML:''}};",
  "const $=id=>controls[id];",
  "const busy=(id,on)=>{controls[id].hidden=!on};",
  "const renders=[],pending=[];",
  "const renderSummaries=data=>renders.push(data.marker);",
  "const api=url=>new Promise((resolve,reject)=>pending.push({url,resolve,reject}));",
  handler("loadSummaries"),
  "const older=loadSummaries(0,false);",
  "controls.summaryFilterScope.value='scope-b';",
  "const newer=loadSummaries(0,false);",
  "pending[1].resolve({marker:'scope-b'});await newer;",
  "pending[0].resolve({marker:'scope-a'});await older;",
  "assert.deepEqual(renders,['scope-b'],'a delayed older summary response must not replace the selected scope');",
  "assert.equal(controls.summaryHistoryStatus.textContent,'Showing saved receipts only. Counts remain separate by source file and grouping row.');",
  "assert.equal(controls.summaryHistoryProgress.hidden,true);",
  "assert.ok(pending[0].url.includes('scope_id=scope-a'));assert.ok(pending[1].url.includes('scope_id=scope-b'));",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "function node(tag='div'){return {tag,className:'',dataset:{},children:[],textContent:'',disabled:false,hidden:false,append(...items){this.children.push(...items)},replaceChildren(...items){this.children=[...items]}}}",
  "const document={createElement(tag){const item=node(tag);if(tag==='table'){Object.defineProperty(item,'innerHTML',{set(){item.tBodies=[node('tbody')]}})}return item}};",
  "const esc=value=>String(value??''),requested=[];",
  "const exact='9007199254740993',receipt={source_line:102,source_ordinal:100,source_ip:null,destination_ip:'198.51.100.1',destination_port:443,transport:'tcp',detected_protocol:'tls',vlan:10,session_count:exact,packet_count:exact,byte_count:exact};",
  "const pages=new Map([[100,{receipts:[receipt],pagination:{offset:100,total:205,has_more:true}}],[200,{receipts:[{...receipt,source_line:206,source_ordinal:204}],pagination:{offset:200,total:205,has_more:false}}]]);",
  "const api=async url=>{requested.push(url);const value=Number(new URL(url,'http://nct').searchParams.get('offset'));return pages.get(value)};",
  syncHandler("summaryReceiptTable"),
  handler("loadSummaryReceiptPage"),
  "const host=node();const first={receipts:[{...receipt,source_line:2,source_ordinal:0}],pagination:{offset:0,total:205,has_more:true}};",
  "summaryReceiptTable(first,host,'summary-1');",
  "assert.ok(host.children[0].children[0].tBodies[0].children[0].innerHTML.includes(exact),'the browser must render the exact decimal count without Number rounding');",
  "let next=host.children[1].children[1].children[1];await next.onclick();",
  "next=host.children[1].children[1].children[1];await next.onclick();",
  "assert.ok(requested[0].includes('offset=100'));assert.ok(requested[1].includes('offset=200'));",
  "assert.equal(host.children[1].children[0].textContent,'Grouped rows 201–201 of 205');",
  "})()",
].join("\n"));

assert.equal((source.match(/Observed activity upload/g) || []).length, 0, "the shell owns the page heading");

await eval([
  "(async () => {",
  "let communicationHistoryResultId='',communicationHistoryRequest=0,communicationHistoryFilter='',communicationHistorySelectionRevision=1;",
  "const options=[{value:'run-a',dataset:{streamIdentity:'stream-a'}},{value:'run-b',dataset:{streamIdentity:'stream-b'}}],select={value:'run-a',get selectedOptions(){return options.filter(item=>item.value===this.value)}};",
  "const controls={historyStream:select,historyCalculationProgress:{hidden:true},historyCalculationStatus:{textContent:'',className:''},historyResult:{innerHTML:''},historyPathFilterForm:{hidden:true}};",
  "const $=id=>controls[id],busy=(id,on)=>{controls[id].hidden=!on},renders=[],pending=[];",
  "const renderHistory=data=>renders.push(data.marker),api=url=>new Promise((resolve,reject)=>pending.push({url,resolve,reject}));",
  multilineHandler("loadHistory"),
  multilineHandler("loadLatestHistory"),
  "const older=loadLatestHistory(1);",
  "select.value='run-b';communicationHistorySelectionRevision=2;const newer=loadLatestHistory(2);",
  "pending[1].resolve({items:[{result_id:'result-b'}]});await new Promise(resolve=>setTimeout(resolve,0));",
  "assert.ok(pending[2].url.includes('/result-b?'),'the selected stream must load its own saved generation');",
  "pending[2].resolve({marker:'stream-b',stream_identity:'stream-b'});await newer;",
  "pending[0].resolve({items:[{result_id:'result-a'}]});await older;",
  "assert.deepEqual(renders,['stream-b'],'a delayed prior stream list must not start or render an older detail request');",
  "assert.equal(pending.length,3,'the stale prior stream must stop before requesting detail');",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "let historyStreamOffset=0;",
  "const select={value:'',options:[],replaceChildren(...items){this.options=[...items];for(const item of this.options)item.parent=this},append(item){item.parent=this;this.options.push(item)},get lastElementChild(){return this.options.at(-1)}};",
  "function Option(text,value){return {textContent:text,value,dataset:{},disabled:false,parent:null,remove(){const index=this.parent.options.indexOf(this);if(index>=0)this.parent.options.splice(index,1)}}}",
  "const controls={historyStream:select,historyCalculate:{disabled:false},historyCalculationStatus:{textContent:'',className:''}},$=id=>controls[id];",
  "const requested=[],pages=[{items:[{profile_name:'Newest',operator_sensor:'sensor-a',scope_label:'Range',scope_version:1,query_expression:'',pull_count:100,anchor_run_id:'run-100',stream_identity:'stream-100',history_ready:true}],pagination:{has_more:true}},{items:[{profile_name:'Oldest',operator_sensor:'sensor-b',scope_label:'Range',scope_version:1,query_expression:'',pull_count:1,anchor_run_id:'run-101',stream_identity:'stream-101',history_ready:true}],pagination:{has_more:false}}];",
  "const api=async url=>{requested.push(url);return pages.shift()};",
  multilineHandler("loadHistoryStreams"),
  "await loadHistoryStreams(false);",
  "assert.equal(select.options.at(-1).value,'__load_more__','the first page must offer usable continuation');",
  "await loadHistoryStreams(true);",
  "assert.ok(requested[1].includes('offset=1'),'continuation must request the next catalog offset');",
  "assert.ok(select.options.some(item=>item.value==='run-101'),'the next stream page must become selectable');",
  "assert.ok(!select.options.some(item=>item.value==='__load_more__'),'the continuation option must disappear at the end');",
  "})()",
].join("\n"));

console.log("Arkime UI paging and request-ownership regressions passed");
