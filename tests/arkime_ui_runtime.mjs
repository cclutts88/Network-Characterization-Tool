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

await eval([
  "(async () => {",
  "let trafficFilters=[{field:'ip.src',operator:'==',value:'192.0.2.1'}],trafficMatchMode='all',trafficImportId='import-1',trafficRequest=0;",
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
  "let trafficFilters=[{field:'ip.src',operator:'==',value:'192.0.2.1'}],trafficMatchMode='any',trafficImportId='',trafficRequest=0;",
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
  "const esc=value=>String(value??'');",
  syncHandler("trafficPredicate"),
  syncHandler("trafficValueActions"),
  syncHandler("trafficMetricTable"),
  syncHandler("trafficFilterValue"),
  syncHandler("trafficEndpointLink"),
  syncHandler("trafficActiveContext"),
  syncHandler("trafficPathTable"),
  "const exact='18000000000000000000';",
  "const html=trafficMetricTable('Top source addresses',[{label:'10.0.0.5',filter_clauses:[{field:'ip.src',operator:'==',value:'10.0.0.5'}],retained_session_rows:2,known_packet_total:exact,packet_rows_missing:0,known_byte_total:'0',byte_rows_missing:1,receipt_ordinals:[0,1],receipt_references_truncated:false}],'empty');",
  "assert.ok(html.includes(exact),'traffic analytics must render exact decimal totals without Number conversion');",
  "assert.ok(html.includes('1 row Unknown'),'missing values must remain visibly Unknown');",
  "assert.ok(html.includes('class=\"metric-value\"'),'value actions must live in the compact hover or focus control');",
  "assert.ok(html.includes('Click to filter for this value'),'the main value must explain its one-click include behavior');",
  "const grouped=trafficPredicate({filter_clauses:[{field:'ipProtocol',operator:'==',value:'tcp'},{field:'port.dst',operator:'==',value:53}]},true);",
  "assert.equal(grouped.negated,true);assert.equal(grouped.match_mode,'all');assert.equal(grouped.clauses.length,2);",
  "const pathHtml=trafficPathTable({correlated_paths:[{source_ip:'10.0.0.5',destination_ip:'8.8.8.8',destination_port:53,transport:'udp',retained_session_rows:2,known_packet_total:'12',packet_rows_missing:1,known_byte_total:'400',byte_rows_missing:0,receipt_ordinals:[0,1],receipt_references_truncated:false,filter_clauses:[{field:'ip.src',operator:'==',value:'10.0.0.5'},{field:'ip.dst',operator:'==',value:'8.8.8.8'},{field:'ipProtocol',operator:'==',value:'udp'},{field:'port.dst',operator:'==',value:53}],active_context:{label:'Observed / Scan Mismatch',reported_state:'closed',reason:'The reports differ.',selection_revision:'1234567890abcdef',active_sources:[{source_url:'/api/imports/source/raw'}],source_endpoint:{detail_url:'/api/foundation-evidence/source',workspace_url:'/analysis#networkChangesPanel'},destination_endpoint:{detail_url:'/api/foundation-evidence/destination',workspace_url:'/analysis#networkChangesPanel'},evidence_windows:{passive:{start:'2030-01-01',end:'2030-01-02'},active:{start:{utc:'2029-12-01'},end:{utc:'2029-12-02'}},note:'These are reports from different times.'}}}],correlated_path_count:1,correlated_paths_truncated:false,correlation_note:'One-source correlation.',active_context_note:'Same-scope context.'});",
  "assert.ok(pathHtml.includes('Correlated communication paths'));assert.ok(pathHtml.includes('10.0.0.5'));assert.ok(pathHtml.includes('8.8.8.8'));assert.ok(pathHtml.includes('53 / udp'));assert.ok(pathHtml.includes('1 row Unknown'));assert.ok(pathHtml.includes('Filter exact path'));assert.ok(pathHtml.includes('Observed / Scan Mismatch'));assert.ok(pathHtml.includes('Nmap source 1'));assert.ok(pathHtml.includes('These are reports from different times.'));assert.ok(pathHtml.includes('Processed Nmap endpoint'));assert.ok(pathHtml.includes('/api/foundation-evidence/'));assert.ok(pathHtml.includes('Analyze workspace'));assert.ok(pathHtml.includes('Arkime window (UTC)'));assert.ok(pathHtml.includes('Nmap window (UTC)'));assert.ok(pathHtml.includes('Start:'));assert.ok(pathHtml.includes('End:'));assert.equal((pathHtml.match(/class=\"evidence-window\"/g)||[]).length,2);",
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
console.log("Arkime UI paging and request-ownership regressions passed");
