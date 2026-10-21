import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/arkime_ui.py", import.meta.url), "utf8");

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

assert.equal((source.match(/Observed activity upload/g) || []).length, 0, "the shell owns the page heading");
console.log("Arkime UI paging and request-ownership regressions passed");
