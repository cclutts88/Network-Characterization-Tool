import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/device_ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/device_ui.py`);
  return match[0];
}

await eval(`(async () => {
  const newest=Array.from({length:25},(_,index)=>({run_id:'new-'+index,summary_processing_state:'completed'}));
  const olderRunning={run_id:'older-active',summary_processing_state:'running'};
  const olderCompleted={...olderRunning,summary_processing_state:'completed'};
  let historyRecords=[...newest],historyOffset=25,historyBusy=false,historyPipelineTimer=null;
  let scheduledCallback=null,rendered=[],requested=[];
  const controls=new Map();
  const $=id=>{if(!controls.has(id))controls.set(id,{disabled:false,textContent:'',classList:{toggle:()=>{}}});return controls.get(id)};
  const clearTimeout=()=>{};
  const clearInterval=()=>{};
  const setInterval=()=>1;
  const setTimeout=callback=>{scheduledCallback=callback;return 1};
  const renderHistory=records=>{rendered=records.map(item=>item.run_id)};
  const updateWanCollectionOptions=()=>{};
  const historyJSON=async url=>{
    requested.push(url);
    if(url==='/api/device-configs?limit=25&offset=25')return [olderRunning];
    if(url==='/api/device-configs?limit=26&offset=0')return [...newest,olderCompleted];
    throw new Error('Unexpected URL '+url);
  };
  ${handler("pipelineActive")}
  ${handler("refreshLoadedHistory")}
  ${handler("loadHistory")}
  await loadHistory(false);
  assert.equal(historyRecords.length,26);
  assert.ok(rendered.includes('older-active'));
  assert.ok(scheduledCallback);
  const poll=scheduledCallback;scheduledCallback=null;await poll();
  assert.equal(historyRecords.length,26);
  assert.ok(rendered.includes('older-active'));
  assert.equal(historyRecords.find(item=>item.run_id==='older-active').summary_processing_state,'completed');
  assert.deepEqual(requested,[
    '/api/device-configs?limit=25&offset=25',
    '/api/device-configs?limit=26&offset=0'
  ]);
  assert.equal(scheduledCallback,null);
})()`);

assert.ok(source.includes("openDevices=new Set"));
assert.ok(source.includes("openRuns=new Set"));
assert.ok(source.includes("device.dataset.deviceAddress=address"));
assert.ok(source.includes("card.dataset.runId=run.run_id"));
assert.ok(source.includes("data-device-scope-assignment") || source.includes("dataset.deviceScopeAssignment"));
assert.ok(source.includes("dataset.deviceScopeReceipts"));
assert.ok(source.includes("Retained by scoped receipts"));

await eval(`(async () => {
  const node=(tag,text='')=>({tag,textContent:text,children:[],disabled:false,append(...items){this.children.push(...items)},replaceChildren(...items){this.children=[...items]}});
  const element=(tag,_className,text='')=>node(tag,text);
  const document={createElement:tag=>node(tag)};
  const host=node('div'),button=node('button','View scoped address receipts'),requested=[];
  const run={run_id:'paged-run'};
  const receipt=index=>({interface_name:'Ethernet'+index,address:'10.0.'+Math.floor(index/250)+'.'+(index%250),prefix_length:24,address_family:'ipv4',routing_context_status:'default',routing_context:null,source_line_number:index,source_line:' ip address receipt-'+index});
  const fetch=async url=>{requested.push(url);const offset=Number(new URL(url,'http://nct.local').searchParams.get('offset')),items=Array.from({length:Math.min(100,205-offset)},(_,position)=>receipt(offset+position+1));return{ok:true,json:async()=>({pagination:{total:205,offset,limit:100,has_more:offset+items.length<205},assignment:{scope_label:'Paged Lab'},meaning:'This retained configuration reported these interface addresses.',source:{source_url:'/source',filename:'router.txt'},receipts:items})}};
  const apiError=()=>'';
  const notice=message=>{throw new Error(message)};
  ${handler("loadDeviceReceipts")}
  const texts=value=>[value.textContent,...value.children.flatMap(texts)];
  const buttons=value=>value.children.flatMap(child=>[...(child.tag==='button'?[child]:[]),...buttons(child)]);
  await loadDeviceReceipts(run,host,button);
  assert.ok(texts(host).includes('Showing 1-100 of 205 retained address receipts.'));
  let nav=buttons(host),previous=nav.find(item=>item.textContent==='Previous addresses'),next=nav.find(item=>item.textContent==='Next addresses');
  assert.equal(previous.disabled,true);assert.equal(next.disabled,false);
  await next.onclick();
  assert.ok(texts(host).includes('Ethernet101 · 10.0.0.101/24'));
  assert.ok(texts(host).includes('Showing 101-200 of 205 retained address receipts.'));
  nav=buttons(host);next=nav.find(item=>item.textContent==='Next addresses');await next.onclick();
  assert.ok(texts(host).includes('Ethernet205 · 10.0.0.205/24'));
  assert.ok(texts(host).includes('Showing 201-205 of 205 retained address receipts.'));
  nav=buttons(host);previous=nav.find(item=>item.textContent==='Previous addresses');next=nav.find(item=>item.textContent==='Next addresses');
  assert.equal(previous.disabled,false);assert.equal(next.disabled,true);
  assert.equal(button.textContent,'Refresh scoped address receipts');
  assert.deepEqual(requested,[
    '/api/device-configs/paged-run/scope-observations/receipts?limit=100&offset=0',
    '/api/device-configs/paged-run/scope-observations/receipts?limit=100&offset=100',
    '/api/device-configs/paged-run/scope-observations/receipts?limit=100&offset=200'
  ]);
})()`);

console.log("Device History UI runtime regressions passed");
