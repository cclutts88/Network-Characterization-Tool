import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/device_analysis_ui.py", import.meta.url), "utf8")
  .replaceAll("{{", "{").replaceAll("}}", "}");
function handler(name) {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/device_analysis_ui.py`);
  return match[0];
}

await eval(`(async () => {
  const HISTORY_PAGE_SIZE=100,MAX_DIRECT_HISTORY_PAGES=50;
  let records=[],historyOffset=0,historyHasMore=true,historyLoading=false,requestedOpened=false;
  const controls=new Map();
  const control=()=>({value:'',innerHTML:'',disabled:false,classList:{hidden:false,toggle(_name,value){this.hidden=value}}});
  const $=id=>{if(!controls.has(id))controls.set(id,control());return controls.get(id)};
  const location={search:'?run=old-204'};
  const statuses=[],requests=[],opened=[];
  const setStatus=(message,kind)=>statuses.push([message,kind]);
  const analyze=()=>opened.push($('currentRun').value);
  const when=value=>value;
  const esc=value=>String(value??'');
  ${handler("optionLabel")}
  ${handler("refreshBaselines")}
  ${handler("collectionOptions")}
  const all=Array.from({length:205},(_,index)=>({run_id:'old-'+index,created_at:String(205-index),status:'completed',device_address:'10.0.0.1'}));
  const fetch=async url=>{requests.push(url);const offset=Number(new URL(url,'http://nct.local').searchParams.get('offset'));const page=all.slice(offset,offset+100);return{ok:true,json:async()=>page}};
  ${handler("loadHistoryPage")}
  ${handler("loadRecords")}
  await loadRecords();
  assert.equal(records.length,205);
  assert.equal($('currentRun').value,'old-204');
  assert.deepEqual(opened,['old-204'],'a direct link must open an older retained collection after bounded paging');
  assert.equal(historyHasMore,false);
  assert.deepEqual(requests,[
    '/api/device-configs?limit=100&offset=0',
    '/api/device-configs?limit=100&offset=100',
    '/api/device-configs?limit=100&offset=200'
  ]);
})()`);

await eval(`(async () => {
  const HISTORY_PAGE_SIZE=100;
  let records=[],historyOffset=0,historyHasMore=true,historyLoading=false,requestedOpened=false,currentEvidence='';
  const controls=new Map();
  const control=()=>({value:'',innerHTML:'',disabled:false,classList:{hidden:false,toggle(_name,value){this.hidden=value}}});
  const $=id=>{if(!controls.has(id))controls.set(id,control());return controls.get(id)};
  const location={search:'?run=A'};
  const statuses=[],opened=[];
  const setStatus=(message,kind)=>statuses.push([message,kind]);
  const analyze=()=>{currentEvidence=$('currentRun').value;opened.push(currentEvidence)};
  const when=value=>value;
  const esc=value=>String(value??'');
  ${handler("optionLabel")}
  ${handler("refreshBaselines")}
  ${handler("collectionOptions")}
  const all=[
    {run_id:'A',created_at:'3',status:'completed',device_address:'10.0.0.1'},
    {run_id:'B',created_at:'2',status:'completed',device_address:'10.0.0.1'},
    ...Array.from({length:198},(_,index)=>({run_id:'older-'+index,created_at:'1',status:'completed',device_address:'10.0.0.1'}))
  ];
  const fetch=async url=>{const offset=Number(new URL(url,'http://nct.local').searchParams.get('offset'));return{ok:true,json:async()=>all.slice(offset,offset+100)}};
  ${handler("loadHistoryPage")}
  await loadHistoryPage();
  assert.equal($('currentRun').value,'A');
  assert.equal(currentEvidence,'A');
  $('currentRun').value='B';
  analyze();
  await loadHistoryPage();
  assert.equal($('currentRun').value,'B','loading older collections must preserve the operator selection');
  assert.equal(currentEvidence,'B','loading older collections must not change displayed evidence');
  assert.deepEqual(opened,['A','B']);
})()`);

console.log("Device analysis retained-history paging regressions passed");
