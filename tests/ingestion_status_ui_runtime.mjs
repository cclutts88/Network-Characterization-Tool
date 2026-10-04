import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/storage_ui.py", import.meta.url), "utf8");
function handler(name) {
  const match = source.match(new RegExp(`^async function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/storage_ui.py`);
  return match[0];
}

await eval(`(async () => {
  let ingestionOffset=25,ingestionDisplayedOffset=0,ingestionRequestId=0;
  const ingestionLimit=25,requests=[],renders=[];
  const controls=new Map();
  const byId=id=>{if(!controls.has(id))controls.set(id,{textContent:'',disabled:false});return controls.get(id)};
  const pending=[];
  const fetch=url=>{requests.push(url);return new Promise(resolve=>pending.push(resolve))};
  const renderIngestion=data=>renders.push(data.offset);
  const setTimeout=()=>{};
  ${handler("refreshIngestion")}
  const older=refreshIngestion();
  ingestionOffset=0;
  const newest=refreshIngestion();
  pending[1]({ok:true,json:async()=>({items:[],offset:0,total:50,has_more:true,historical_unadopted:{total:0}})});
  await newest;
  pending[0]({ok:true,json:async()=>({items:[{status:'ready'}],offset:25,total:50,has_more:false,historical_unadopted:{total:0}})});
  await older;
  assert.deepEqual(requests,[
    '/api/system/ingestion-status?limit=25&offset=25',
    '/api/system/ingestion-status?limit=25&offset=0'
  ]);
  assert.deepEqual(renders,[0]);
  assert.equal(ingestionDisplayedOffset,0);
})()`);

console.log("Evidence intake status UI runtime regression passed");
