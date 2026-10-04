import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/storage_ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/storage_ui.py`);
  return match[0].trim();
}

await eval(`(async () => {
  const controls=new Map();
  const control=id=>{
    if(!controls.has(id))controls.set(id,{
      value:'',textContent:'',disabled:false,
      classList:{add(){},remove(){}},focus(){}
    });
    return controls.get(id);
  };
  const byId=control;
  const bytes=value=>String(value);
  let currentCompactionPlan={plan_id:'plan-a',eligible_file_count:1,estimated_file_length_savings:10};
  let confirmedCompactionPlan=null;
  let sent=null;
  const render=()=>{};
  const fetch=async (_url,options)=>{
    sent=JSON.parse(options.body);
    return {ok:true,json:async()=>({status:'running',report:null})};
  };
  ${handler("openCompaction")}
  ${handler("confirmCompaction")}
  ${handler("cancelCompaction")}

  openCompaction();
  assert.equal(control('compactSummary').textContent,'1 exact duplicate copies · estimated 10.');
  currentCompactionPlan={plan_id:'plan-b',eligible_file_count:100,estimated_file_length_savings:1000};
  control('compactPhrase').value='REMOVE VERIFIED DUPLICATE COPIES';
  await confirmCompaction();
  assert.equal(sent.plan_id,'plan-a');
  assert.equal(sent.confirmation,'REMOVE VERIFIED DUPLICATE COPIES');

  currentCompactionPlan={plan_id:'plan-c',eligible_file_count:2,estimated_file_length_savings:20};
  openCompaction();
  control('compactPhrase').value='REMOVE VERIFIED DUPLICATE COPIES';
  cancelCompaction();
  assert.equal(confirmedCompactionPlan,null);
  assert.equal(control('compactPhrase').value,'');
})()`);
