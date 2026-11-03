import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync('app/analysis_ui.py','utf8').split('\n').find(x=>x.startsWith('async function openRun('));
const nodes=new Map();
const el=id=>{if(!nodes.has(id))nodes.set(id,{innerHTML:'stale source data',title:'old source',textContent:'',hidden:true,classList:{remove(){el(id).hidden=false;},add(){el(id).hidden=true;}},insertAdjacentHTML(_,html){this.innerHTML+=html;},scrollIntoView(){}});return nodes.get(id);};
let resolve;
const calls=[];
const context={$:el,esc:x=>x,encodeURIComponent,currentAnalysis:{old:true},currentContext:{old:true},currentLabel:'old',
  setStatus(id,text){el(id).textContent=text;},responseError:x=>x.detail.message,
  fetch(url,options){calls.push({url,options});return new Promise(r=>resolve=r);},
  scanRef:x=>({primary:x.display_name,secondary:'saved source',detail:'exact source'}),
  renderAnalysis(a,c){el('results').innerHTML=c.identifier;},savedResultSummary:()=>'',currentAnnotationSummary:()=>'',renderAnalysisWarnings:()=>{}};
vm.createContext(context);vm.runInContext(source,context);
const pending=context.openRun('unprepared');
assert.equal(el('analysisPanel').hidden,false,'Loading status must be visible');
assert.equal(el('results').innerHTML,'','Previous source results must be cleared');
assert.equal(context.currentAnalysis,null);
resolve({ok:false,json:async()=>({detail:{message:'Prepare the saved scan from Scan History'}})});
await pending;
assert.match(el('analysisStatus').textContent,/Prepare/);
assert.match(el('analysisTitle').innerHTML,/\/scans#scanHistory/);
assert.equal(el('analysisPanel').hidden,false);
assert.equal(el('results').innerHTML,'');
assert.equal(calls.length,1);assert.equal(calls[0].options,undefined,'No processing request may be sent');
const ready=context.openRun('prepared');
resolve({ok:true,json:async()=>({metadata:{},display_name:'Prepared retained scan',analysis:{}})});
await ready;
assert.equal(el('results').innerHTML,'prepared');
assert.match(el('analysisStatus').textContent,/opened without network contact/);
console.log('Retained scan loading, unavailable source and prepared result checks passed');
