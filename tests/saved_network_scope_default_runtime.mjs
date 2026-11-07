import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");

function functionLine(name) {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/ui.py`);
  return match[0];
}

function fakeElement(value = "") {
  return { value, textContent: "", options: [], focus() {} };
}

function scopeSelect(options) {
  const select = fakeElement(options[0]?.value || "");
  select.options = options;
  select.appendChild = option => select.options.push(option);
  Object.defineProperty(select, "selectedOptions", {
    get: () => select.options.filter(option => option.value === select.value),
  });
  Object.defineProperty(select, "innerHTML", {
    set(markup) {
      select.options = Array.from(markup.matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g))
        .map(match => ({ value: match[1], textContent: match[2], disabled: false }));
      select.value = select.options[0]?.value || "";
    },
  });
  return select;
}

await eval(`(async () => {
  let editingSavedNetworkId=null,editingSavedNetworkRevision=null,savedNetworkScopeTouched=false,savedNetworkScopeDefaulted=false,savedNetworkScopeDefaultSnapshot=null;
  let networkScopes=[],savedNetworks=[];
  let collectionSafety={ready:true,scope:{scope_id:'scope-a',version:1,label:'Scope A'},review:{revision:1}};
  const controls=new Map(),select=scopeSelect([{value:'',textContent:'None'},{value:'scope-a',textContent:'Scope A'}]);
  controls.set('savedNetworkScope',select);
  const $=id=>{if(!controls.has(id))controls.set(id,fakeElement());return controls.get(id)};
  const document={createElement:()=>({value:'',textContent:'',disabled:false})};
  const activeCollectionScope=()=>collectionSafety.ready?collectionSafety.scope:null;
  const esc=value=>String(value);
  let savedBody=null;
  const fetch=async(url,options)=>{
    if(url==='/api/network-scope-options')return{ok:true,json:async()=>[{scope_id:'scope-b',label:'Scope B'}]};
    savedBody=JSON.parse(options.body);
    return{ok:false,json:async()=>({detail:'stop after payload capture'})};
  };
  const setSavedNetworkStatus=()=>{},loadSavedNetworks=async()=>{},loadNetworkCandidates=async()=>{};
  ${functionLine("savedNetworkEditorHasDraft")}
  ${functionLine("retainSavedNetworkScopeChoice")}
  ${functionLine("applyNewSavedNetworkScopeDefault")}
  ${functionLine("loadNetworkScopes")}
  ${functionLine("saveSavedNetwork")}

  applyNewSavedNetworkScopeDefault();
  assert.equal(select.value,'scope-a');
  assert.deepEqual(savedNetworkScopeDefaultSnapshot,{scope_id:'scope-a',scope_version:1,review_revision:1,label:'Scope A'});
  $('savedNetworkName').value='Analyst draft';
  $('savedNetworkCidr').value='10.60.0.0/24';
  collectionSafety={ready:true,scope:{scope_id:'scope-b',version:1,label:'Scope B'},review:{revision:2}};
  await loadNetworkScopes();
  assert.equal(select.value,'scope-a','scope refresh must retain the frozen selection');
  assert.equal(select.options.find(option=>option.value==='scope-a').disabled,true,'a removed frozen scope must remain visibly unavailable');
  assert.match($('savedNetworkScopeHelp').textContent,/default is frozen/);
  await saveSavedNetwork();
  assert.equal(savedBody.scope_id,'scope-a','save must never fall back to an unassociated record');
  assert.equal(savedBody.use_reviewed_scope_default,true);
  assert.equal(savedBody.expected_collection_review_revision,1);
  assert.equal(savedBody.expected_scope_version,1);
})()`);

await eval(`(async () => {
  let editingSavedNetworkId='network-a',editingSavedNetworkRevision={updated_at:'2026-11-07T00:00:00Z',scope_id:'scope-a',scope_label:'Scope A',association_id:'association-a',association_revision:1};
  let savedNetworkScopeTouched=true,savedNetworkScopeDefaulted=false,savedNetworkScopeDefaultSnapshot=null,networkScopes=[],savedNetworks=[];
  let collectionSafety={ready:true,scope:{scope_id:'scope-b',version:1,label:'Scope B'},review:{revision:2}};
  const controls=new Map(),select=scopeSelect([{value:'',textContent:'None'},{value:'scope-a',textContent:'Scope A'}]);
  select.value='scope-a';controls.set('savedNetworkScope',select);
  const $=id=>{if(!controls.has(id))controls.set(id,fakeElement());return controls.get(id)};
  const document={createElement:()=>({value:'',textContent:'',disabled:false})};
  const activeCollectionScope=()=>collectionSafety.scope,esc=value=>String(value);
  let savedBody=null;
  const fetch=async(url,options)=>{
    if(url==='/api/network-scope-options')return{ok:true,json:async()=>[{scope_id:'scope-b',label:'Scope B'}]};
    savedBody=JSON.parse(options.body);return{ok:false,json:async()=>({detail:'stop after payload capture'})};
  };
  const setSavedNetworkStatus=()=>{},loadSavedNetworks=async()=>{},loadNetworkCandidates=async()=>{};
  ${functionLine("savedNetworkEditorHasDraft")}
  ${functionLine("retainSavedNetworkScopeChoice")}
  ${functionLine("applyNewSavedNetworkScopeDefault")}
  ${functionLine("loadNetworkScopes")}
  ${functionLine("saveSavedNetwork")}

  $('savedNetworkName').value='Existing network';$('savedNetworkCidr').value='10.61.0.0/24';
  await loadNetworkScopes();
  assert.equal(select.value,'scope-a','editing refresh must retain the existing association');
  assert.equal(select.options.find(option=>option.value==='scope-a').disabled,true);
  await saveSavedNetwork();
  assert.equal(savedBody.scope_id,'scope-a');
  assert.equal(savedBody.expected_association_id,'association-a');
  assert.equal(savedBody.expected_revision,1);
})()`);

await eval(`(async () => {
  let editingSavedNetworkId='network-a',editingSavedNetworkRevision={scope_id:'scope-a'};
  let savedNetworkScopeTouched=true,savedNetworkScopeDefaulted=false,savedNetworkScopeDefaultSnapshot=null,networkScopes=[];
  const controls=new Map(),select=scopeSelect([{value:'',textContent:'None'},{value:'scope-a',textContent:'Scope A'},{value:'scope-b',textContent:'Scope B'}]);
  select.value='scope-a';controls.set('savedNetworkScope',select);
  const $=id=>{if(!controls.has(id))controls.set(id,fakeElement());return controls.get(id)};
  const document={createElement:()=>({value:'',textContent:'',disabled:false})};
  const esc=value=>String(value),activeCollectionScope=()=>null;
  const pendingResponses=[];
  const fetch=()=>new Promise(resolve=>pendingResponses.push(resolve));
  ${functionLine("savedNetworkEditorHasDraft")}
  ${functionLine("retainSavedNetworkScopeChoice")}
  ${functionLine("applyNewSavedNetworkScopeDefault")}
  ${functionLine("loadNetworkScopes")}

  const changedToB=loadNetworkScopes();
  select.value='scope-b';
  pendingResponses.shift()({ok:true,json:async()=>[{scope_id:'scope-a',label:'Scope A'},{scope_id:'scope-b',label:'Scope B'}]});
  await changedToB;
  assert.equal(select.value,'scope-b','a refresh response must preserve an edited A to B choice');

  select.value='scope-a';
  const cleared=loadNetworkScopes();
  select.value='';
  pendingResponses.shift()({ok:true,json:async()=>[{scope_id:'scope-a',label:'Scope A'},{scope_id:'scope-b',label:'Scope B'}]});
  await cleared;
  assert.equal(select.value,'','a refresh response must preserve an explicit cleared association');
})()`);

await eval(`(() => {
  let editingSavedNetworkId=null,savedNetworkScopeTouched=false,savedNetworkScopeDefaulted=false,savedNetworkScopeDefaultSnapshot=null;
  let collectionSafety={ready:false,scope:null,review:null};
  const controls=new Map(),select=scopeSelect([{value:'',textContent:'None'},{value:'scope-a',textContent:'Scope A'}]);controls.set('savedNetworkScope',select);
  const $=id=>{if(!controls.has(id))controls.set(id,fakeElement());return controls.get(id)};
  const document={createElement:()=>({value:'',textContent:'',disabled:false})};
  const activeCollectionScope=()=>collectionSafety.ready?collectionSafety.scope:null;
  ${functionLine("savedNetworkEditorHasDraft")}
  ${functionLine("retainSavedNetworkScopeChoice")}
  ${functionLine("applyNewSavedNetworkScopeDefault")}

  $('savedNetworkName').value='Draft started before review';
  applyNewSavedNetworkScopeDefault();
  collectionSafety={ready:true,scope:{scope_id:'scope-a',version:1,label:'Scope A'},review:{revision:1}};
  applyNewSavedNetworkScopeDefault();
  assert.equal(select.value,'','a newly ready review must not change a draft already in progress');
  assert.equal(savedNetworkScopeDefaulted,false);
  assert.equal(savedNetworkScopeDefaultSnapshot,null);
  assert.match($('savedNetworkScopeHelp').textContent,/did not change your draft/);
})()`);

console.log("saved network reviewed-scope default runtime checks passed");
