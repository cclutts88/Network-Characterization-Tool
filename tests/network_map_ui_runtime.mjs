import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/network_map_ui.py", import.meta.url), "utf8");

function handler(name, asyncFunction = false, raw = false) {
  const prefix = asyncFunction ? "async function" : "function";
  const match = source.match(new RegExp(`^${prefix} ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/network_map_ui.py`);
  return raw ? match[0] : match[0].replaceAll("{{", "{").replaceAll("}}", "}");
}

await eval(`(() => {
  let summaryTop=0,canvasTop=58;
  const properties=new Map(),expandedTopHistory=[];
  const shell={
    getBoundingClientRect:()=>({top:0,left:0,right:1200,bottom:900}),
    style:{setProperty:(name,value)=>{
      properties.set(name,value);
      if(name==='--expanded-safe-top'){
        expandedTopHistory.push(Number.parseFloat(value));
        summaryTop=Number.parseFloat(value);
        canvasTop=summaryTop+67;
      }
    }},
  };
  const canvas={getBoundingClientRect:()=>({top:canvasTop,left:0,right:1200,bottom:900})};
  const expandedControls={hidden:false,getBoundingClientRect:()=>({top:12,bottom:50})};
  const scaleControls={getBoundingClientRect:()=>({top:12,bottom:63})};
  const document={
    body:{classList:{contains:name=>name==='map-expanded'}},
    querySelector:selector=>selector==='.map-shell'?shell:selector==='.zoom-controls'?scaleControls:null,
  };
  const $=id=>id==='mapCanvas'?canvas:id==='expandedWorkspaceControls'?expandedControls:null;
  ${handler("expandedFloatingControlsSafeTop")}
  ${handler("expandedControlSafeTop")}
  ${handler("updateMapControlsCanvasBounds")}

  updateMapControlsCanvasBounds();
  const stableSummaryTop=summaryTop,stableCanvasTop=canvasTop;
  for(let index=0;index<4;index+=1)updateMapControlsCanvasBounds();
  assert.equal(stableSummaryTop,71,'summary begins below the floating controls');
  assert.equal(summaryTop,stableSummaryTop,'repeated updates must not push the summary downward');
  assert.equal(canvasTop,stableCanvasTop,'repeated updates must not push the canvas downward');
  assert.deepEqual(expandedTopHistory,[71,71,71,71,71]);
  assert.equal(properties.get('--map-control-top'),'148px');
})()`);

await eval(`(() => {
  let state={x:0},activeLayoutKey=null,cleanLayoutSnapshot=null,cleanLayoutFingerprint=null,workingLayoutDirty=false,layoutSaveInFlight=false,serverWorkspaceEnabled=true,serverWorkspaceAnalyst={username:'alice',role:'analyst'};
  const active={layout_id:'layout-a',name:'Alpha',owner:'alice',version:3};
  const controls=new Map();
  for(const id of ['layoutDirtyBar','layoutDirtyMessage','saveCurrentLayout','expandedSaveCurrent','discardLayoutChanges','expandedSaveAsNew','saveLayout','loadLayout','resetLayout','deleteLayout','setDefaultLayout','shareLayout','unsavedOverwrite','unsavedSaveAsNew','unsavedDiscard','unsavedStay'])controls.set(id,{hidden:true,disabled:false,textContent:''});
  const $=id=>controls.get(id);
  const capturePresentation=()=>JSON.parse(JSON.stringify(state));
  const readNamedLayouts=()=>[active];
  const selectedNamedLayout=()=>active;
  const layoutKey=layout=>layout.layout_id;
  const layoutOwnedByAnalyst=layout=>layout.owner==='alice';
  const updateLayoutWorkspaceStatus=()=>{};
  const updateHistoryButtons=()=>{};
  const restorePresentation=snapshot=>{state=JSON.parse(JSON.stringify(snapshot));};
  const undoStack=[],redoStack=[];
  ${handler("presentationFingerprint")}
  ${handler("activeNamedLayout")}
  ${handler("syncLayoutDirtyState")}
  ${handler("markLayoutClean")}
  ${handler("commitHistorySnapshot")}
  ${handler("undoPresentation")}

  markLayoutClean(active,state);
  state={x:1};
  commitHistorySnapshot({x:0},'move object');
  assert.equal(workingLayoutDirty,true);
  assert.equal($('layoutDirtyBar').hidden,false);
  assert.equal($('saveCurrentLayout').disabled,false);
  undoPresentation();
  assert.equal(state.x,0);
  assert.equal(workingLayoutDirty,false,'undoing to the saved baseline clears dirty state');
  assert.equal($('layoutDirtyBar').hidden,true);
})()`);

await eval(`(async () => {
  let state={x:1},activeLayoutKey='layout-a',cleanLayoutSnapshot={x:0},cleanLayoutFingerprint=JSON.stringify({x:0}),workingLayoutDirty=true,layoutSaveInFlight=false,pendingLayoutTransition='stay';
  let serverWorkspaceEnabled=true,serverWorkspaceAnalyst={username:'alice',role:'analyst'},serverLayouts=[{layout_id:'layout-a',name:'Alpha',owner:'alice',version:3,is_default:true}],request=null,resolveRequest,requestCount=0;
  const controls=new Map();
  for(const id of ['layoutDirtyBar','layoutDirtyMessage','saveCurrentLayout','expandedSaveCurrent','discardLayoutChanges','expandedSaveAsNew','saveLayout','loadLayout','resetLayout','deleteLayout','setDefaultLayout','shareLayout','unsavedOverwrite','unsavedSaveAsNew','unsavedDiscard','unsavedStay','layoutName','expandedLayoutName','notice'])controls.set(id,{hidden:true,disabled:false,textContent:'',value:'Alpha',className:''});
  const $=id=>controls.get(id);
  const capturePresentation=()=>JSON.parse(JSON.stringify(state));
  const readNamedLayouts=()=>serverLayouts;
  const selectedNamedLayout=()=>serverLayouts[0];
  const writeNamedLayouts=()=>{};
  const layoutKey=layout=>layout.layout_id||layout.name;
  const layoutOwnedByAnalyst=layout=>layout.owner===serverWorkspaceAnalyst.username;
  const updateLayoutWorkspaceStatus=()=>{};
  const refreshNamedLayouts=()=>{};
  const fetch=(url,options)=>new Promise(resolve=>{requestCount+=1;request={url,options};resolveRequest=resolve;});
  ${handler("presentationFingerprint")}
  ${handler("activeNamedLayout")}
  ${handler("layoutSaveBlocks")}
  ${handler("syncLayoutDirtyState")}
  ${handler("loadNamedLayout")}
  ${handler("discardLayoutChanges")}
  ${handler("closeUnsavedLayoutDialog")}
  ${handler("persistNamedLayout", true)}

  const save=persistNamedLayout('Alpha',capturePresentation(),serverLayouts[0]);
  await Promise.resolve();
  const payload=JSON.parse(request.options.body);
  assert.equal(payload.layout_id,'layout-a');
  assert.equal(payload.expected_version,3);
  assert.equal($('loadLayout').disabled,true,'loading is disabled while a save is pending');
  assert.equal($('unsavedSaveAsNew').disabled,true,'duplicate dialog saves are disabled');
  assert.equal($('unsavedStay').disabled,true,'the original save transition cannot be replaced while pending');
  const duplicate=await persistNamedLayout('Alpha duplicate',capturePresentation(),null);
  assert.equal(duplicate,null,'a second save cannot start while the first is pending');
  assert.equal(requestCount,1,'only one save request is sent');
  let loadCount=0,dialogCount=0;
  const performLoadNamedLayout=()=>{loadCount+=1;};
  const openUnsavedLayoutDialog=()=>{dialogCount+=1;};
  loadNamedLayout();
  assert.equal(loadCount,0,'a different layout cannot replace the canvas while saving');
  assert.equal(dialogCount,0,'loading does not replace the original pending transition');
  assert.equal(discardLayoutChanges(true),false,'discard cannot replace the canvas while saving');
  assert.equal(closeUnsavedLayoutDialog(),false,'Stay cannot clear the original transition while saving');
  assert.equal(pendingLayoutTransition,'stay');
  state={x:2};
  resolveRequest({ok:true,json:async()=>({layout_id:'layout-a',name:'Alpha',owner:'alice',version:4,snapshot:{x:1}})});
  const result=await save;
  assert.equal(result.currentWasSaved,false);
  assert.equal(workingLayoutDirty,true,'edits made during a save remain unsaved');
  assert.match($('notice').textContent,/newer map changes still need to be saved/);

  const failed=persistNamedLayout('Alpha',capturePresentation(),serverLayouts[0]);
  await Promise.resolve();
  resolveRequest({ok:false,json:async()=>({detail:'version conflict'})});
  assert.equal(await failed,null);
  assert.equal(workingLayoutDirty,true,'failed save must retain dirty state');
  assert.equal(pendingLayoutTransition,'stay','failed save must not continue navigation');
  assert.match($('notice').textContent,/were not saved: version conflict/);
})()`);

await eval(`(async () => {
  let state={x:2},activeLayoutKey='layout-a',cleanLayoutSnapshot={x:1},cleanLayoutFingerprint=JSON.stringify({x:1}),workingLayoutDirty=true,layoutSaveInFlight=false;
  let serverWorkspaceEnabled=true,serverWorkspaceAnalyst={username:'alice',role:'analyst'},serverLayouts=[{layout_id:'layout-a',name:'Alpha',owner:'alice',version:3}];
  const controls=new Map();
  for(const id of ['layoutDirtyBar','layoutDirtyMessage','saveCurrentLayout','expandedSaveCurrent','discardLayoutChanges','expandedSaveAsNew','saveLayout','loadLayout','resetLayout','deleteLayout','setDefaultLayout','shareLayout','unsavedOverwrite','unsavedSaveAsNew','unsavedDiscard','unsavedStay','layoutName','expandedLayoutName','notice'])controls.set(id,{hidden:true,disabled:false,textContent:'',value:'Alpha',className:''});
  const $=id=>controls.get(id);
  const capturePresentation=()=>JSON.parse(JSON.stringify(state));
  const readNamedLayouts=()=>serverLayouts;
  const selectedNamedLayout=()=>serverLayouts[0]||null;
  const layoutKey=layout=>layout.layout_id||layout.name;
  const layoutOwnedByAnalyst=layout=>layout.owner===serverWorkspaceAnalyst.username;
  const updateLayoutWorkspaceStatus=()=>{};
  const refreshNamedLayouts=()=>{};
  const confirm=()=>true;
  const fetch=async()=>({ok:true,json:async()=>({deleted:true})});
  ${handler("presentationFingerprint")}
  ${handler("activeNamedLayout")}
  ${handler("layoutSaveBlocks")}
  ${handler("syncLayoutDirtyState")}
  ${handler("markLayoutClean")}
  ${handler("deleteNamedLayout", true, true)}

  await deleteNamedLayout();
  assert.deepEqual(state,{x:2},'deleting the saved copy does not discard visible edits');
  assert.equal(activeLayoutKey,null,'the deleted saved layout no longer owns the canvas');
  assert.equal(workingLayoutDirty,true,'visible edits remain protected as unsaved work');
  assert.equal($('layoutDirtyBar').hidden,false,'navigation will still offer save/discard/stay choices');
  assert.match($('notice').textContent,/still has unsaved changes/);
})()`);

console.log("Network Map expanded spacing runtime regression passed");
