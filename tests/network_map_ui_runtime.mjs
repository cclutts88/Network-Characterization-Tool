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

await eval(`(() => {
  const wrappers=[];
  const document={createElement:()=>({className:'',dataset:{},attributes:{},setAttribute(name,value){this.attributes[name]=value},append(node){this.child=node;node.parentElement=this}})};
  const makeTable=label=>({previousElementSibling:{textContent:label},parentElement:{classList:{contains:()=>false}},replaceWith(wrapper){wrappers.push(wrapper)}});
  const tables=[makeTable('Open services'),makeTable('MAC evidence')];
  const root={querySelectorAll:selector=>selector==='table'?tables:[]};
  ${handler("wrapDetailsTables")}

  wrapDetailsTables(root);
  assert.equal(wrappers.length,2);
  for(const wrapper of wrappers){
    assert.equal(wrapper.className,'table-wrap');
    assert.equal(wrapper.dataset.nctTableMode,'contained');
    assert.equal(wrapper.attributes.role,'region');
    assert.equal(wrapper.tabIndex,0);
    assert.match(wrapper.attributes['aria-label'],/table$/);
    assert.ok(wrapper.child,'the original table remains inside the new scrolling region');
  }
})()`);

await eval(`(() => {
  const esc=value=>String(value??'').replace(/[&<>"']/g,character=>character);
  ${handler("serviceObservedAddress")}
  ${handler("interfaceObservedAddresses")}
  ${handler("serviceExposureGroup")}
  ${handler("serviceEvidenceMarkup")}
  ${handler("renderServiceGroups")}
  const node={kind:'device',ip:'192.0.2.1',addresses:['192.0.2.1','10.0.0.1'],interfaces:[{name:'wan0',zone:'WAN',addresses:['192.0.2.1/24']},{name:'lan0',zone:'LAN',addresses:['10.0.0.1/24']}]};
  const services=[
    {address:'192.0.2.1',port:443,protocol:'tcp',service:'https',product:'nginx',version:'1.26',sources:[{label:'WAN scan',url:'/source/wan'}]},
    {address:'10.0.0.1',port:443,protocol:'tcp',service:'https',product:'admin portal',version:'4',sources:[{label:'LAN scan'}]},
    {address:'172.16.0.1',port:22,protocol:'tcp',service:'ssh',product:'OpenSSH'},
  ];
  const html=renderServiceGroups(node,services);
  assert.match(html,/WAN · 192\.0\.2\.1/);
  assert.match(html,/LAN · 10\.0\.0\.1/);
  assert.match(html,/Interface \\/ address not established/);
  assert.match(html,/Observed address 172\.16\.0\.1/);
  assert.match(html,/WAN scan/);
  assert.equal((html.match(/443\\/tcp/g)||[]).length,2,'the same port on two interfaces remains two attributable rows');
  assert.ok(html.indexOf('443/tcp')<html.indexOf('nginx'),'the port and matching fingerprint are rendered in one row');
  const ambiguousNode={kind:'device',addresses:['10.1.0.1'],interfaces:[{name:'red',zone:'RED',addresses:['10.1.0.1/24']},{name:'blue',zone:'BLUE',addresses:['10.1.0.1/24']}]};
  assert.equal(serviceExposureGroup(ambiguousNode,{address:'10.1.0.1',port:443}).kind,'unmatched','duplicate retained interface addresses cannot be attributed by array order');
  assert.equal(serviceExposureGroup(ambiguousNode,{address:'10.1.0.1',interface:'blue',port:443}).label,'BLUE · 10.1.0.1','an explicit retained interface resolves an otherwise ambiguous address');
})()`);

await eval(`(() => {
  let detailsSuppressed=true,toggleForce=null,syncForce=null;
  let focused=false,focusOptions=null;
  const missionRole={focus(options){focused=true;focusOptions=options}};
  const details={querySelector:selector=>selector==='.mission-role-details'?missionRole:null,focus(){throw new Error('role details should receive focus')}};
  const open={},summary={hidden:true,_html:'',set innerHTML(value){this._html=value},get innerHTML(){return this._html}},workspace={classList:{contains:name=>name==='map-expanded'}};
  const $=id=>id==='selectedObjectSummary'?summary:id==='mapWorkspace'?workspace:id==='openSelectedDetails'?open:id==='details'?details:null;
  const esc=value=>String(value),compactServicePorts=()=> '53/tcp, 53/udp',osInferenceTitle=()=> 'Declared role',displayOs=()=> 'Unclassified';
  const toggleWorkspace=force=>{toggleForce=force},syncDetailsVisibility=force=>{syncForce=force};
  const requestAnimationFrame=callback=>callback();
  ${handler("openSelectedObjectDetails")}
  ${handler("renderSelectedObjectSummary")}

  renderSelectedObjectSummary({label:'Mission DNS',address:'10.77.0.10'});
  assert.equal(typeof open.onclick,'function','Open full details has native click activation');
  open.onclick();
  assert.equal(detailsSuppressed,false);
  assert.equal(toggleForce,true);
  assert.equal(syncForce,true);
  assert.equal(focused,true,'opening details moves focus to the declared-role explanation');
  assert.deepEqual(focusOptions,{preventScroll:true});
})()`);

await eval(`(() => {
  const reachPathColors={equal_cost:'#73bfff'},reachPathPalette=['#57d6bf','#73bfff','#f4c95d','#c49aff','#ff9f68','#ff7b7b','#35d0f2','#9ad86a'];
  const makeClassList=()=>({values:new Set(),toggle(name,enabled){if(enabled)this.values.add(name);else this.values.delete(name)},contains(name){return this.values.has(name)}});
  const makeItem=dataset=>({dataset:{...dataset},classList:makeClassList(),style:{values:new Map(),setProperty(name,value){this.values.set(name,value)},removeProperty(name){this.values.delete(name)}},attributes:{},setAttribute(name,value){this.attributes[name]=value},removeAttribute(name){delete this.attributes[name]}});
  const nodeItems=['ip:10.1.0.50','subnet:10.1.0.0/24','ip:10.0.0.1','ip:10.0.0.2','subnet:10.2.0.0/24'].map(node=>makeItem({node}));
  const edges=[
    makeItem({edgeSource:'ip:10.1.0.50',edgeTarget:'subnet:10.1.0.0/24',edgeRelation:'subnet_membership'}),
    makeItem({edgeSource:'ip:10.0.0.1',edgeTarget:'subnet:10.1.0.0/24',edgeRelation:'directly_connected'}),
    makeItem({edgeSource:'ip:10.0.0.1',edgeTarget:'subnet:10.2.0.0/24',edgeRelation:'directly_connected'}),
    makeItem({edgeSource:'ip:10.0.0.2',edgeTarget:'subnet:10.1.0.0/24',edgeRelation:'directly_connected'}),
  ];
  const document={querySelectorAll(selector){if(selector==='[data-node]')return nodeItems;if(selector==='[data-group-host]')return[];if(selector==='[data-edge-source]')return edges;return[]}};
  const requestAnimationFrame=callback=>callback(),fitBounds=()=>{},boundsForIds=()=>({});
  const currentPositions=new Map(nodeItems.map(item=>[item.dataset.node,{}]));
  let reachFocusPendingFit=false;
  const topology={
    nodes:[
      {id:'ip:10.1.0.50',ip:'10.1.0.50',label:'Endpoint'},
      {id:'subnet:10.1.0.0/24',network:'10.1.0.0/24',label:'Assessed subnet'},
      {id:'ip:10.0.0.1',ip:'10.0.0.1',label:'Core A'},
      {id:'ip:10.0.0.2',ip:'10.0.0.2',label:'Core B'},
      {id:'subnet:10.2.0.0/24',network:'10.2.0.0/24',label:'Unrelated subnet'},
    ],
    edges:[
      {source:'ip:10.1.0.50',target:'subnet:10.1.0.0/24',relation:'subnet_membership'},
      {source:'ip:10.0.0.1',target:'subnet:10.1.0.0/24',relation:'directly_connected'},
      {source:'ip:10.0.0.1',target:'subnet:10.2.0.0/24',relation:'directly_connected'},
      {source:'ip:10.0.0.2',target:'subnet:10.1.0.0/24',relation:'directly_connected'},
    ],
  };
  const path=id=>({id,role:'equal_cost',label:id==='a'?'Primary retained path':'Alternate retained path',query:{source:'Internet',destination:'10.1.0.50'},destination_network:{cidr:'10.1.0.0/24'},path:[{kind:'route',label:'10.1.0.0/24'}],retained_objects:{selected_path_routes:[{network:'10.1.0.0/24',device:id==='a'?'Core A':'Core B',device_address:id==='a'?'10.0.0.1':'10.0.0.2'}]}});
  let reachFocus={result:{query:{source:'Internet'},active_path_id:'a',path_options:[path('a'),path('b')]},visible_path_ids:['a']};
  const reachFocusNodeIds=new Set(),reachFocusPathNodeIds=new Map(),reachFocusNodeColors=new Map(),reachFocusEdgeColors=new Map();
  ${handler("reachPathOptions", false, true)}
  ${handler("reachPathColorAssignments", false, true)}
  ${handler("reachPathColor", false, true)}
  ${handler("visibleReachPathOptions", false, true)}
  ${handler("addReachFocusValue", false, true)}
  ${handler("ipv4InCidr", false, true)}
  ${handler("resolveReachResultNodes", false, true)}
  ${handler("addReachFocusColor", false, true)}
  ${handler("resolveReachFocusNodes", false, true)}
  ${handler("reachPathMatchesEdge", false, true)}
  ${handler("applyReachFocus", false, true)}

  applyReachFocus();
  assert.equal(reachFocusNodeIds.has('subnet:10.2.0.0/24'),false,'a router-adjacent unrelated subnet is not part of the selected path');
  assert.equal(nodeItems[4].classList.contains('reach-focus-dim'),true);
  assert.equal(edges[2].classList.contains('reach-focus-dim'),true,'the unrelated subnet link remains dim');
  assert.equal(edges[0].classList.contains('reach-focus-match'),true,'the exact endpoint membership remains highlighted');
  assert.equal(edges[1].classList.contains('reach-focus-match'),true,'the selected router branch remains highlighted');
  assert.equal(edges[3].classList.contains('reach-focus-dim'),true,'the unselected alternate router branch remains dim');

  reachFocus.visible_path_ids=['a','b'];
  applyReachFocus();
  const colors=reachPathColorAssignments();
  assert.notEqual(colors.get('a'),colors.get('b'),'two selected same-role paths receive distinct colors');
  assert.equal(edges[0].classList.contains('reach-focus-shared'),true,'a common endpoint segment is explicitly marked shared');
  assert.equal(edges[1].classList.contains('reach-focus-shared'),false);
  assert.equal(edges[3].classList.contains('reach-focus-shared'),false);
  assert.notEqual(edges[1].style.values.get('--reach-focus-color'),edges[3].style.values.get('--reach-focus-color'));

  reachFocus.visible_path_ids=[];
  assert.deepEqual(visibleReachPathOptions(),[],'an explicitly empty path selection remains empty');
  reachFocus.visible_path_ids=['stale-path'];
  assert.deepEqual(visibleReachPathOptions(),[],'a stale path id cannot broaden the selection');

  topology.nodes.push({id:'device:edge',kind:'device',label:'Edge router',addresses:['10.1.0.1','10.2.0.1']});
  topology.edges.push(
    {source:'device:edge',target:'subnet:10.1.0.0/24',relation:'subnet_membership'},
    {source:'device:edge',target:'subnet:10.2.0.0/24',relation:'subnet_membership'},
  );
  const routerEndpointPath={query:{source:'10.1.0.1',destination:'10.1.0.50'},destination_network:{cidr:'10.1.0.0/24'},path:[],retained_objects:{}};
  reachFocus={result:routerEndpointPath,visible_path_ids:[]};
  const routerEndpointResolved=resolveReachResultNodes(routerEndpointPath);
  assert.equal(routerEndpointResolved.nodes.has('device:edge'),true,'the exact queried router address resolves the router endpoint');
  assert.equal(routerEndpointResolved.nodes.has('subnet:10.1.0.0/24'),true,'the exact queried router address retains its supported subnet');
  assert.equal(routerEndpointResolved.nodes.has('subnet:10.2.0.0/24'),false,'another subnet on the same multi-interface router stays unrelated');
})()`);

console.log("Network Map expanded spacing runtime regression passed");
