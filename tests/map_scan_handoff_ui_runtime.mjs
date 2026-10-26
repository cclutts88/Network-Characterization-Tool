import assert from "node:assert/strict";
import fs from "node:fs";

const mapSource = fs.readFileSync(new URL("../app/network_map_ui.py", import.meta.url), "utf8");
const scanSource = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");

function handler(source, name) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name}`);
  return match[0].replaceAll("{{", "{").replaceAll("}}", "}");
}

function rawHandler(source, name) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name}`);
  return match[0];
}

await eval(`(() => {
  const location={origin:'https://nct.example'};
  ${handler(mapSource, "validMapIpv4")}
  ${handler(mapSource, "validMapCidr")}
  ${handler(mapSource, "mapDeviceAddresses")}
  ${handler(mapSource, "mapNodeHasNmapObservation")}
  ${handler(mapSource, "mapScanPreparation")}
  ${handler(mapSource, "mapScanHref")}

  const subnet={kind:'subnet',network:'10.50.15.0/24',host_count:0,infrastructure_count:0,saved_network_id:'saved-dev',saved_network_cidr:'10.50.15.0/24'};
  const preparedSubnet=mapScanPreparation(subnet);
  assert.deepEqual(preparedSubnet,{kind:'subnet',targets:['10.50.15.0/24'],savedNetworkId:'saved-dev'});
  assert.equal(mapScanPreparation({...subnet,host_count:1}),null,'a subnet with retained Nmap endpoints is not presented as a gap');
  assert.equal(mapScanPreparation({kind:'subnet_group',network:'10.50.0.0/16',host_count:0}),null,'synthetic groups cannot prepare scans');

  const device={kind:'device',ip:'10.50.15.20',addresses:['10.50.15.20','10.50.15.3'],interfaces:[{addresses:['10.50.15.10/24']}]};
  assert.deepEqual(mapScanPreparation(device).targets,['10.50.15.3','10.50.15.10','10.50.15.20']);
  assert.equal(mapScanPreparation({...device,sources:[{kind:'automated_nmap'}]}),null,'retained Nmap evidence removes the gap action');
  assert.equal(mapScanPreparation({kind:'device',label:'10.60.0.1 but no explicit address'}),null,'labels are never parsed into scan targets');

  const href=mapScanHref({label:'Dev subnet <script>'},'10.50.15.0/24',preparedSubnet);
  const url=new URL(href,location.origin);
  assert.equal(url.pathname,'/scans');
  assert.equal(url.hash,'#scanBuilder');
  assert.equal(url.searchParams.get('map_target'),'10.50.15.0/24');
  assert.equal(url.searchParams.get('map_saved_network_id'),'saved-dev');
  assert.equal(url.searchParams.get('map_label'),'Dev subnet <script>');
})()`);

function runScanHandoff(search, savedNetworks) {
  const classes = new Set(["hidden"]);
  const controls = new Map([
    ["mapScanHandoff", {classList:{add:(...names)=>names.forEach(name=>classes.add(name)),remove:(...names)=>names.forEach(name=>classes.delete(name))}}],
    ["mapScanHandoffTarget", {textContent:""}],
    ["mapScanHandoffContext", {textContent:""}],
    ["savedNetworkSelect", {options:savedNetworks.map(item=>({value:item.saved_network_id,selected:false}))}],
    ["scopeMode", {value:"saved"}],
    ["targets", {value:"prior draft"}],
    ["scanName", {value:"Terrain_Baseline"}],
  ]);
  const $=id=>controls.get(id);
  let scopeRefreshes=0,safetyRefreshes=0,draftSaves=0;
  const location={search};
  const showScopeInputs=()=>{scopeRefreshes+=1;};
  const scheduleSafetySummary=()=>{safetyRefreshes+=1;};
  const scheduleDraftSave=()=>{draftSaves+=1;};
  return eval(`(() => {
    ${handler(scanSource, "validMapHandoffIpv4")}
    ${handler(scanSource, "validMapHandoffTarget")}
    ${handler(scanSource, "applyMapScanHandoff")}
    const result=applyMapScanHandoff();
    return {result,classes:[...classes],scopeMode:$('scopeMode').value,targets:$('targets').value,scanName:$('scanName').value,selected:[...$('savedNetworkSelect').options].filter(option=>option.selected).map(option=>option.value),targetText:$('mapScanHandoffTarget').textContent,contextText:$('mapScanHandoffContext').textContent,scopeRefreshes,safetyRefreshes,draftSaves};
  })()`);
}

const exact = runScanHandoff(
  "?map_target=10.50.15.0%2F24&map_kind=subnet&map_label=AFB%20Dev&map_saved_network_id=saved-dev",
  [{saved_network_id:"saved-dev",name:"AFB Dev",cidr:"10.50.15.0/24"}],
);
assert.equal(exact.result,true);
assert.equal(exact.scopeMode,"saved");
assert.deepEqual(exact.selected,["saved-dev"]);
assert.equal(exact.targets,"");
assert.match(exact.contextText,/Exact active Saved Network/);
assert.equal(exact.targetText,"Selected subnet: AFB Dev · Target: 10.50.15.0/24");
assert.deepEqual([exact.scopeRefreshes,exact.safetyRefreshes,exact.draftSaves],[1,1,1]);

const labelAlreadyContainsTarget = runScanHandoff(
  "?map_target=10.50.15.0%2F24&map_kind=subnet&map_label=Unmapped%20Lab%20%C2%B7%2010.50.15.0%2F24&map_saved_network_id=saved-dev",
  [{saved_network_id:"saved-dev",name:"Unmapped Lab",cidr:"10.50.15.0/24"}],
);
assert.equal(labelAlreadyContainsTarget.targetText,"Selected subnet: Unmapped Lab · 10.50.15.0/24");

const stale = runScanHandoff(
  "?map_target=10.50.15.0%2F24&map_kind=subnet&map_label=AFB%20Dev&map_saved_network_id=archived",
  [{saved_network_id:"replacement",name:"Different exact record",cidr:"10.50.15.0/24"}],
);
assert.equal(stale.scopeMode,"manual");
assert.equal(stale.targets,"10.50.15.0/24");
assert.deepEqual(stale.selected,[],'a different record with the same CIDR is not inferred');
assert.match(stale.contextText,/prepared as a manual target/);
assert.match(stale.contextText,/reviewed Mission Environment scope/);

const invalid = runScanHandoff("?map_target=not-an-address&map_kind=device&map_label=Injected", []);
assert.equal(invalid.result,false);
assert.equal(invalid.targets,"prior draft",'invalid handoff data cannot replace the existing draft');
assert.equal(invalid.scopeRefreshes,0);
assert.ok(invalid.classes.includes("bad"));

function runScopeReview({mode="manual", selected=[], safety}) {
  const controls = new Map([
    ["networkScopeReview", {innerHTML:""}],
    ["scopeMode", {value:mode}],
    ["preview", {disabled:false}],
    ["generatePackage", {disabled:false}],
    ["runNow", {disabled:false}],
  ]);
  const $=id=>controls.get(id);
  const collectionSafety=safety;
  const missionEnvironment={tools:[],scopes:[{
    scope_id:"scope-active",scope_label:"Active mission",version:0,
    nmap_authorization:"authorized",arkime_coverage:"unknown",kibana_coverage:"unknown",
  }]};
  const sessionAnalyst={role:"analyst"};
  const activeCollectionEnabled=true;
  const selectedSavedNetworkRecords=()=>selected;
  const esc=value=>String(value??"").replace(/[&<>"']/g,character=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[character]);
  const updateSchedulePin=()=>{};
  return eval(`(() => {
    ${rawHandler(scanSource, "activeCollectionScope")}
    ${rawHandler(scanSource, "collectionScopeConflict")}
    ${rawHandler(scanSource, "missionScopeSnapshots")}
    ${rawHandler(scanSource, "missionCollectionBlocked")}
    ${rawHandler(scanSource, "collectionContactBlocked")}
    ${rawHandler(scanSource, "updateMissionActionState")}
    ${rawHandler(scanSource, "renderNetworkScopeReview")}
    renderNetworkScopeReview();
    return {html:$('networkScopeReview').innerHTML,runDisabled:$('runNow').disabled};
  })()`);
}

const readySafety={ready:true,scope:{scope_id:"scope-active",label:"Active mission",version:1},missing_checks:[]};
const manualReview=runScopeReview({safety:readySafety});
assert.match(manualReview.html,/Active mission/);
assert.match(manualReview.html,/manual target has no Saved Network association/);
assert.equal(manualReview.runDisabled,false);

const unassociatedNetwork={saved_network_id:"saved-unassociated",name:"Unassociated",network_scope_association:null};
const unassociatedReview=runScopeReview({mode:"saved",selected:[unassociatedNetwork],safety:readySafety});
assert.match(unassociatedReview.html,/no reusable association/);
assert.match(unassociatedReview.html,/still retain the reviewed active scope/);

const combinedReview=runScopeReview({mode:"combined",selected:[unassociatedNetwork],safety:readySafety});
assert.match(combinedReview.html,/Saved Networks and manual targets/);

const conflictReview=runScopeReview({mode:"saved",selected:[{
  saved_network_id:"saved-other",name:"Other mission",network_scope_association:{scope:{scope_id:"scope-other",label:"Other",active:true}},
}],safety:readySafety});
assert.match(conflictReview.html,/Collection scope:<\/strong> Blocked/);
assert.match(conflictReview.html,/does not match the active Mission Environment scope/);
assert.equal(conflictReview.runDisabled,true);

const incompleteReview=runScopeReview({safety:{ready:false,scope:null,missing_checks:["Global No-Strike review is missing"]}});
assert.match(incompleteReview.html,/Not ready/);
assert.match(incompleteReview.html,/Global No-Strike review is missing/);
assert.equal(incompleteReview.runDisabled,true);

console.log("Map-to-scan handoff runtime regression passed");
