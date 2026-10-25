import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/reachability_ui.py", import.meta.url), "utf8");

function handler(name, asyncFunction = false) {
  const prefix = asyncFunction ? "async function" : "function";
  const match = source.match(new RegExp(`^${prefix} ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/reachability_ui.py`);
  return match[0].replaceAll("{{", "{").replaceAll("}}", "}");
}

function node(value = "") {
  const classes = new Set(["hidden"]);
  return {
    value,
    textContent: "",
    innerHTML: "",
    className: "",
    disabled: false,
    classList: {
      add: value => classes.add(value),
      remove: value => classes.delete(value),
      contains: value => classes.has(value),
      toggle: (value, force) => {
        const next = force === undefined ? !classes.has(value) : Boolean(force);
        if (next) classes.add(value); else classes.delete(value);
        return next;
      },
    },
  };
}

await eval(`(async () => {
  let currentPolicyContext=null,policyRuleDirty=false,policyContextRequestRevision=0,policyTemplateRequestRevision=0;
  let latestScenario=null,scenarioRequestRevision=0;
  const controls=new Map();
  for(const id of ['simulationDevice','simulationInterface','simulationLocalAddress','simulationTemplate','simulationPosition','simulationExistingRules','simulationRule','simulationRuleHint','generatePolicyRule','scenarioStatus','scenarioSource','scenarioDestination','scenarioTrafficTarget','scenarioProtocol','scenarioPort','scenarioFlowState','scenarioSourceExternal','simulationAction','scenarioResult','exportScenario','showScenarioOnMap','simulateScenario'])controls.set(id,node());
  const $=id=>{assert.ok(controls.has(id),'unknown DOM id: '+id);return controls.get(id)};
  $('scenarioSource').value='10.0.0.2';$('scenarioDestination').value='10.20.0.10';$('scenarioTrafficTarget').value='forwarded';$('scenarioProtocol').value='tcp';$('scenarioPort').value='443';$('scenarioFlowState').value='new';$('scenarioSourceExternal').checked=false;$('simulationAction').value='deny';$('simulationTemplate').value='exact-service';$('simulationPosition').value='0';
  const reachDevices=[
    {run_id:'run-a',name:'Device A',address:'10.0.0.1'},
    {run_id:'run-b',name:'Device B',address:'10.0.0.2'},
  ];
  const requests=[];
  const fetch=(url,options={})=>new Promise(resolve=>requests.push({url,options,resolve}));
  const responseData=async response=>response.data;
  const encodeURIComponent=value=>String(value);
  const esc=value=>String(value??'');
  ${handler("selectedPolicyDevice")}
  ${handler("renderExistingPolicyRules")}
  ${handler("clearPolicyWorkspace")}
  ${handler("policyTemplateBody")}
  ${handler("invalidateScenarioResult")}
  ${handler("loadPolicyContext", true)}
  ${handler("generatePolicyRule", true)}

  $('simulationDevice').value='10.0.0.1';
  const older=loadPolicyContext();
  $('simulationDevice').value='10.0.0.2';
  const newer=loadPolicyContext();
  requests[1].resolve({ok:true,data:{vendor:'cisco',device:{name:'Device B'},interfaces:[{name:'B-in',address:'10.0.0.2/24'}],templates:[{id:'exact-service',name:'B template'}],positions:[{index:0,label:'First rule'}],rules:[{position:1,action:'permit',policy:'B policy',evidence:'B rule'}]}});
  await newer;
  requests[0].resolve({ok:true,data:{vendor:'vyos',device:{name:'Device A'},interfaces:[{name:'A-in',address:'10.0.0.1/24'}],templates:[{id:'exact-service',name:'A template'}],positions:[{index:0,label:'First rule'}],rules:[]}});
  await older;
  assert.equal(currentPolicyContext.device.name,'Device B','older context must not replace the selected device');
  assert.match($('simulationInterface').innerHTML,/B-in/);
  assert.doesNotMatch($('simulationInterface').innerHTML,/A-in/);
  assert.match($('scenarioStatus').textContent,/Loaded Device B/);

  $('simulationInterface').value='B-in';
  $('simulationRule').value='CUSTOM B RULE';
  latestScenario={status:'complete'};
  $('scenarioResult').classList.remove('hidden');
  $('exportScenario').disabled=false;
  $('showScenarioOnMap').disabled=false;
  const regeneratedForB=generatePolicyRule();
  requests[2].resolve({ok:true,data:{vendor:'cisco',placement:'First rule',rule_text:'GENERATED B RULE'}});
  await regeneratedForB;
  assert.equal($('simulationRule').value,'GENERATED B RULE');
  assert.equal(latestScenario,null,'generating a replacement rule invalidates the completed scenario');
  assert.equal($('scenarioResult').classList.contains('hidden'),true);
  assert.equal($('exportScenario').disabled,true);
  assert.equal($('showScenarioOnMap').disabled,true);

  const generatedForB=generatePolicyRule();
  assert.equal(requests[3].url,'/api/reachability/policy-template');
  $('simulationDevice').value='10.0.0.1';
  const switchedBack=loadPolicyContext();
  requests[4].resolve({ok:true,data:{vendor:'cisco',device:{name:'Device A'},interfaces:[{name:'A-in',address:'10.0.0.1/24'}],templates:[{id:'exact-service',name:'A template'}],positions:[{index:0,label:'First rule'}],rules:[]}});
  await switchedBack;
  requests[3].resolve({ok:true,data:{vendor:'cisco',placement:'First rule',rule_text:'STALE B RULE'}});
  await generatedForB;
  assert.equal(currentPolicyContext.device.name,'Device A');
  assert.equal($('simulationRule').value,'','a rule generated for the previous device must be discarded');
  assert.equal($('generatePolicyRule').disabled,false,'changing device must release the generate action');
})()`);

await eval(`(() => {
  let latestScenario={status:'complete'},scenarioRequestRevision=4;
  const controls=new Map();
  for(const id of ['scenarioResult','exportScenario','showScenarioOnMap','simulateScenario','scenarioStatus'])controls.set(id,node());
  controls.get('scenarioResult').classList.remove('hidden');
  controls.get('exportScenario').disabled=false;
  controls.get('showScenarioOnMap').disabled=false;
  const $=id=>controls.get(id);
  ${handler("invalidateScenarioResult")}
  invalidateScenarioResult();
  assert.equal(latestScenario,null);
  assert.equal(scenarioRequestRevision,5);
  assert.equal($('scenarioResult').classList.contains('hidden'),true);
  assert.equal($('exportScenario').disabled,true);
  assert.equal($('showScenarioOnMap').disabled,true);
  assert.match($('scenarioStatus').textContent,/inputs changed/i);
  assert.equal($('simulateScenario').textContent,'Reassess proposed scenario');
})()`);

await eval(`(async () => {
  let latestScenario=null,scenarioRequestRevision=0;
  const controls=new Map();
  for(const id of ['scenarioSource','scenarioDestination','scenarioTrafficTarget','simulationLocalAddress','scenarioProtocol','scenarioPort','scenarioFlowState','scenarioSourceExternal','simulationAction','simulationDevice','simulationInterface','simulationPosition','simulationTemplate','simulationRule','routeSimulationAction','routeSimulationDevice','routeSimulationNetwork','routeSimulationInterface','routeSimulationNextHop','routeSimulationPriorityKind','routeSimulationPriorityValue','scenarioStatus','simulateScenario','scenarioResult','scenarioBefore','scenarioAfterRoute','scenarioAfterPolicy','scenarioValidation','scenarioExplanation','scenarioPlacement','scenarioValidatedRule','scenarioScope','scenarioPath','scenarioImpact','scenarioEvidence','scenarioCaveats','scenarioRouteArrow','scenarioRouteResult','exportScenario','showScenarioOnMap'])controls.set(id,node());
  const $=id=>{assert.ok(controls.has(id),'unknown DOM id: '+id);return controls.get(id)};
  Object.assign($('scenarioSource'),{value:'10.0.0.2'});Object.assign($('scenarioDestination'),{value:'10.20.0.10'});Object.assign($('scenarioTrafficTarget'),{value:'forwarded'});Object.assign($('scenarioProtocol'),{value:'tcp'});Object.assign($('scenarioPort'),{value:'443'});Object.assign($('scenarioFlowState'),{value:'new'});$('scenarioSourceExternal').checked=false;Object.assign($('simulationAction'),{value:'deny'});Object.assign($('simulationDevice'),{value:'edge'});Object.assign($('simulationInterface'),{value:'inside'});Object.assign($('simulationPosition'),{value:'0'});Object.assign($('simulationTemplate'),{value:'exact-service'});Object.assign($('simulationRule'),{value:'CUSTOM RULE'});Object.assign($('routeSimulationAction'),{value:'add'});Object.assign($('routeSimulationDevice'),{value:'edge'});Object.assign($('routeSimulationNetwork'),{value:'10.20.0.10/32'});Object.assign($('routeSimulationInterface'),{value:'outside'});Object.assign($('routeSimulationNextHop'),{value:''});Object.assign($('routeSimulationPriorityKind'),{value:'metric'});Object.assign($('routeSimulationPriorityValue'),{value:'100'});
  const requests=[];
  const fetch=(url,options={})=>new Promise(resolve=>requests.push({url,options,resolve}));
  const responseData=async response=>response.data;
  const esc=value=>String(value??'');
  const routeIdentity=()=>'';
  const reportEvidence=()=>'';
  ${handler("policyTemplateBody")}
  ${handler("routeScenarioBody")}
  ${handler("scenarioCheck")}
  ${handler("invalidateScenarioResult")}
  ${handler("simulateScenario", true)}
  const pending=simulateScenario();
  assert.equal($('simulateScenario').disabled,true);
  $('simulationRule').value='REPLACED RULE';
  invalidateScenarioResult();
  requests[0].resolve({ok:true,data:{comparison:{after:'Expected Blocked'},projected:{},policy_proposal:{},validation:[],disclaimer:'OLD RESULT'}});
  await pending;
  assert.equal(latestScenario,null,'a delayed scenario response must not return after its rule changes');
  assert.equal($('scenarioResult').classList.contains('hidden'),true);
  assert.equal($('exportScenario').disabled,true);
  assert.match($('scenarioStatus').textContent,/inputs changed/i);
})()`);

await eval(`(async () => {
  let latestScenario=null,scenarioRequestRevision=0;
  const controls=new Map();
  for(const id of ['scenarioSource','scenarioDestination','scenarioTrafficTarget','simulationLocalAddress','scenarioProtocol','scenarioPort','scenarioFlowState','scenarioSourceExternal','simulationAction','simulationDevice','simulationInterface','simulationPosition','simulationTemplate','simulationRule','routeSimulationAction','routeSimulationDevice','routeSimulationNetwork','routeSimulationInterface','routeSimulationNextHop','routeSimulationPriorityKind','routeSimulationPriorityValue','scenarioStatus','simulateScenario','scenarioResult','scenarioBefore','scenarioAfterRoute','scenarioAfterPolicy','scenarioValidation','scenarioExplanation','scenarioPlacement','scenarioValidatedRule','scenarioScope','scenarioPath','scenarioImpact','scenarioEvidence','scenarioCaveats','scenarioRouteArrow','scenarioRouteResult','exportScenario','showScenarioOnMap'])controls.set(id,node());
  const $=id=>{assert.ok(controls.has(id),'unknown DOM id: '+id);return controls.get(id)};
  Object.assign($('scenarioSource'),{value:'Internet'});Object.assign($('scenarioDestination'),{value:'198.51.100.1'});Object.assign($('scenarioTrafficTarget'),{value:'router_local'});Object.assign($('simulationLocalAddress'),{value:'198.51.100.1'});Object.assign($('scenarioProtocol'),{value:'tcp'});Object.assign($('scenarioPort'),{value:'22'});Object.assign($('scenarioFlowState'),{value:'new'});$('scenarioSourceExternal').checked=true;Object.assign($('simulationAction'),{value:'deny'});Object.assign($('simulationDevice'),{value:'edge'});Object.assign($('simulationInterface'),{value:'outside'});Object.assign($('simulationPosition'),{value:'0'});Object.assign($('simulationTemplate'),{value:'exact-service'});Object.assign($('simulationRule'),{value:'LOCAL ACL'});
  const fetch=async (url,options={})=>{
    const body=JSON.parse(options.body);
    assert.equal(url,'/api/reachability/simulate-change-scenario');
    assert.equal(body.route,null,'router-local assessment must not submit a route change');
    assert.equal(body.policy.traffic_target,'router_local');
    assert.equal(body.destination,'198.51.100.1');
    return {ok:true,data:{comparison:{before:'Unknown',after_route:null,after:'Expected Blocked',intent_achieved:true,policy_on_projected_path:true,scope:{source_addresses:null,destination_addresses:1,protocol:'tcp',port:22},collateral_impact:{summary:'exact address'}},projected:{explanation:'Modeled local block',evidence:[],caveats:[]},policy_proposal:{vendor:'cisco',traffic_target:'router_local',policy_plane:'Local input / management plane',interface:'outside',destination:'198.51.100.1',placement:'First rule',rule_text:'LOCAL ACL'},validation:[],disclaimer:'Not applied'}};
  };
  const responseData=async response=>response.data;
  const esc=value=>String(value??'');
  const routeIdentity=()=>'';
  const reportEvidence=()=>'';
  ${handler("policyTemplateBody")}
  ${handler("routeScenarioBody")}
  ${handler("scenarioCheck")}
  ${handler("simulateScenario", true)}
  await simulateScenario();
  assert.equal(latestScenario.comparison.after,'Expected Blocked');
  assert.equal($('scenarioRouteResult').classList.contains('hidden'),true);
  assert.equal($('scenarioRouteArrow').classList.contains('hidden'),true);
  assert.equal($('showScenarioOnMap').disabled,true);
  assert.match($('scenarioPlacement').textContent,/NOT APPLIED/);
  assert.match($('scenarioPath').textContent,/no forwarding route/);
})()`);

await eval(`(() => {
  let latestScenario={status:'complete'},scenarioRequestRevision=0;
  const controls=new Map();
  for(const id of ['scenarioSource','scenarioDestination','scenarioTrafficTarget','simulationLocalAddress','scenarioProtocol','scenarioPort','scenarioFlowState','scenarioSourceExternal','scenarioFlowContext','scenarioRouteStage','scenarioDestinationControl','simulationLocalAddressControl','policyStepNumber','policyStepHelp','scenarioRouteArrow','scenarioRouteResult','routeSimulationDevice','routeSimulationNetwork','routeSimulationInterface','routeSimulationNextHop','scenarioResult','scenarioStatus','exportScenario','showScenarioOnMap','simulateScenario'])controls.set(id,node());
  const $=id=>{assert.ok(controls.has(id),'unknown DOM id: '+id);return controls.get(id)};
  Object.assign($('scenarioSource'),{value:'Internet'});Object.assign($('scenarioDestination'),{value:'198.51.100.1'});Object.assign($('scenarioTrafficTarget'),{value:'forwarded'});Object.assign($('simulationLocalAddress'),{value:'198.51.100.1'});Object.assign($('scenarioProtocol'),{value:'tcp'});Object.assign($('scenarioPort'),{value:'22'});Object.assign($('scenarioFlowState'),{value:'new'});$('scenarioSourceExternal').checked=true;Object.assign($('routeSimulationDevice'),{value:'edge'});Object.assign($('routeSimulationNetwork'),{value:'198.51.100.1/32'});Object.assign($('routeSimulationInterface'),{value:'outside'});Object.assign($('routeSimulationNextHop'),{value:'198.51.100.254'});
  const esc=value=>String(value??'');
  const loadPolicyContext=()=>{};
  ${handler("invalidateScenarioResult")}
  ${handler("syncScenarioFlow")}
  ${handler("syncScenarioMode")}
  syncScenarioMode();
  assert.equal($('scenarioDestination').value,'','switching from a local address must clear the forwarded destination');
  assert.equal($('routeSimulationDevice').value,'');
  assert.equal($('routeSimulationNetwork').value,'');
  assert.equal($('routeSimulationNextHop').value,'');
  assert.match($('scenarioFlowContext').innerHTML,/Traffic is not complete/);
  assert.doesNotMatch($('scenarioFlowContext').innerHTML,/Forwarded traffic ready/);
  $('scenarioDestination').value='203.0.113.25';
  syncScenarioFlow();
  assert.match($('scenarioFlowContext').innerHTML,/Choose a route device and exact route network/);
  $('routeSimulationDevice').value='edge';
  syncScenarioFlow();
  assert.match($('scenarioFlowContext').innerHTML,/Forwarded traffic ready to validate/);
})()`);

console.log("Reach proposed-policy UI runtime regressions passed");
