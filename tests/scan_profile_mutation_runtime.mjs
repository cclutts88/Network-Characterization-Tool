import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/ui.py`);
  return match[0];
}

await eval([
  "(async () => {",
  "let selectedProfile={profile_id:'custom-one',version:1,name:'Custom one',built_in:false},profileMutationInFlight=false,profileEditRevision=0;",
  "const profileRetryTokens=new Map();let sessionAnalyst={username:'analyst01'};",
  "const classList=()=>({values:new Set(),add(value){this.values.add(value)},remove(value){this.values.delete(value)},contains(value){return this.values.has(value)}});",
  "const nodes={profileManagementPanel:{attributes:{},setAttribute(key,value){this.attributes[key]=value},removeAttribute(key){delete this.attributes[key]}},profileStatus:{textContent:'',className:''},profileScheduleLink:{disabled:false,classList:classList()},saveProfile:{disabled:false},saveVersion:{disabled:false},cloneProfile:{disabled:false},deleteProfile:{disabled:false,textContent:'',title:''},profileName:{value:'Mission profile'},scanName:{value:'Authorized scan'},profileSelect:{value:'custom-one:1'}};",
  "const $=id=>nodes[id],updateSchedulePin=()=>{},auditActor=()=>sessionAnalyst.username,settings=()=>({protocol:'tcp',tcp_scope:'common'});",
  "const crypto={counter:0,randomUUID(){this.counter+=1;return `00000000-0000-4000-8000-${String(this.counter).padStart(12,'0')}`}};",
  "let fetchCalls=[],loadCalls=[],resolveFetch,loadProfiles=async(selectId,options)=>{loadCalls.push({selectId,options})};",
  "let fetch=async(url,options)=>{fetchCalls.push({url,options});return new Promise(resolve=>{resolveFetch=resolve})};",
  handler("profileStatus"),
  handler("apiMessage"),
  handler("newProfileRequestToken"),
  handler("profileRequestToken"),
  handler("beginProfileMutation"),
  handler("endProfileMutation"),
  handler("refreshProfilesAfterMutation"),
  handler("updateProfileButtons"),
  handler("saveProfile"),
  "const first=saveProfile();const duplicate=saveProfile();",
  "await Promise.resolve();await Promise.resolve();",
  "assert.equal(fetchCalls.length,1,'a rapid repeated click must submit only once');",
  "assert.equal(profileMutationInFlight,true);assert.equal(nodes.profileManagementPanel.attributes['aria-busy'],'true');",
  "assert.ok([nodes.saveProfile,nodes.saveVersion,nodes.cloneProfile,nodes.deleteProfile].every(node=>node.disabled),'all profile actions stay disabled while saving');",
  "profileEditRevision+=1;nodes.profileName.value='Newer unsaved name';",
  "resolveFetch({ok:true,json:async()=>({profile_id:'saved-one',version:1,name:'Mission profile',request_replayed:false})});",
  "await first;await duplicate;",
  "assert.equal(loadCalls.length,1);assert.equal(loadCalls[0].options.applySelection,false,'a delayed response must not overwrite newer edits');",
  "assert.equal(loadCalls[0].options.preserveValue,'custom-one:1');",
  "assert.match(nodes.profileStatus.textContent,/newer builder edits were kept/);",
  "assert.equal(profileMutationInFlight,false);assert.ok([nodes.saveProfile,nodes.saveVersion,nodes.cloneProfile,nodes.deleteProfile].every(node=>!node.disabled));",
  "assert.equal(profileRetryTokens.size,0);",
  "fetchCalls=[];nodes.profileName.value='Retry profile';loadProfiles=async()=>{};let failOnce=true;",
  "fetch=async(url,options)=>{fetchCalls.push({url,options});if(failOnce){failOnce=false;throw new TypeError('connection lost')}return{ok:true,json:async()=>({profile_id:'retry-one',version:1,name:'Retry profile',request_replayed:true})}};",
  "await saveProfile();assert.match(nodes.profileStatus.textContent,/Retry the same save/);assert.equal(profileRetryTokens.size,1);",
  "await saveProfile();assert.equal(fetchCalls.length,2);",
  "const retryBodies=fetchCalls.map(call=>JSON.parse(call.options.body));assert.equal(retryBodies[0].request_token,retryBodies[1].request_token,'an uncertain retry must reuse the same server request token');",
  "assert.match(nodes.profileStatus.textContent,/Confirmed the earlier completed request/);assert.equal(profileRetryTokens.size,0);",
  "nodes.profileName.value='Refresh failure profile';loadProfiles=async()=>{throw new Error('refresh unavailable')};",
  "fetch=async()=>({ok:true,json:async()=>({profile_id:'refresh-one',version:1,name:'Refresh failure profile',request_replayed:false})});",
  "await saveProfile();assert.match(nodes.profileStatus.textContent,/save completed, but the profile list could not refresh/i);assert.match(nodes.profileStatus.className,/warn/);",
  "assert.equal(profileMutationInFlight,false);",
  "})()",
].join("\n"));

console.log("Scan profile mutation UI runtime regression passed");
