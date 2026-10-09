import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/analysis_ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^async function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/analysis_ui.py`);
  return match[0];
}

function syncHandler(name) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/analysis_ui.py`);
  return match[0];
}

await eval([
  "(() => {",
  syncHandler("processedEvidenceMacs"),
  "const facts={addresses:[",
  "{addrtype:'mac',addr:'001122334455'},",
  "{addrtype:'mac',addr:'00:11:22:33:44:55'},",
  "{addrtype:'mac',addr:'00-11-22-33-44-66'},",
  "{addrtype:'mac',addr:'0011.2233.4477'},",
  "{addrtype:'mac',addr:'00ZZ11ZZ22ZZ33ZZ44ZZ55'},",
  "{addrtype:'mac',addr:'00/11/22/33/44/88'},",
  "{addrtype:'mac',addr:'01:11:22:33:44:99'},",
  "]};",
  "assert.deepEqual(processedEvidenceMacs(facts).map(item=>item.normalized),[",
  "'00:11:22:33:44:55','00:11:22:33:44:66','00:11:22:33:44:77',",
  "]);",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "const scope={value:'scope-a'},target={dataset:{},innerHTML:'',isConnected:true};",
  "const receipt={querySelector:()=>target};",
  "const button={dataset:{mac:'00:11:22:33:44:55'},disabled:false,textContent:'',closest:()=>receipt};",
  "const $=()=>scope,esc=value=>String(value),renders=[],pending=[];",
  "const renderMacAssociations=(control,node,data)=>renders.push(data.marker);",
  "const fetch=url=>new Promise(resolve=>pending.push({url,resolve}));",
  handler("openMacAssociations"),
  "const older=openMacAssociations(button,0,'');",
  "button.dataset.mac='00:11:22:33:44:66';",
  "const newer=openMacAssociations(button,0,'');",
  "pending[1].resolve({ok:true,json:async()=>({marker:'newer'})});",
  "await newer;",
  "pending[0].resolve({ok:true,json:async()=>({marker:'older'})});",
  "await older;",
  "assert.deepEqual(renders,['newer'],'a delayed MAC result must not replace the latest request');",
  "assert.ok(pending[0].url.includes('mac=00%3A11%3A22%3A33%3A44%3A55'));",
  "assert.ok(pending[1].url.includes('mac=00%3A11%3A22%3A33%3A44%3A66'));",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  "const scope={value:'scope-a'},target={dataset:{},innerHTML:'',isConnected:true};",
  "const receipt={querySelector:()=>target};",
  "const button={dataset:{mac:'00:11:22:33:44:55'},disabled:false,textContent:'',closest:()=>receipt};",
  "const $=()=>scope,esc=value=>String(value),renders=[],pending=[];",
  "const renderMacAssociations=(control,node,data)=>renders.push(data.marker);",
  "const fetch=url=>new Promise(resolve=>pending.push({url,resolve}));",
  handler("openMacAssociations"),
  "const request=openMacAssociations(button,25,'a'.repeat(64));",
  "scope.value='scope-b';",
  "pending[0].resolve({ok:true,json:async()=>({marker:'stale-scope'})});",
  "await request;",
  "assert.deepEqual(renders,[],'a response from the previously selected scope must not render');",
  "assert.ok(pending[0].url.includes('offset=25'));",
  "assert.ok(pending[0].url.includes(`selection_revision=${'a'.repeat(64)}`));",
  "})()",
].join("\n"));

console.log("MAC association UI stale-response regression passed");
