import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/analysis_ui.py", import.meta.url), "utf8");
const revisionA = "a".repeat(64);
const revisionB = "b".repeat(64);

function handler(name) {
  const match = source.match(new RegExp(`^async function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/analysis_ui.py`);
  return match[0];
}

function namedFunction(name, esc) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/analysis_ui.py`);
  return Function("esc", `return (${match[0]})`)(esc);
}

{
  const esc = value => String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
  const hostnameEvidence = namedFunction("hostnameEvidence", esc);
  assert.equal(hostnameEvidence({}), "");
  assert.equal(
    hostnameEvidence({analyst_hostname:{hostname:"branch-office",source_filename:"analyst & notes.csv"}}),
    '<span class="hostname-origin">Analyst hostname · analyst &amp; notes.csv</span>',
  );
  assert.equal(
    hostnameEvidence({hostname_conflict:true,analyst_hostname:{hostname:"alias <one>",source_filename:"source.csv"}}),
    '<span class="hostname-origin conflict" title="Scanner hostname retained">Imported alias: alias &lt;one&gt; · source.csv</span>',
  );
}

await eval([
  "(async () => {",
  `let currentNetwork={source_revision:${JSON.stringify(revisionA)}},networkPage=1,networkRequest=0;`,
  "const controls={networkPageSize:{value:'25'},networkSearch:{value:'first'},networkSubnet:{value:''},networkFocus:{value:'ip'},networkOverview:{classList:{remove:()=>{}}},networkStatus:{}};",
  "const $=id=>controls[id];",
  "const statuses=[],renders=[],pending=[];",
  "const setStatus=(id,message,kind='')=>statuses.push({id,message,kind});",
  "const renderNetworkOverview=data=>renders.push(data.marker);",
  "const fetch=url=>new Promise(resolve=>pending.push({url,resolve}));",
  handler("loadNetworkPage"),
  "const older=loadNetworkPage(1);",
  "controls.networkSearch.value='second';",
  "const newer=loadNetworkPage(1);",
  `pending[1].resolve({status:200,ok:true,json:async()=>({marker:'newer',pagination:{limit:25,offset:0},source_revision:${JSON.stringify(revisionA)}})});`,
  "await newer;",
  `pending[0].resolve({status:200,ok:true,json:async()=>({marker:'older',pagination:{limit:25,offset:0},source_revision:${JSON.stringify(revisionA)}})});`,
  "await older;",
  "assert.deepEqual(renders,['newer'],'a delayed older filter response must not replace the latest page');",
  "assert.ok(pending[0].url.includes('search=first'));",
  "assert.ok(pending[1].url.includes('search=second'));",
  "assert.ok(pending[0].url.includes('revision='));",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  `let currentNetwork={source_revision:${JSON.stringify(revisionA)}},networkPage=3,networkRequest=0;`,
  "const controls={networkPageSize:{value:'25'},networkSearch:{value:''},networkSubnet:{value:''},networkFocus:{value:'ip'},networkOverview:{classList:{remove:()=>{}}},networkStatus:{}};",
  "const $=id=>controls[id];",
  "const renders=[],urls=[];",
  "const setStatus=()=>{};",
  "const renderNetworkOverview=data=>renders.push(data.marker);",
  `const responses=[{status:409,ok:false,json:async()=>({detail:'changed'})},{status:200,ok:true,json:async()=>({marker:'refreshed',pagination:{limit:25,offset:0},source_revision:${JSON.stringify(revisionB)}})}];`,
  "const fetch=async url=>{urls.push(url);return responses.shift();};",
  handler("loadNetworkPage"),
  "await loadNetworkPage(3);",
  "assert.deepEqual(renders,['refreshed']);",
  "assert.ok(urls[0].includes('offset=50'));",
  "assert.ok(urls[0].includes('revision='));",
  "assert.ok(urls[1].includes('offset=0'));",
  "assert.ok(!urls[1].includes('revision='),'stale refresh must establish a fresh exact-source revision');",
  "})()",
].join("\n"));

await eval([
  "(async () => {",
  `let currentNetwork={source_revision:${JSON.stringify(revisionA)}},networkLfaRequest=0;`,
  "const controls={networkOutliersPanel:{open:true},lfaThreshold:{value:'20',setAttribute:()=>{}},networkSubnet:{value:''},networkOutliersResult:{innerHTML:''}};",
  "const $=id=>controls[id];",
  "const esc=value=>String(value);",
  "let revisionSeenByRefresh='not called',refreshes=0;",
  `const loadNetworkPage=async()=>{revisionSeenByRefresh=currentNetwork;refreshes+=1;currentNetwork={source_revision:${JSON.stringify(revisionB)}};};`,
  "const renderNetworkOutliers=()=>{throw new Error('stale LFA response must not render');};",
  "const fetch=async()=>({status:409,ok:false,json:async()=>({detail:'changed'})});",
  handler("loadNetworkOutliers"),
  "await loadNetworkOutliers();",
  "assert.equal(revisionSeenByRefresh,null,'LFA stale recovery must clear the old revision before refreshing page one');",
  "assert.equal(refreshes,1);",
  `assert.equal(currentNetwork.source_revision,${JSON.stringify(revisionB)});`,
  "})()",
].join("\n"));

assert.ok(source.includes("/api/analysis/network/page?${params}"));
assert.ok(source.includes("/api/analysis/network/outliers?${params}"));
assert.ok(source.includes("/api/analysis/network/ips?${params}"));
assert.ok(!source.includes("fetch('/api/analysis/network')"));
console.log("Current Network server paging runtime regression passed");
