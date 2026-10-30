import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/ui.py`);
  return match[0];
}

const esc = value => String(value ?? "");
const scanArtifactLabel = eval(`(${handler("scanArtifactLabel")})`);
const scanArtifactNote = eval(`(${handler("scanArtifactNote")})`);
const scanArtifactMarkup = eval(`(${handler("scanArtifactMarkup")})`);

assert.match(
  scanArtifactMarkup({name: "xml", download_url: "/aggregate"}),
  />Analysis-ready scan evidence \(XML\)</
);

for (const protocol of ["TCP", "UDP"]) {
  const name = protocol === "TCP" ? "tcp_xml" : "udp_xml";
  const run = {
    coverage: {protocols: [protocol]},
    artifacts: [{name}, {name: "xml"}],
    partial_results: false,
  };
  assert.equal(scanArtifactNote(run), "", `${protocol}-only evidence must not claim a combined run`);
}

const complete = {
  coverage: {protocols: ["TCP", "UDP"]},
  artifacts: [{name: "tcp_xml"}, {name: "udp_xml"}, {name: "xml"}],
  partial_results: false,
};
assert.match(scanArtifactNote(complete), /merges both completed phases/);
assert.doesNotMatch(scanArtifactNote(complete), /partial/i);

const partial = {
  coverage: {requested_protocols: ["TCP", "UDP"], protocols: ["TCP"]},
  artifacts: [{name: "tcp_xml"}, {name: "xml"}],
  partial_results: true,
};
assert.match(scanArtifactNote(partial), /TCP \+ UDP run is partial/);
assert.match(scanArtifactNote(partial), /only those completed phases/);

// Render real history details before clicking their new anchors. Calling the
// download function directly would miss the original missing-binding regression.
for (const outcome of ["success", "401", "404", "network", "body"]) {
  const requests = [], downloads = [], messages = [], timers = [], revoked = [];
  const parent = {nodes: [], querySelector(){return this.nodes.find(n=>n.dataset?.scanDownloadStatus!==undefined)||null},append(node){this.nodes.push(node)}};
  let anchors = [];
  const detail = {
    hidden: true, html: "",
    classList: {contains(){return detail.hidden},add(){detail.hidden=true},remove(){detail.hidden=false}},
    get innerHTML(){return this.html},
    set innerHTML(value){
      this.html=value;parent.nodes=[];
      anchors=[...value.matchAll(/<a href="([^"]*)" download data-scan-artifact="([^"]*)" data-artifact-name="([^"]*)">([^<]*)<\/a>/g)].map(match=>({
        dataset:{scanArtifact:match[2],artifactName:match[3]},textContent:match[4],parentElement:parent,attributes:{},
        setAttribute(k,v){this.attributes[k]=v},removeAttribute(k){delete this.attributes[k]}
      }));
    },
    querySelectorAll(){return anchors}
  };
  const document = {
    querySelectorAll(){return [detail]},
    body:{append(){}},
    createElement(tag){
      return {dataset:{},attributes:{},setAttribute(k,v){this.attributes[k]=v},remove(){},click(){downloads.push({href:this.href,name:this.download})}};
    }
  };
  const button={closest:()=>({querySelector:()=>detail})};
  const blob=new Blob(["<nmaprun/>"],{type:"application/xml"});
  const context={document,Blob,console,encodeURIComponent,
    esc,scanRef:()=>({primary:"Retained scan",detail:"Original retained evidence"}),scanTime:v=>v,
    status:(...args)=>messages.push(args),
    setTimeout:(fn,ms)=>timers.push({fn,ms}),
    URL:{createObjectURL(value){assert.equal(value,blob);return "blob:test-xml"},revokeObjectURL:v=>revoked.push(v)},
    fetch:async(url,options)=>{
      requests.push({url,options});
      if(url==="/api/scan-runs/retained-run")return {ok:true,json:async()=>({run_id:"retained-run",status:"completed",created_at:"2026-10-29",artifacts:[{name:"xml",download_url:"/api/scan-runs/retained-run/artifacts/xml"}]})};
      if(outcome==="network")throw Error("Network connection lost");
      const ok=outcome==="success"||outcome==="body";
      return {ok,status:Number(outcome)||200,json:async()=>({detail:outcome==="401"?"Sign in again":"Artifact not found"}),
        headers:{get:()=> 'attachment; filename="retained-run-scan.xml"'},
        blob:async()=>{if(outcome==="body")throw Error("Evidence body interrupted");return blob}};
    }
  };
  vm.createContext(context);
  vm.runInContext(["scanArtifactLabel","scanArtifactNote","scanArtifactMarkup","scanArtifactStatus","saveScanArtifact","bindScanArtifactDownloads","selectRun"].map(handler).join("\n"),context);
  await context.selectRun("retained-run",button);
  let link=anchors[0];
  assert.equal(typeof link.onclick,"function","newly rendered history evidence must use the download handler");
  let prevented=false;
  await link.onclick({currentTarget:link,preventDefault(){prevented=true}});
  assert.ok(prevented,"prevent the native URL download path");
  assert.equal(requests[1].url,"/api/scan-runs/retained-run/artifacts/xml");
  assert.equal(requests[1].options.credentials,"same-origin");
  assert.equal(link.textContent,"Analysis-ready scan evidence (XML)");
  assert.equal(link.attributes["aria-busy"],undefined);
  assert.equal(messages.length,0,"history download messages must not target the hidden builder");
  const notice=parent.nodes[0];assert.ok(notice,"feedback must be beside the evidence links");
  assert.equal(notice.attributes.role,"status");assert.equal(notice.attributes["aria-live"],"polite");
  if(outcome==="success"){
    assert.deepEqual(downloads,[{href:"blob:test-xml",name:"retained-run-scan.xml"}]);
    assert.match(notice.textContent,/prepared|ready to save/i);
    assert.doesNotMatch(notice.textContent,/successfully saved|saved to disk/i);
    assert.equal(timers.length,1);assert.equal(timers[0].ms,30000);assert.equal(revoked.length,0);
    timers[0].fn();assert.deepEqual(revoked,["blob:test-xml"]);
  } else {
    assert.equal(downloads.length,0);assert.equal(timers.length,0);
    assert.match(notice.className,/bad/);
    assert.match(notice.textContent,/Sign in again|Artifact not found|Network connection lost|Evidence body interrupted/);
  }
  await context.selectRun("retained-run",button);assert.ok(detail.hidden);
  await context.selectRun("retained-run",button);
  assert.notEqual(anchors[0],link,"reopening creates a fresh anchor");
  assert.equal(typeof anchors[0].onclick,"function","fresh anchors must also be bound");
}

console.log("Scan artifact UI runtime regressions passed");
