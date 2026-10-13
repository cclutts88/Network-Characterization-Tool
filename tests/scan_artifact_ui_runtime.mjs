import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
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

console.log("Scan artifact UI runtime regressions passed");
