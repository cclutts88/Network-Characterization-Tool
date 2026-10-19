import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/analysis_ui.py", import.meta.url), "utf8");
const match = source.match(/^function renderNetworkChangeScope\(.*$/m);
assert.ok(match, "Could not find renderNetworkChangeScope in app/analysis_ui.py");

const esc = value => String(value ?? "");
const networkChangeScopeLabel = () => "Lab scope";
const scanRef = value => ({selection: value?.selection || "saved source"});
const evidenceLinks = () => "<span>evidence-link</span>";
const renderHostSnapshot = () => "";
const renderChangedHost = () => "";
const comparisonHostName = host => host.ip || host.key || "Unknown address";
const renderNetworkChangeScope = Function(
  "esc", "networkChangeScopeLabel", "scanRef", "evidenceLinks",
  "renderHostSnapshot", "renderChangedHost", "comparisonHostName",
  `return (${match[0]})`,
)(esc, networkChangeScopeLabel, scanRef, evidenceLinks,
  renderHostSnapshot, renderChangedHost, comparisonHostName);

const html = renderNetworkChangeScope({
  status: "comparison_complete",
  before: {selection: "Earlier"},
  after: {selection: "Later"},
  summary: {
    hosts_added: 0,
    hosts_removed: 0,
    hosts_changed: 0,
    routes_not_assessed: 1,
  },
  path_assessments_not_assessed: [{
    key: "192.0.2.10",
    ip: "192.0.2.10",
    route_assessment: {reason: "The later saved source did not retain a complete ordered traceroute path."},
    evidence: {},
  }],
});

assert.match(html, /1 paths not assessed/);
assert.match(html, /Traceroute paths not assessed/);
assert.match(html, /192\.0\.2\.10/);
assert.match(html, /Some traceroute paths were not assessed/);
assert.doesNotMatch(html, /No source-reported host, port, service, product, version, address attribute, MAC, OS, or path changes were detected/);
console.log("Network changes path-assessment UI runtime regression passed");
