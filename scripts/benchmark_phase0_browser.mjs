/** Run one real-browser Phase 0 benchmark repeat against a prepared NCT container. */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

export const RUNNER_VERSION = "phase0-rendered-browser:2";
export const EXPECTED_COMMON = Object.freeze({
  host_count: 4188,
  finding_count: 6125,
  ordered_host_addresses_sha256: "09dcf4ae04213b940e824b8aeaf73ac0b71db509f46dd3fef26d7e558e2325b1",
  map: Object.freeze({
    stable: Object.freeze({devices: 1, gateways: 1, interfaces: 2, subnets: 2, hosts: 4188, relationships: 47, nmap_records_read: 4315, configuration_records_read: 4, mac_observations: 4315, mac_identified_hosts: 4188, mac_conflicts: 0, arp_neighbors: 0, topology_neighbors: 0, switchport_links: 0}),
    foundation: Object.freeze({devices: 1, gateways: 0, interfaces: 1000, subnets: 0, hosts: 4188, relationships: 1041, nmap_records_read: 4315, configuration_records_read: 4, mac_observations: 4315, mac_identified_hosts: 4188, mac_conflicts: 0, arp_neighbors: 0, topology_neighbors: 0, switchport_links: 0}),
  }),
});
export const ABSOLUTE_LIMITS = Object.freeze({
  common_action_to_ready_ms: 30000,
  foundation_action_to_ready_ms: 15000,
  navigation_load_event_ms: 30000,
  longest_task_ms: 2500,
  long_task_total_ms: 5000,
  dom_nodes: 175000,
  js_heap_bytes: 536870912,
  transfer_bytes: 52428800,
  request_count: 150,
  cls: 0.25,
  lcp_ms: 20000,
  browser_peak_working_set_bytes: 2684354560,
  browser_cpu_seconds: 180,
  app_peak_memory_bytes: 1073741824,
  app_cpu_seconds: 180,
});

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const BENCHMARK_ROOT = path.dirname(path.dirname(SCRIPT_PATH));
const HARNESS_COMPONENT_PATHS = Object.freeze([
  "scripts/benchmark_phase0_browser.mjs",
  "scripts/prepare_phase0_browser_data.py",
  "scripts/phase0_loopback_proxy.py",
  "scripts/run_phase0_browser_repeat.ps1",
  "scripts/sample_windows_browser.ps1",
  "scripts/snapshot_phase0_browser_state.py",
  "scripts/summarize_phase0_browser_benchmark.py",
]);
const WORKLOADS = ["analysis", "hunt", "reach", "map"];
const FOUNDATION_ACTIONS = ["current:first-100", "current:last-20", "processed:first-100", "processed:last-20"];

function sha256File(filename) {
  return crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}

function sha256Values(values) {
  return crypto.createHash("sha256").update(JSON.stringify(values)).digest("hex");
}

function harnessComponents() {
  return Object.fromEntries(HARNESS_COMPONENT_PATHS.map(relative => {
    const filename = path.join(BENCHMARK_ROOT, ...relative.split("/"));
    assert.ok(fs.existsSync(filename), `benchmark harness component is missing: ${relative}`);
    return [relative, sha256File(filename)];
  }));
}

function run(command, args) {
  const result = spawnSync(command, args, {encoding: "utf8", windowsHide: true});
  if (result.status !== 0) throw new Error(`${command} failed: ${result.stderr || result.stdout}`);
  return result.stdout.trim();
}

function dockerExec(container, args) {
  return run("docker", ["exec", container, ...args]);
}

function appResource(container) {
  const raw = dockerExec(container, ["sh", "-lc", "cat /sys/fs/cgroup/cpu.stat; printf '\\nMEMORY_PEAK='; cat /sys/fs/cgroup/memory.peak"]);
  const usage = Number(raw.match(/^usage_usec\s+(\d+)/m)?.[1]);
  const peak = Number(raw.match(/^MEMORY_PEAK=(\d+)/m)?.[1]);
  assert.ok(Number.isFinite(usage) && Number.isFinite(peak), "container cgroup resource counters are unavailable");
  return {cpu_usage_usec: usage, peak_memory_bytes: peak, method: "container cgroup v2"};
}

function retainedState(container, scriptPath) {
  return JSON.parse(dockerExec(container, ["python", scriptPath, "--data-root", "/data"]));
}

function verifyContainerIsolation(config, inspected) {
  const attested = config.identity_evidence.container;
  assert.equal(inspected.Id, config.container_id, "container identity mismatch");
  assert.equal(inspected.Image, config.container_image_id, "container image identity mismatch");
  assert.equal(inspected.Created, attested.created_at, "container creation identity mismatch");
  assert.equal(inspected.Config?.Labels?.["nct.phase0.browser.token"], attested.controller_token, "controller token label mismatch");
  const mounts = Object.fromEntries((inspected.Mounts || []).map(item => [item.Destination, item]));
  assert.equal(mounts["/workspace"]?.RW, false, "source mount is not read-only");
  assert.equal(mounts["/benchmark"]?.RW, false, "benchmark mount is not read-only");
  assert.equal(mounts["/data"]?.RW, true, "data mount is not writable");
  assert.equal(path.resolve(mounts["/workspace"]?.Source || ""), path.resolve(attested.source_mount_host_path), "source mount path mismatch");
  assert.equal(path.resolve(mounts["/benchmark"]?.Source || ""), path.resolve(attested.benchmark_mount_host_path), "benchmark mount path mismatch");
  assert.equal(path.resolve(mounts["/data"]?.Source || ""), path.resolve(attested.data_mount_host_path), "data mount path mismatch");
  const networks = Object.entries(inspected.NetworkSettings?.Networks || {});
  assert.equal(networks.length, 1, "container must use exactly one Docker network");
  assert.equal(networks[0][1]?.NetworkID, attested.network_id, "container network identity mismatch");
  const network = JSON.parse(run("docker", ["network", "inspect", attested.network_id]))[0];
  assert.equal(network.Internal, true, "Docker network is not internal");
  const appBindings = Object.values(inspected.NetworkSettings?.Ports || {}).flat().filter(Boolean);
  assert.equal(appBindings.length, 0, "app container must not publish a host port directly");
  const proxy = JSON.parse(run("docker", ["inspect", attested.proxy_container_id]))[0];
  assert.equal(proxy.Id, attested.proxy_container_id, "proxy container identity mismatch");
  assert.equal(proxy.Image, attested.proxy_image_id, "proxy image identity mismatch");
  assert.equal(proxy.Created, attested.proxy_created_at, "proxy creation identity mismatch");
  assert.equal(proxy.Config?.Labels?.["nct.phase0.browser.proxy-token"], attested.controller_token, "proxy controller token mismatch");
  const proxyMounts = Object.fromEntries((proxy.Mounts || []).map(item => [item.Destination, item]));
  assert.equal(proxyMounts["/benchmark"]?.RW, false, "proxy benchmark mount is not read-only");
  const proxyNetworks = Object.values(proxy.NetworkSettings?.Networks || {});
  assert.ok(proxyNetworks.some(item => item.NetworkID === attested.network_id), "proxy is not attached to the internal app network");
  assert.ok(proxyNetworks.some(item => item.NetworkID !== attested.network_id), "proxy has no publication network");
  const bindings = Object.values(proxy.NetworkSettings?.Ports || {}).flat().filter(Boolean);
  assert.ok(bindings.length > 0, "proxy has no loopback publication");
  assert.ok(bindings.every(item => item.HostIp === "127.0.0.1"), "proxy publication is not loopback-only");
  const prepared = JSON.parse(dockerExec(config.container_name, ["cat", "/data/.phase0-browser-prepared.json"]));
  assert.equal(prepared.source_digest_sha256, config.source_digest_sha256, "prepared data source digest mismatch");
  assert.equal(prepared.corpus_manifest_sha256, config.corpus_manifest_sha256, "prepared data corpus mismatch");
  assert.equal(prepared.foundation_capabilities, config.foundation_capabilities, "prepared data capability mismatch");
  assert.equal(prepared.staging_complete, true);
  assert.equal(prepared.prewarm_complete, true);
  return {type: config.identity_evidence.type, validated: true, git: config.identity_evidence.git, corpus: config.identity_evidence.corpus, container: {...attested, inspected_mount_destinations: Object.keys(mounts).sort(), inspected_network_name: networks[0][0], app_direct_publication_count: 0, inspected_proxy_network_count: proxyNetworks.length, inspected_published_bindings: bindings}};
}

function validateBrowserProcessTree(resource, browserExecutable) {
  const processes = resource.processes || [];
  assert.ok(processes.length > 0, "browser process tree is empty");
  const ids = new Set(processes.map(item => item.process_id));
  assert.equal(ids.size, processes.length, "browser process identities are not unique");
  assert.ok(processes.every(item => Number.isInteger(item.process_id) && Number.isInteger(item.parent_process_id) && item.creation_date && path.resolve(item.executable_path) === browserExecutable), "browser process identity is incomplete");
  assert.ok(processes.some(item => !ids.has(item.parent_process_id)), "browser process tree has no root");
  assert.deepEqual([...ids].sort((a, b) => a - b), [...(resource.process_ids || [])].sort((a, b) => a - b), "browser PID summary does not match process tree");
  return true;
}

export function validateConfig(config) {
  assert.ok(config && typeof config === "object", "configuration is required");
  assert.match(config.base_url || "", /^http:\/\/127\.0\.0\.1:\d+$/, "base_url must be loopback HTTP");
  assert.ok(Number.isInteger(config.repeat) && config.repeat >= 1 && config.repeat <= 3, "repeat must be 1, 2 or 3");
  assert.ok(typeof config.foundation_capabilities === "boolean", "foundation_capabilities must be boolean");
  for (const key of ["container_name", "container_id", "container_image_id", "revision", "source_digest_sha256", "corpus_manifest_sha256", "browser_executable", "browser_sha256", "browser_version", "playwright_version", "profile_root", "artifact_root", "snapshot_script_in_container"]) {
    assert.ok(typeof config[key] === "string" && config[key], `${key} is required`);
  }
  assert.match(config.container_id, /^[0-9a-f]{64}$/i);
  assert.match(config.revision, /^[0-9a-f]{40}$/i);
  for (const key of ["source_digest_sha256", "corpus_manifest_sha256", "browser_sha256"]) assert.match(config[key], /^[0-9a-f]{64}$/i);
  assert.equal(path.resolve(config.browser_executable), config.browser_executable, "browser executable must be absolute");
  assert.equal(path.resolve(config.profile_root), config.profile_root, "profile root must be absolute");
  assert.equal(path.resolve(config.artifact_root), config.artifact_root, "artifact root must be absolute");
  assert.equal(sha256File(config.browser_executable), config.browser_sha256, "browser executable identity mismatch");
  assert.equal(require("playwright/package.json").version, config.playwright_version, "Playwright version mismatch");
  validateControllerAttestation(config);
  if (fs.existsSync(config.profile_root)) throw new Error("fresh browser profile root already exists");
  fs.mkdirSync(config.profile_root, {recursive: true});
  fs.mkdirSync(config.artifact_root, {recursive: true});
  return config;
}

function validateControllerAttestation(config) {
  const evidence = config.identity_evidence || {};
  const git = evidence.git || {};
  const container = evidence.container || {};
  const corpus = evidence.corpus || {};
  assert.equal(evidence.type, "externally-verified-browser-controller-attestations", "unsupported controller attestation");
  assert.equal(evidence.validated, true, "controller attestation is not validated");
  assert.equal(git.verification_method, "controller:git-rev-parse-status-and-source-digest");
  assert.equal(git.clean, true, "target checkout is not clean");
  assert.equal(git.revision, config.revision, "Git revision attestation mismatch");
  assert.equal(git.source_digest_sha256, config.source_digest_sha256, "source digest attestation mismatch");
  assert.equal(corpus.verification_method, "controller:canonical-corpus-regeneration");
  assert.equal(corpus.manifest_sha256, config.corpus_manifest_sha256, "corpus attestation mismatch");
  assert.equal(container.verification_method, "controller:docker-inspect-and-prewarm");
  assert.equal(container.container_id, config.container_id, "container attestation mismatch");
  assert.equal(container.image_id, config.container_image_id, "image attestation mismatch");
  assert.match(container.proxy_container_id || "", /^[0-9a-f]{64}$/i, "proxy container identity is missing");
  assert.equal(container.proxy_image_id, config.container_image_id, "proxy image attestation mismatch");
  for (const key of ["source_mount_host_path", "benchmark_mount_host_path", "data_mount_host_path"]) assert.ok(path.isAbsolute(container[key] || ""), `${key} is missing`);
  for (const key of ["fresh_container", "fresh_data_root", "staging_complete", "prewarm_complete", "live_http_prewarm_complete", "source_mount_read_only", "benchmark_mount_read_only", "network_internal", "loopback_only_publication"]) {
    assert.equal(container[key], true, `controller did not prove ${key}`);
  }
  assert.equal(container.published_host_ip, "127.0.0.1");
  assert.match(container.network_id || "", /^[0-9a-f]{64}$/i, "internal network identity is missing");
  assert.match(container.controller_token || "", /^[0-9a-f-]{36}$/i, "controller token is missing");
}

function expectedShell(name, foundation) {
  return {
    analysis: {active: "/analysis#xmlImport", breadcrumb: "Collect / Nmap Scans", heading: foundation ? "Import & Investigate" : "Import Nmap Evidence"},
    hunt: {active: "/hunting#huntOverview", breadcrumb: "Investigate / Hunt", heading: "Network Evidence"},
    reach: {active: "/reachability#reachAssessment", breadcrumb: "Investigate / Reach", heading: "Path Assessment"},
    map: {active: "/network-map#mapWorkspace", breadcrumb: "Investigate / Map", heading: "Network Map"},
  }[name];
}

export function attachProblemMonitoring(page, problems) {
  if (page.__nctProblemMonitoringAttached) return;
  page.__nctProblemMonitoringAttached = true;
  page.on("console", message => { if (message.type() === "error") problems.console.push(message.text()); });
  page.on("pageerror", error => problems.page.push(error.message));
  page.on("requestfailed", request => {
    if (!problems.external.includes(request.url())) problems.request.push(`${request.url()}: ${request.failure()?.errorText || "failed"}`);
  });
  page.on("response", response => { if (response.status() >= 400) problems.response.push(`${response.status()} ${response.url()}`); });
}

export async function installMonitoring(context, baseUrl) {
  const origin = new URL(baseUrl).origin;
  await context.addInitScript(() => {
    window.__nctPerf = {longTasks: [], layoutShifts: [], lcp: 0};
    new PerformanceObserver(list => window.__nctPerf.longTasks.push(...list.getEntries().map(item => item.duration))).observe({type: "longtask", buffered: true});
    new PerformanceObserver(list => window.__nctPerf.layoutShifts.push(...list.getEntries().filter(item => !item.hadRecentInput).map(item => item.value))).observe({type: "layout-shift", buffered: true});
    new PerformanceObserver(list => { const entries = list.getEntries(); if (entries.length) window.__nctPerf.lcp = entries.at(-1).startTime; }).observe({type: "largest-contentful-paint", buffered: true});
  });
  const problems = {console: [], page: [], request: [], response: [], external: []};
  await context.route("**/*", async route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) {
      problems.external.push(route.request().url());
      await route.abort("blockedbyclient");
    } else if (url.pathname === "/favicon.ico") {
      await route.fulfill({status: 204, body: ""});
    } else {
      await route.continue();
    }
  });
  for (const page of context.pages()) attachProblemMonitoring(page, problems);
  context.on("page", page => attachProblemMonitoring(page, problems));
  return problems;
}

async function stableFrames(page) {
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function waitReady(page, name, foundation) {
  if (name === "analysis") {
    await page.waitForFunction(() => document.querySelector("main")?.getAttribute("aria-busy") === "false");
    await page.waitForFunction(() => document.querySelector("#networkPageSummary")?.textContent === "Rows 1–25 of 4188 · page 1 of 168");
  } else if (name === "hunt") {
    await page.waitForFunction(() => document.querySelectorAll("#findingSummaryRows tr").length === 4188);
  } else if (name === "reach") {
    const devices = foundation ? 0 : 1;
    await page.waitForFunction(expected => document.querySelector("#status")?.textContent === `0 Saved Networks, 4188 observed hosts, and ${expected} current device collection${expected === 1 ? "" : "s"} available.`, devices);
  } else if (name === "map") {
    const summary = foundation ? "1 device · 0 subnets · 4188 hosts" : "2 devices · 2 subnets · 4188 hosts";
    await page.waitForFunction(expected => document.querySelector("#summaryCompact")?.textContent === expected && !document.querySelector("#refresh")?.disabled, summary);
  }
  await stableFrames(page);
}

async function collectMetrics(page, elapsedMs, baseline = null) {
  return page.evaluate(({elapsed, baseline}) => {
    const nav = performance.getEntriesByType("navigation")[0] || {};
    const resources = performance.getEntriesByType("resource");
    const longTasks = window.__nctPerf?.longTasks || [];
    const shifts = window.__nctPerf?.layoutShifts || [];
    const resourceTransfer = resources.reduce((sum, item) => sum + Number(item.transferSize || 0), 0);
    const newLongTasks = longTasks.slice(Number(baseline?.long_task_count || 0));
    return {
      action_to_ready_ms: elapsed,
      navigation: {dom_content_loaded_ms: nav.domContentLoadedEventEnd || 0, load_event_ms: nav.loadEventEnd || 0, response_end_ms: nav.responseEnd || 0},
      request_count: resources.length + (baseline ? 0 : 1) - Number(baseline?.resource_count || 0),
      transfer_bytes: Number(nav.transferSize || 0) + resourceTransfer - Number(baseline?.transfer_bytes || 0),
      dom_nodes: document.querySelectorAll("*").length,
      js_heap_bytes: Number(performance.memory?.usedJSHeapSize || 0),
      long_task_count: longTasks.length,
      resource_count: resources.length,
      long_task_total_ms: newLongTasks.reduce((sum, item) => sum + item, 0),
      longest_task_ms: Math.max(0, ...newLongTasks),
      cls: Math.max(0, shifts.reduce((sum, item) => sum + item, 0) - Number(baseline?.cls || 0)),
      lcp_ms: Math.max(0, Number(window.__nctPerf?.lcp || 0) - Number(baseline?.lcp_ms || 0)),
    };
  }, {elapsed: elapsedMs, baseline});
}

function validateMetrics(metric, foundationAction = false) {
  const limit = foundationAction ? ABSOLUTE_LIMITS.foundation_action_to_ready_ms : ABSOLUTE_LIMITS.common_action_to_ready_ms;
  assert.ok(metric.action_to_ready_ms <= limit, "action-to-ready limit exceeded");
  assert.ok(metric.navigation.load_event_ms <= ABSOLUTE_LIMITS.navigation_load_event_ms, "navigation load-event limit exceeded");
  for (const [key, limitKey] of [["longest_task_ms", "longest_task_ms"], ["long_task_total_ms", "long_task_total_ms"], ["dom_nodes", "dom_nodes"], ["js_heap_bytes", "js_heap_bytes"], ["transfer_bytes", "transfer_bytes"], ["request_count", "request_count"], ["cls", "cls"], ["lcp_ms", "lcp_ms"]]) {
    assert.ok(metric[key] <= ABSOLUTE_LIMITS[limitKey], `${key} limit exceeded`);
  }
}

async function shellOracle(page, name, foundation) {
  const actual = await page.evaluate(() => ({
    active: document.querySelector("#nct-sidebar [aria-current=page]")?.getAttribute("data-task-href") || "",
    breadcrumb: document.querySelector("#nct-page-context .nct-breadcrumb")?.textContent || "",
    heading: document.querySelector("#nct-page-context h1")?.textContent || "",
  }));
  assert.deepEqual(actual, expectedShell(name, foundation));
  return actual;
}

async function jsonFromPage(page, pathName) {
  return page.evaluate(async pathName => {
    const response = await fetch(pathName, {cache: "no-store"});
    const data = await response.json();
    if (!response.ok) throw new Error(`${pathName} returned HTTP ${response.status}`);
    return data;
  }, pathName);
}

async function exactRenderedOracle(page, name, foundation) {
  if (name === "analysis") {
    const data = await jsonFromPage(page, "/api/analysis/network");
    const addresses = (data.hosts || []).map(item => String(item.ip || ""));
    const rendered = await page.locator(".network-host-row .host-title").allTextContents();
    assert.equal(data.status, "analysis_network_complete");
    assert.equal(data.host_count, EXPECTED_COMMON.host_count);
    assert.equal(addresses.length, EXPECTED_COMMON.host_count);
    assert.equal(new Set(addresses).size, EXPECTED_COMMON.host_count);
    assert.equal(sha256Values(addresses), EXPECTED_COMMON.ordered_host_addresses_sha256);
    assert.deepEqual(rendered, addresses.slice(0, 25), "Analyze rendered address order mismatch");
    return {host_count: data.host_count, ordered_host_addresses_sha256: sha256Values(addresses), rendered_first_page: rendered};
  }
  if (name === "hunt") {
    const data = await jsonFromPage(page, "/api/hunting/network");
    const grouped = [];
    const seen = new Set();
    for (const finding of data.findings || []) {
      const key = String(finding.host_key || finding.ip || finding.hostname || "unknown");
      if (seen.has(key)) continue;
      seen.add(key);
      grouped.push(String(finding.ip || ""));
    }
    const rendered = await page.locator(".finding-summary-row").evaluateAll(rows => rows.map(row => row.dataset.ip || ""));
    assert.equal(data.status, "hunting_network_complete");
    assert.equal(data.host_count, EXPECTED_COMMON.host_count);
    assert.equal(data.finding_count, EXPECTED_COMMON.finding_count);
    assert.deepEqual(rendered, grouped, "Hunt rendered host/order mismatch");
    assert.equal(sha256Values(rendered), EXPECTED_COMMON.ordered_host_addresses_sha256, "Hunt rendered host/order digest mismatch");
    return {host_count: data.host_count, finding_count: data.finding_count, rendered_group_count: rendered.length, ordered_groups_sha256: sha256Values(rendered)};
  }
  if (name === "reach") {
    const data = await jsonFromPage(page, "/api/reachability/context");
    const expected = {saved_networks: 0, hosts: EXPECTED_COMMON.host_count, devices: foundation ? 0 : 1, device_collections: foundation ? 0 : 1};
    const actual = {saved_networks: (data.saved_networks || []).length, hosts: (data.hosts || []).length, devices: (data.devices || []).length, device_collections: Number(data.device_collections || 0)};
    assert.deepEqual(actual, expected, "Reach exact context mismatch");
    assert.equal(await page.locator("#status").textContent(), `0 Saved Networks, 4188 observed hosts, and ${expected.device_collections} current device collection${expected.device_collections === 1 ? "" : "s"} available.`);
    return actual;
  }
  if (name === "map") {
    const data = await jsonFromPage(page, "/api/network-map");
    const expected = EXPECTED_COMMON.map[foundation ? "foundation" : "stable"];
    assert.deepEqual(data.summary, expected, "Map exact summary mismatch");
    const rendered = await page.evaluate(() => ({
      devices: Number(document.querySelector("#deviceCount")?.textContent),
      interfaces: Number(document.querySelector("#interfaceCount")?.textContent),
      subnets: Number(document.querySelector("#subnetCount")?.textContent),
      hosts: Number(document.querySelector("#hostCount")?.textContent),
      mac_observations: Number(document.querySelector("#macObservationCount")?.textContent),
      arp_neighbors: Number(document.querySelector("#arpNeighborCount")?.textContent),
      topology_neighbors: Number(document.querySelector("#topologyNeighborCount")?.textContent),
    }));
    assert.deepEqual(rendered, {devices: expected.devices + expected.gateways, interfaces: expected.interfaces, subnets: expected.subnets, hosts: expected.hosts, mac_observations: expected.mac_observations, arp_neighbors: expected.arp_neighbors, topology_neighbors: expected.topology_neighbors}, "Map rendered counters mismatch");
    return {summary: data.summary, rendered};
  }
  throw new Error(`unknown workload ${name}`);
}

async function measureNavigation(page, url, name, foundation) {
  const started = performance.now();
  await page.goto(url, {waitUntil: "domcontentloaded", timeout: 120000});
  await waitReady(page, name, foundation);
  const metric = await collectMetrics(page, performance.now() - started);
  validateMetrics(metric);
  const shell = await shellOracle(page, name, foundation);
  const correctness = await exactRenderedOracle(page, name, foundation);
  return {metric, shell, correctness};
}

async function foundationActions(page, baseUrl) {
  const actions = {};
  const correctness = {current_addresses: [], processed_addresses: []};
  await page.goto(baseUrl + "/analysis#networkOverview", {waitUntil: "domcontentloaded", timeout: 120000});
  await waitReady(page, "analysis", true);
  await page.waitForFunction(() => document.body.dataset.nctTask === "networkOverview" && !document.querySelector("#networkOverview")?.classList.contains("hidden"));
  await page.selectOption("#networkSubnet", "10.20.0.0/24");
  await page.waitForFunction(() => document.querySelector("#networkPageSummary")?.textContent?.startsWith("Rows 1–25 of 120"));
  let metricBaseline = await collectMetrics(page, 0);
  let started = performance.now();
  await page.selectOption("#networkPageSize", "100");
  await page.waitForFunction(() => document.querySelector("#networkPageSummary")?.textContent === "Rows 1–100 of 120 · page 1 of 2");
  await stableFrames(page);
  actions["current:first-100"] = await collectMetrics(page, performance.now() - started, metricBaseline);
  assert.equal(await page.locator(".network-host-row").count(), 100);
  correctness.current_addresses.push(...await page.locator(".network-host-row .host-title").allTextContents());
  metricBaseline = await collectMetrics(page, 0);
  started = performance.now();
  await page.click("#networkNext");
  await page.waitForFunction(() => document.querySelector("#networkPageSummary")?.textContent === "Rows 101–120 of 120 · page 2 of 2");
  await stableFrames(page);
  actions["current:last-20"] = await collectMetrics(page, performance.now() - started, metricBaseline);
  assert.equal(await page.locator(".network-host-row").count(), 20);
  correctness.current_addresses.push(...await page.locator(".network-host-row .host-title").allTextContents());

  await page.goto(baseUrl + "/analysis#networkChangesPanel", {waitUntil: "domcontentloaded", timeout: 120000});
  await page.waitForFunction(() => document.querySelector("main")?.getAttribute("aria-busy") === "false");
  await page.locator("#networkChangesPanel").evaluate(node => { node.open = true; });
  await page.waitForFunction(() => !document.querySelector("#networkChangesPanel")?.classList.contains("nct-task-hidden"));
  const scopeValue = await page.locator("#processedEvidenceScope option:not([value=''])").first().getAttribute("value");
  assert.ok(scopeValue, "processed evidence scope is missing");
  await page.selectOption("#processedEvidenceScope", scopeValue);
  await page.evaluate(() => { processedEvidencePageSize = 100; });
  metricBaseline = await collectMetrics(page, 0);
  started = performance.now();
  await page.click("#loadProcessedEvidence");
  await page.waitForFunction(() => document.querySelector("#processedEvidenceStatus")?.textContent?.startsWith("Loaded a read-only evidence snapshot"));
  await page.waitForFunction(() => document.querySelectorAll(".processed-evidence-endpoint").length === 100);
  await stableFrames(page);
  actions["processed:first-100"] = await collectMetrics(page, performance.now() - started, metricBaseline);
  correctness.processed_addresses.push(...await page.locator(".processed-evidence-endpoint h4").allTextContents());
  assert.match(await page.locator("#processedEvidenceResult .processed-evidence-pager").first().innerText(), /Addresses 1–100 of 120/);
  metricBaseline = await collectMetrics(page, 0);
  started = performance.now();
  await page.locator('[data-evidence-page="endpoint"]:not([disabled])').click();
  await page.waitForFunction(() => document.querySelectorAll(".processed-evidence-endpoint").length === 20);
  await stableFrames(page);
  actions["processed:last-20"] = await collectMetrics(page, performance.now() - started, metricBaseline);
  correctness.processed_addresses.push(...await page.locator(".processed-evidence-endpoint h4").allTextContents());
  assert.match(await page.locator("#processedEvidenceResult .processed-evidence-pager").first().innerText(), /Addresses 101–120 of 120/);
  for (const metric of Object.values(actions)) validateMetrics(metric, true);
  assert.deepEqual(correctness.current_addresses, Array.from({length: 120}, (_, index) => `10.20.0.${index + 1}`), "Current Network 100/20 address sequence mismatch");
  assert.deepEqual(correctness.processed_addresses, Array.from({length: 120}, (_, index) => `10.20.0.${index + 1}`).sort(), "Processed Evidence 100/20 address sequence mismatch");
  return {metrics: actions, correctness: {current_count: 120, current_ordered_addresses_sha256: sha256Values(correctness.current_addresses), processed_count: 120, processed_ordered_addresses_sha256: sha256Values(correctness.processed_addresses)}};
}

async function runWorkload(config, name) {
  const profile = path.join(config.profile_root, name);
  const context = await chromium.launchPersistentContext(profile, {
    headless: true,
    executablePath: config.browser_executable,
    viewport: {width: 1440, height: 900},
    deviceScaleFactor: 1,
    locale: "en-US",
    timezoneId: "America/Chicago",
    colorScheme: "dark",
    reducedMotion: "reduce",
    args: ["--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--metrics-recording-only", "--no-first-run"],
  });
  const problems = await installMonitoring(context, config.base_url);
  const page = context.pages()[0] || await context.newPage();
  const browserSession = await context.newCDPSession(page);
  const actualBrowser = await browserSession.send("Browser.getVersion");
  await browserSession.detach();
  assert.equal(actualBrowser.product, `Chrome/${config.browser_version}`, "browser version mismatch");
  const tracePath = path.join(config.artifact_root, `${name}-failure.zip`);
  await context.tracing.start({screenshots: true, snapshots: true, sources: true});
  try {
    const route = {analysis: "/analysis", hunt: "/hunting", reach: "/reachability", map: "/network-map"}[name];
    const cold = await measureNavigation(page, config.base_url + route, name, config.foundation_capabilities);
    const coldScreenshot = path.join(config.artifact_root, `${name}-cold.png`);
    await page.screenshot({path: coldScreenshot});
    const started = performance.now();
    await page.reload({waitUntil: "domcontentloaded", timeout: 120000});
    await waitReady(page, name, config.foundation_capabilities);
    const reload = {metric: await collectMetrics(page, performance.now() - started), shell: await shellOracle(page, name, config.foundation_capabilities), correctness: await exactRenderedOracle(page, name, config.foundation_capabilities)};
    validateMetrics(reload.metric);
    const reloadScreenshot = path.join(config.artifact_root, `${name}-reload.png`);
    await page.screenshot({path: reloadScreenshot});
    const actionResult = name === "analysis" && config.foundation_capabilities ? await foundationActions(page, config.base_url) : {metrics: {}, correctness: null};
    const screenshotEntries = [coldScreenshot, reloadScreenshot];
    if (name === "analysis" && config.foundation_capabilities) {
      const actionScreenshot = path.join(config.artifact_root, "analysis-foundation-actions.png");
      await page.screenshot({path: actionScreenshot});
      screenshotEntries.push(actionScreenshot);
    }
    assert.deepEqual(problems, {console: [], page: [], request: [], response: [], external: []});
    await context.tracing.stop();
    return {cold, reload, actions: actionResult.metrics, action_correctness: actionResult.correctness, screenshots: screenshotEntries.map(filename => ({filename: path.basename(filename), sha256: sha256File(filename)}))};
  } catch (error) {
    await page.screenshot({path: path.join(config.artifact_root, `${name}-failure.png`), fullPage: true}).catch(() => {});
    await context.tracing.stop({path: tracePath}).catch(() => {});
    throw error;
  } finally {
    await context.close();
  }
}

async function benchmark(config) {
  validateConfig(config);
  const preState = retainedState(config.container_name, config.snapshot_script_in_container);
  const inspected = JSON.parse(run("docker", ["inspect", config.container_name]))[0];
  const identityEvidence = verifyContainerIsolation(config, inspected);
  const appStart = appResource(config.container_name);
  const stopFile = path.join(config.artifact_root, "browser-sampler.stop");
  const samplerOutput = path.join(config.artifact_root, "browser-resources.json");
  const sampler = spawn("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.join(path.dirname(SCRIPT_PATH), "sample_windows_browser.ps1"), "-ProfileRoot", config.profile_root, "-StopFile", stopFile, "-OutputFile", samplerOutput], {windowsHide: true});
  let samplerError = "";
  sampler.stderr.on("data", chunk => { samplerError += String(chunk); });
  const workloads = {};
  let failure;
  try {
    for (const name of WORKLOADS) workloads[name] = await runWorkload(config, name);
  } catch (error) {
    failure = error;
  } finally {
    fs.writeFileSync(stopFile, "stop\n");
    if (sampler.exitCode === null) await new Promise(resolve => sampler.once("exit", resolve));
  }
  if (failure) throw failure;
  if (sampler.exitCode !== 0 || !fs.existsSync(samplerOutput)) throw new Error(`browser resource sampler failed: ${samplerError || `exit ${sampler.exitCode}`}`);
  const browserResource = JSON.parse(fs.readFileSync(samplerOutput, "utf8").replace(/^\uFEFF/, ""));
  browserResource.process_tree_verified = validateBrowserProcessTree(browserResource, config.browser_executable);
  const appEnd = appResource(config.container_name);
  const postState = retainedState(config.container_name, config.snapshot_script_in_container);
  assert.deepEqual(postState, preState, "browser reads changed retained database or evidence state");
  const app = {method: appEnd.method, cpu_seconds: (appEnd.cpu_usage_usec - appStart.cpu_usage_usec) / 1e6, peak_memory_bytes: appEnd.peak_memory_bytes};
  assert.ok(browserResource.process_count > 0, "browser sampler did not observe Chrome");
  assert.ok(browserResource.peak_working_set_bytes <= ABSOLUTE_LIMITS.browser_peak_working_set_bytes, "browser peak memory limit exceeded");
  assert.ok(browserResource.cpu_seconds <= ABSOLUTE_LIMITS.browser_cpu_seconds, "browser CPU limit exceeded");
  assert.ok(app.peak_memory_bytes <= ABSOLUTE_LIMITS.app_peak_memory_bytes, "app peak memory limit exceeded");
  assert.ok(app.cpu_seconds <= ABSOLUTE_LIMITS.app_cpu_seconds, "app CPU limit exceeded");
  const expectedActions = config.foundation_capabilities ? FOUNDATION_ACTIONS : [];
  const actualActions = Object.values(workloads).flatMap(item => Object.keys(item.actions)).sort();
  assert.deepEqual(actualActions, [...expectedActions].sort());
  fs.rmSync(config.profile_root, {recursive: true, force: true});
  assert.equal(fs.existsSync(config.profile_root), false, "browser profiles were not cleaned up");
  return {
    benchmark: "phase0-rendered-browser-comparison",
    runner_version: RUNNER_VERSION,
    runner_sha256: sha256File(SCRIPT_PATH),
    harness_components: harnessComponents(),
    repeat: config.repeat,
    foundation_capabilities: config.foundation_capabilities,
    target: {revision: config.revision, source_digest_sha256: config.source_digest_sha256, container_id: config.container_id, container_image_id: config.container_image_id, identity_evidence: identityEvidence},
    corpus_manifest_sha256: config.corpus_manifest_sha256,
    browser: {version: config.browser_version, executable_sha256: config.browser_sha256, playwright_version: config.playwright_version, node_version: process.version, profile_root_token: path.basename(config.profile_root), profile_cleanup_verified: true, settings: {viewport: "1440x900", device_scale_factor: 1, locale: "en-US", timezone: "America/Chicago", color_scheme: "dark", reduced_motion: "reduce", external_requests: "blocked and fatal", favicon: "locally fulfilled with HTTP 204"}},
    workloads,
    resources: {browser: browserResource, app},
    retained_state: {pre: preState, post: postState, unchanged: true},
    limits: ABSOLUTE_LIMITS,
    passed: true,
    failures: [],
    limitations: ["Same-host Windows Chrome comparison using fresh browser processes and profiles.", "No browser-container, Linux-browser, GPU, human-interaction, multi-process, Range, production-scale or mission performance claim."],
  };
}

async function main() {
  if (process.argv.includes("--self-test")) {
    const invalid = {base_url: "https://example.com"};
    assert.throws(() => validateConfig(invalid));
    assert.equal(expectedShell("reach", true).active, "/reachability#reachAssessment");
    assert.equal(Object.keys(ABSOLUTE_LIMITS).length, 15);
    assert.equal(Object.keys(harnessComponents()).length, HARNESS_COMPONENT_PATHS.length);
    class FakePage {
      constructor() { this.handlers = {}; }
      on(name, handler) { (this.handlers[name] ||= []).push(handler); }
      emit(name, value) { for (const handler of this.handlers[name] || []) handler(value); }
    }
    const existing = new FakePage();
    const future = new FakePage();
    const contextHandlers = {};
    let routeHandler;
    const fakeContext = {
      pages: () => [existing],
      addInitScript: async () => {},
      route: async (_pattern, handler) => { routeHandler = handler; },
      on: (name, handler) => { contextHandlers[name] = handler; },
    };
    const faults = await installMonitoring(fakeContext, "http://127.0.0.1:1234");
    contextHandlers.page(future);
    existing.emit("console", {type: () => "error", text: () => "existing console fault"});
    future.emit("pageerror", new Error("future page fault"));
    existing.emit("requestfailed", {url: () => "http://127.0.0.1:1234/failed", failure: () => ({errorText: "reset"})});
    future.emit("response", {status: () => 503, url: () => "http://127.0.0.1:1234/bad"});
    let aborted = false;
    await routeHandler({request: () => ({url: () => "https://example.com/blocked"}), abort: async () => { aborted = true; }, continue: async () => {}, fulfill: async () => {}});
    assert.deepEqual(faults, {console: ["existing console fault"], page: ["future page fault"], request: ["http://127.0.0.1:1234/failed: reset"], response: ["503 http://127.0.0.1:1234/bad"], external: ["https://example.com/blocked"]});
    assert.equal(aborted, true);
    assert.equal(existing.handlers.console.length, 1);
    assert.equal(future.handlers.console.length, 1);
    console.log("Phase 0 rendered-browser benchmark self-test passed");
    return;
  }
  const configIndex = process.argv.indexOf("--config");
  const outputIndex = process.argv.indexOf("--output");
  if (configIndex < 0 || outputIndex < 0) throw new Error("--config and --output are required");
  const config = JSON.parse(fs.readFileSync(process.argv[configIndex + 1], "utf8"));
  const result = await benchmark(config);
  const rendered = JSON.stringify(result, null, 2) + "\n";
  fs.writeFileSync(process.argv[outputIndex + 1], rendered);
  process.stdout.write(rendered);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(SCRIPT_PATH)) main().catch(error => { console.error(error); process.exit(1); });
