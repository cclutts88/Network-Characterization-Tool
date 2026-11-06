import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const shellSource = fs.readFileSync(path.join(here, '..', '..', 'app', 'shell_ui.py'), 'utf8');
const deviceSource = fs.readFileSync(path.join(here, '..', '..', 'app', 'device_ui.py'), 'utf8');

function extractFunction(name, source = shellSource) {
  const markers = [`async function ${name}`, `function ${name}`];
  const start = markers.map(marker => source.indexOf(marker)).find(index => index !== -1) ?? -1;
  assert.notEqual(start, -1, `${name} must exist in the production shell`);
  const bodyStart = source.indexOf('{', start);
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let index = bodyStart; index < source.length; index += 1) {
    const character = source[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === '"' || character === '`') {
      quote = character;
      continue;
    }
    if (character === '{') depth += 1;
    if (character === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, index + 1);
    }
  }
  throw new Error(`Could not extract ${name}`);
}

function context(values) {
  return vm.createContext({
    Boolean,
    JSON,
    Object,
    Error,
    Promise,
    ...values,
  });
}

async function authOffKeepsBrowserAppearance() {
  let applyCount = 0;
  const runtime = context({
    fetch: async () => ({ ok: true, json: async () => ({ server_persistence: false, preference: null }) }),
    profilePreferencesEnabled: true,
    shellPreferencePersistenceMode: 'unknown',
    shellPreferencesHydrated: false,
    saved: { preset: 'custom-browser-theme' },
    valid: value => value,
    apply: () => { applyCount += 1; },
    setGuideDock: () => {},
    validGuideSize: value => value,
    applyGuideSize: () => {},
    setGuideEnabled: () => {},
    setClosed: () => {},
    setAchievementMuted: () => {},
    cleanTutorialState: value => value || { local: true },
    localStorage: { getItem: () => '{"local":true}', removeItem: () => {} },
    TUTORIAL_LOCAL_KEY: 'tutorial',
    configureTutorialSidebarRestore: () => {},
    accountMenu: { querySelector: () => ({ textContent: '' }) },
    tutorialCenterStatus: { textContent: '' },
    renderTutorialCenter: () => {},
    renderTutorialPanel: () => {},
  });
  vm.runInContext(`${extractFunction('loadGuidedShellPreference')}; this.run = loadGuidedShellPreference;`, runtime);
  await runtime.run();
  assert.deepEqual(runtime.saved, { preset: 'custom-browser-theme' });
  assert.equal(applyCount, 0);
  assert.equal(runtime.shellPreferencePersistenceMode, 'local');
  assert.equal(runtime.shellPreferencesHydrated, true);
}

function sidebarRestoreIsScopedToConfirmedOwner() {
  const values = new Map([
    ['nct-tutorial-sidebar-restore-v1', '0'],
    ['nct-tutorial-sidebar-restore-v1:server:analyst-a', '0'],
    ['nct-tutorial-sidebar-restore-v1:local', '1'],
  ]);
  const runtime = context({
    TUTORIAL_SIDEBAR_RESTORE_KEY: 'nct-tutorial-sidebar-restore-v1',
    tutorialSidebarRestore: null,
    tutorialSidebarRestoreStorageKey: null,
    encodeURIComponent,
    localStorage: {
      getItem: key => values.get(key) ?? null,
      removeItem: key => values.delete(key),
      setItem: (key, value) => values.set(key, value),
    },
  });
  vm.runInContext(`${extractFunction('configureTutorialSidebarRestore')}; this.configure = configureTutorialSidebarRestore;`, runtime);

  runtime.configure('server', 'analyst-a');
  assert.equal(runtime.tutorialSidebarRestore, false, 'same analyst resumes its cross-page restore state');
  assert.equal(runtime.tutorialSidebarRestoreStorageKey, 'nct-tutorial-sidebar-restore-v1:server:analyst-a');
  assert.equal(values.has('nct-tutorial-sidebar-restore-v1'), false, 'legacy unscoped marker is discarded');

  runtime.configure('server', 'analyst-b');
  assert.equal(runtime.tutorialSidebarRestore, null, 'another analyst cannot inherit analyst A state');
  assert.equal(runtime.tutorialSidebarRestoreStorageKey, 'nct-tutorial-sidebar-restore-v1:server:analyst-b');

  runtime.configure('local', '');
  assert.equal(runtime.tutorialSidebarRestore, true, 'authentication-off mode uses its separate browser marker');
  runtime.configure('server', 'analyst-b');
  assert.equal(runtime.tutorialSidebarRestore, null, 'local-browser state cannot override a later signed-in account');
}

async function anotherAccountKeepsItsServerSidebarPreference() {
  const values = new Map([
    ['nct-tutorial-sidebar-restore-v1:server:analyst-a', '0'],
    ['nct-tutorial-sidebar-restore-v1:local', '0'],
  ]);
  let closed = false;
  const runtime = context({
    fetch: async () => ({
      ok: true,
      json: async () => ({
        server_persistence: true,
        preference_owner: 'analyst-b',
        preference: { snapshot: { sidebar_closed: true, guided_tutorials: null } },
      }),
    }),
    profilePreferencesEnabled: false,
    shellPreferencePersistenceMode: 'unknown',
    shellPreferencesHydrated: false,
    saved: { preset: 'current' },
    valid: value => value,
    apply: () => {},
    setGuideDock: () => {},
    validGuideSize: value => value,
    applyGuideSize: () => {},
    setGuideEnabled: () => {},
    setClosed: value => { closed = value; },
    setAchievementMuted: () => {},
    cleanTutorialState: () => ({ enabled: true, panel_open: false, active_track: null, tracks: {} }),
    localStorage: {
      getItem: key => values.get(key) ?? null,
      removeItem: key => values.delete(key),
      setItem: (key, value) => values.set(key, value),
    },
    TUTORIAL_LOCAL_KEY: 'nct-guided-tutorials-v1',
    TUTORIAL_SIDEBAR_RESTORE_KEY: 'nct-tutorial-sidebar-restore-v1',
    tutorialSidebarRestore: null,
    tutorialSidebarRestoreStorageKey: null,
    encodeURIComponent,
    accountMenu: { querySelector: () => ({ textContent: '' }) },
    tutorialCenterStatus: { textContent: '' },
    tutorialState: { enabled: true, panel_open: false, active_track: null, tracks: {} },
    tutorialPanel: { hidden: false },
    TUTORIALS: {},
    clearTutorialHighlight: () => {},
    document: { body: { classList: { remove: () => {} } } },
    renderTutorialCenter: () => {},
    clearTutorialSidebarRestore: () => {},
  });
  vm.runInContext(`${extractFunction('configureTutorialSidebarRestore')}; ${extractFunction('renderTutorialPanel')}; ${extractFunction('loadGuidedShellPreference')}; this.load = loadGuidedShellPreference;`, runtime);
  await runtime.load();
  assert.equal(runtime.tutorialSidebarRestore, null);
  assert.equal(runtime.tutorialSidebarRestoreStorageKey, 'nct-tutorial-sidebar-restore-v1:server:analyst-b');
  assert.equal(closed, true, 'analyst B keeps its saved closed sidebar preference');
}

async function failedLoadCannotWriteAnonymousProgress() {
  let localWrites = 0;
  const runtime = context({
    fetch: async () => { throw new Error('unavailable'); },
    profilePreferencesEnabled: false,
    shellPreferencePersistenceMode: 'unknown',
    shellPreferencesHydrated: false,
    tutorialCenterStatus: { textContent: '' },
    tutorialTargetStatus: { textContent: '', className: '' },
    renderTutorialCenter: () => {},
    renderTutorialPanel: () => {},
    localStorage: { setItem: () => { localWrites += 1; } },
  });
  vm.runInContext(`${extractFunction('loadGuidedShellPreference')}; ${extractFunction('persistShellPreference')}; this.load = loadGuidedShellPreference; this.persist = persistShellPreference;`, runtime);
  await runtime.load();
  const saved = await runtime.persist();
  assert.equal(saved, false);
  assert.equal(runtime.shellPreferencesHydrated, false);
  assert.equal(runtime.shellPreferencePersistenceMode, 'unknown');
  assert.equal(localWrites, 0);
}

async function blockedDevicePreviewSurvivesDelayedModeRefresh() {
  const startButton = { disabled: false };
  const draft = { device_address: '192.0.2.10', ssh_port: 22 };
  const runtime = context({
    current: { collection_scope_preview: { ready: false, compatible: false } },
    reviewedCollectionPayload: { ...draft },
    payload: () => ({ ...draft }),
    window: { isSecureContext: true },
    activeCollectionEnabled: true,
    currentAnalystRole: 'analyst',
    historyRecords: [],
    fetch: async () => ({
      ok: true,
      json: async () => ({ analyst: { role: 'admin' }, active_collection: { enabled: true } }),
    }),
    $: id => id === 'startSsh' ? startButton : { classList: { toggle: () => {} } },
    renderHistory: () => {},
    notice: () => {},
  });
  vm.runInContext(`${extractFunction('collectionDraftFingerprint', deviceSource)}; ${extractFunction('collectionStartReady', deviceSource)}; ${extractFunction('refreshCollectionStartState', deviceSource)}; ${extractFunction('loadActiveCollectionMode', deviceSource)}; this.load = loadActiveCollectionMode;`, runtime);
  assert.equal(await runtime.load(), true);
  assert.equal(startButton.disabled, true, 'a delayed mode refresh cannot enable Start for a blocked preview');

  startButton.disabled = false;
  runtime.fetch = async () => ({ ok: false, json: async () => ({ detail: 'signed out' }) });
  assert.equal(await runtime.load(), false);
  assert.equal(startButton.disabled, true, 'an unsuccessful identity refresh keeps Start disabled');
}

async function editedDeviceDraftCannotUseOldPreview() {
  const startButton = { disabled: false };
  const draft = { device_address: '192.0.2.11', ssh_port: 22 };
  let fetchCount = 0;
  const runtime = context({
    current: { collection_scope_preview: { ready: true, compatible: true } },
    reviewedCollectionPayload: { device_address: '192.0.2.10', ssh_port: 22 },
    payload: () => ({ ...draft }),
    window: { isSecureContext: true },
    activeCollectionEnabled: true,
    $: id => id === 'startSsh' ? startButton : { textContent: '' },
    notice: () => {},
    fetch: async () => { fetchCount += 1; return { ok: true, json: async () => ({}) }; },
  });
  vm.runInContext(`${extractFunction('collectionDraftFingerprint', deviceSource)}; ${extractFunction('collectionStartReady', deviceSource)}; ${extractFunction('refreshCollectionStartState', deviceSource)}; ${extractFunction('startInteractiveSsh', deviceSource)}; this.ready = collectionStartReady; this.start = startInteractiveSsh;`, runtime);
  assert.equal(runtime.ready(), false, 'editing a manual address after preview invalidates Start');
  await runtime.start();
  assert.equal(fetchCount, 0, 'a stale preview never starts device contact');
  assert.equal(startButton.disabled, true);
}

async function editDuringPreviewCannotPublishStaleResult() {
  const previewButton = { disabled: false };
  const startButton = { disabled: false };
  const hiddenClassList = { add: () => {}, remove: () => {} };
  let draft = { device_address: '192.0.2.10', ssh_port: 22 };
  let resolveFetch;
  let shown = 0;
  const response = new Promise(resolve => { resolveFetch = resolve; });
  const runtime = context({
    current: null,
    reviewedCollectionPayload: null,
    previewRequestRevision: 0,
    payload: () => ({ ...draft }),
    $: id => {
      if (id === 'preview') return previewButton;
      if (id === 'startSsh') return startButton;
      return { classList: hiddenClassList };
    },
    notice: () => {},
    fetch: () => response,
    showPreview: () => { shown += 1; },
    apiError: () => 'failed',
  });
  vm.runInContext(`${extractFunction('collectionDraftFingerprint', deviceSource)}; ${extractFunction('invalidateCollectionPreview', deviceSource)}; ${extractFunction('generate', deviceSource)}; this.invalidate = invalidateCollectionPreview; this.generate = generate;`, runtime);
  const pending = runtime.generate();
  draft = { device_address: '192.0.2.11', ssh_port: 22 };
  runtime.invalidate();
  resolveFetch({ ok: true, json: async () => ({ collection_scope_preview: { ready: true, compatible: true } }) });
  await pending;
  assert.equal(shown, 0, 'a preview response for fields edited in flight is discarded');
  assert.equal(startButton.disabled, true);
}

async function exitInvalidatesDeferredNavigation() {
  let resolveSave;
  let assignments = 0;
  const save = new Promise(resolve => { resolveSave = resolve; });
  const step = { id: 'scope', path: '/settings/mission-environment', hash: '#missionScopePanel' };
  const runtime = context({
    tutorialTransitionRevision: 1,
    tutorialState: { enabled: true, panel_open: true, active_track: 'mission' },
    TUTORIALS: { mission: { steps: [step] } },
    tutorialProgress: () => ({ step }),
    flushShellPreferenceSave: () => save,
    tutorialTargetStatus: { textContent: '', className: '' },
    location: { pathname: '/scans', hash: '', assign: () => { assignments += 1; } },
    renderTutorialPanel: () => {},
    highlightTutorialTarget: () => {},
  });
  vm.runInContext(`${extractFunction('openCurrentTutorialStep')}; this.openStep = openCurrentTutorialStep;`, runtime);
  const pending = runtime.openStep(1);
  runtime.tutorialState.enabled = false;
  runtime.tutorialState.panel_open = false;
  runtime.tutorialTransitionRevision = 2;
  resolveSave(true);
  assert.equal(await pending, false);
  assert.equal(assignments, 0);
}

await authOffKeepsBrowserAppearance();
await blockedDevicePreviewSurvivesDelayedModeRefresh();
await editedDeviceDraftCannotUseOldPreview();
await editDuringPreviewCannotPublishStaleResult();
sidebarRestoreIsScopedToConfirmedOwner();
await anotherAccountKeepsItsServerSidebarPreference();
await failedLoadCannotWriteAnonymousProgress();
await exitInvalidatesDeferredNavigation();
console.log('tutorial runtime regressions passed');
