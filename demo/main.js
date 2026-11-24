// Main thread: message router between party workers, plus UI. It never sees secrets: workers
// post only envelopes (what a network would carry) and public results.

const $ = (id) => document.getElementById(id);
const SETTINGS_KEY = 'cggmp21-demo-settings'; // UI settings only, never key material
const LOG_LIMIT = 400;
const STAGE_LABELS = {
  keygen: 'Keygen',
  paillier: 'Paillier primes',
  aux: 'Aux info',
  sign: 'Signing',
  presign: 'Presigning',
  partial: 'Partial signature',
};
// Rough number of candidates needed to hit a 1536-bit prime (≈ ln(2^1536) / 2)
const EXPECTED_PRIME_CANDIDATES = 532;

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(2)} MiB`);
const fmtMs = (ms) => (ms < 1000 ? `${ms.toFixed(0)} ms` : `${(ms / 1000).toFixed(2)} s`);
const clock = () => performance.timeOrigin + performance.now();
const randomEid = () => crypto.getRandomValues(new Uint8Array(32));

let wasm = null; // main-thread instance: public operations only (combine, verify)
let wasmModule = null;

const state = {
  n: 3,
  t: 2,
  ranks: null,
  workers: [],
  rows: [],
  busy: false,
  publicKey: null,
  keygenDone: false,
  auxDone: false,
  signature: null,
  signedMessage: null,
  active: null, // running stage: { stage, members, done, resolve, reject, stats }
  stats: [],
  timelineOrigin: null,
};

// ---------------------------------------------------------------------------------------------
// Startup

async function loadWasm() {
  const status = $('wasm-status');
  try {
    wasm = await import('./pkg/cggmp21_wasm.js');
    const response = await fetch(new URL('./pkg/cggmp21_wasm_bg.wasm', import.meta.url));
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const t0 = performance.now();
    wasmModule = await WebAssembly.compile(await response.arrayBuffer());
    await wasm.default({ module_or_path: wasmModule });
    status.textContent = `WebAssembly ready · compiled in ${fmtMs(performance.now() - t0)}`;
    status.dataset.state = 'ready';
    return true;
  } catch (err) {
    status.textContent = 'WebAssembly package missing — run cggmp21-wasm/build.sh';
    status.dataset.state = 'error';
    showError(`Could not load demo/pkg (${err.message}). Build it with cggmp21-wasm/build.sh and serve the demo directory over HTTP.`);
    return false;
  }
}

function loadSettings() {
  try {
    const s = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? '{}');
    if (s.n) $('n').value = s.n;
    if (s.t) $('t').value = s.t;
    if (typeof s.htss === 'boolean') $('htss').checked = s.htss;
    if (s.ranks) $('ranks').value = s.ranks;
    if (s.mode) $('mode').value = s.mode;
  } catch {
    localStorage.removeItem(SETTINGS_KEY);
  }
}

function saveSettings() {
  const s = { n: $('n').value, t: $('t').value, htss: $('htss').checked, ranks: $('ranks').value, mode: $('mode').value };
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
}

// ---------------------------------------------------------------------------------------------
// Parameters

function readParams() {
  const n = Number($('n').value);
  const t = Number($('t').value);
  if (!Number.isInteger(n) || n < 2 || n > 8) throw new Error('n must be between 2 and 8');
  if (!Number.isInteger(t) || t < 2 || t > n) throw new Error('t must be between 2 and n');
  let ranks = null;
  if ($('htss').checked) {
    ranks = $('ranks').value.split(',').map((r) => Number(r.trim()));
    if (ranks.length !== n || ranks.some((r) => !Number.isInteger(r) || r < 0 || r >= t)) {
      throw new Error(`HTSS needs ${n} comma-separated ranks, each between 0 and ${t - 1}`);
    }
  }
  return { n, t, ranks };
}

function selectedSigners() {
  return [...document.querySelectorAll('#signers input:checked')].map((c) => Number(c.value));
}

function renderSigners() {
  const box = $('signers');
  const previous = new Set(selectedSigners());
  box.replaceChildren();
  for (let i = 0; i < state.n; i++) {
    const label = document.createElement('label');
    label.className = 'chip';
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = i;
    input.checked = previous.size ? previous.has(i) : i < state.t;
    input.addEventListener('change', updateButtons);
    label.append(input, ` P${i}`);
    box.append(label);
  }
}

// ---------------------------------------------------------------------------------------------
// Parties (workers)

function createParties() {
  for (const w of state.workers) w.terminate();
  state.workers = [];
  state.rows = [];
  $('parties').replaceChildren();
  const ready = [];
  for (let i = 0; i < state.n; i++) {
    const worker = new Worker(new URL('./party-worker.js', import.meta.url), { type: 'module' });
    ready.push(
      new Promise((resolve, reject) => {
        worker.onmessage = ({ data }) => (data.type === 'ready' ? resolve() : reject(new Error(data.message)));
        worker.onerror = (e) => reject(new Error(e.message || 'worker failed to start'));
      }).then(() => {
        worker.onmessage = ({ data }) => onWorkerMessage(data);
        worker.onerror = (e) => failActive(i, e.message || 'worker crashed');
      }),
    );
    worker.postMessage({ type: 'init', module: wasmModule, index: i });
    state.workers.push(worker);
    state.rows.push(createRow(i));
  }
  state.publicKey = null;
  state.keygenDone = state.auxDone = false;
  state.signature = state.signedMessage = null;
  state.timelineOrigin = null;
  state.stats = [];
  renderStats();
  renderResult();
  renderAxis(0);
  return Promise.all(ready);
}

function createRow(i) {
  const row = document.createElement('div');
  row.className = 'party';
  row.innerHTML = `
    <div class="party-head">
      <span class="party-name">P${i}</span>
      <span class="party-rank"></span>
      <span class="party-status">idle</span>
    </div>
    <div class="primes" hidden>
      <div class="prime"><span>p</span><progress max="1" value="0"></progress><em></em></div>
      <div class="prime"><span>q</span><progress max="1" value="0"></progress><em></em></div>
    </div>
    <div class="track"></div>`;
  $('parties').append(row);
  return {
    el: row,
    status: row.querySelector('.party-status'),
    rank: row.querySelector('.party-rank'),
    primes: row.querySelector('.primes'),
    primeBars: [...row.querySelectorAll('.prime')],
    track: row.querySelector('.track'),
    blocks: [],
    open: null,
    waitStart: null,
  };
}

function setStatus(i, text, kind = '') {
  const row = state.rows[i];
  row.status.textContent = text;
  row.status.dataset.kind = kind;
}

// ---------------------------------------------------------------------------------------------
// Router

function onWorkerMessage(msg) {
  const active = state.active;
  const row = state.rows[msg.party];
  if (!active || msg.stage !== active.stage || !row) return;
  switch (msg.type) {
    case 'started':
      state.timelineOrigin ??= msg.t;
      row.open = { stage: msg.stage, start: msg.t, end: null, marks: [], waits: [], failed: false };
      row.blocks.push(row.open);
      setStatus(msg.party, `${STAGE_LABELS[msg.stage]}…`, 'busy');
      scheduleRender();
      break;
    case 'out':
      for (const envelope of msg.envelopes) route(active, envelope);
      break;
    case 'trace':
      for (const e of msg.events) trace(row, e);
      break;
    case 'progress':
      primeProgress(msg.party, msg.event);
      break;
    case 'done':
      if (row.open) {
        row.open.end = msg.t;
        row.open.busyMs = msg.busyMs;
        row.open = null;
      }
      setStatus(msg.party, `${STAGE_LABELS[msg.stage]} ✓`, 'ok');
      active.results.set(msg.party, msg.result);
      if (active.results.size === active.members.length) {
        active.stats.wall = msg.t - active.stats.start;
        finishActive();
        active.resolve(active.results);
      }
      scheduleRender();
      break;
    case 'error':
      failActive(msg.party, msg.message);
      break;
  }
}

function route(active, envelope) {
  const { members, stats } = active;
  const from = members[envelope.sender];
  const to = envelope.recipient === null ? members.filter((p) => p !== from) : [members[envelope.recipient]];
  for (const p of to) state.workers[p].postMessage({ type: 'msg', stage: active.stage, envelope });

  const size = envelope.payload.byteLength;
  const round = (stats.rounds[envelope.round] ??= { envelopes: 0, delivered: 0, bytes: 0 });
  round.envelopes += 1;
  round.delivered += to.length;
  round.bytes += size * to.length;
  stats.envelopes += 1;
  stats.delivered += to.length;
  stats.bytes += size * to.length;
  log(active.stage, envelope.round, from, envelope.recipient === null ? null : to[0], size);
  renderStatsSoon();
}

function trace(row, e) {
  const block = row.open;
  if (!block) return;
  if (e.kind === 'roundBegins') block.marks.push({ t: e.t, name: e.name });
  if (e.kind === 'receiveMsgs') row.waitStart = e.t;
  if (e.kind === 'msgsReceived' && row.waitStart !== null) {
    block.waits.push([row.waitStart, e.t]);
    row.waitStart = null;
  }
}

function primeProgress(i, event) {
  const row = state.rows[i];
  row.primes.hidden = false;
  const which = event.which ?? 0;
  const bar = row.primeBars[which];
  if (!bar) return;
  const [progress, label] = [bar.querySelector('progress'), bar.querySelector('em')];
  if (event.kind === 'divisorPrimeFound' && which === 0) {
    // the search (re)started: reset both bars
    for (const b of row.primeBars) {
      b.querySelector('progress').value = 0;
      b.querySelector('em').textContent = '';
      b.dataset.done = '';
    }
  }
  if (event.kind === 'candidateTested') {
    progress.value = 1 - Math.exp(-event.attempts / EXPECTED_PRIME_CANDIDATES);
    label.textContent = `${event.attempts} candidates`;
  } else if (event.kind === 'primeFound') {
    progress.value = 1;
    label.textContent = `found after ${event.attempts}`;
    bar.dataset.done = 'yes';
  }
  setStatus(i, `Paillier primes: searching ${which === 0 ? 'p' : 'q'}…`, 'busy');
}

function runStage(stage, members, makeMessage) {
  return new Promise((resolve, reject) => {
    const stats = { stage, start: clock(), wall: null, envelopes: 0, delivered: 0, bytes: 0, rounds: {} };
    state.stats.push(stats);
    state.active = { stage, members, results: new Map(), resolve, reject, stats };
    renderStats();
    members.forEach((p, idx) => state.workers[p].postMessage(makeMessage(p, idx)));
  });
}

function finishActive() {
  state.active = null;
  renderStats();
}

function failActive(party, message) {
  const active = state.active;
  if (!active) return showError(`P${party}: ${message}`);
  for (const p of active.members) {
    state.workers[p].postMessage({ type: 'abort' });
    const row = state.rows[p];
    if (row.open) {
      row.open.end = clock();
      row.open.failed = true;
      row.open = null;
      setStatus(p, 'aborted', 'error');
    }
  }
  setStatus(party, 'failed', 'error');
  finishActive();
  scheduleRender();
  active.reject(new Error(`${STAGE_LABELS[active.stage]} failed at P${party}: ${message}`));
}

// ---------------------------------------------------------------------------------------------
// Pipeline

async function doKeygen() {
  const { n, t, ranks } = readParams();
  if (n !== state.n || t !== state.t) {
    state.n = n;
    state.t = t;
    renderSigners();
  }
  // every key generation starts with fresh parties (and a fresh timeline)
  await createParties();
  state.ranks = ranks;
  state.rows.forEach((row, i) => (row.rank.textContent = ranks ? `rank ${ranks[i]}` : ''));
  const eid = randomEid();
  const members = [...Array(n).keys()];
  const results = await runStage('keygen', members, () => ({ type: 'keygen', eid, n, t, ranks }));
  const keys = new Set([...results.values()].map((r) => hex(r.publicKey)));
  if (keys.size !== 1) throw new Error('parties disagree on the public key');
  state.publicKey = results.get(0).publicKey;
  state.keygenDone = true;
  state.auxDone = false;
  state.signature = null;
  renderResult();
}

async function doAux() {
  if (!state.keygenDone) await doKeygen();
  const members = [...Array(state.n).keys()];
  for (const row of state.rows) {
    row.primes.hidden = false;
    for (const b of row.primeBars) {
      b.querySelector('progress').value = 0;
      b.querySelector('em').textContent = '';
    }
  }
  await runStage('paillier', members, () => ({ type: 'paillier' }));
  const eid = randomEid();
  await runStage('aux', members, () => ({ type: 'aux', eid, n: state.n }));
  state.auxDone = true;
}

async function doSign() {
  if (!state.auxDone) await doAux();
  const signers = selectedSigners();
  if (signers.length < state.t) throw new Error(`select at least t = ${state.t} signers`);
  const messageText = $('message').value;
  const message = new TextEncoder().encode(messageText);
  const eid = randomEid();
  let signature;
  if ($('mode').value === 'presign') {
    await runStage('presign', signers, () => ({ type: 'presign', eid, signers }));
    const partials = await runStage('partial', signers, () => ({ type: 'partial', message }));
    const ordered = signers.map((p) => partials.get(p).partial);
    signature = wasm.combinePartialSignatures(state.publicKey, message, ordered);
  } else {
    const results = await runStage('sign', signers, () => ({ type: 'sign', eid, signers, message }));
    const sigs = new Set([...results.values()].map((r) => hex(r.signature)));
    if (sigs.size !== 1) throw new Error('signers output different signatures');
    signature = results.get(signers[0]).signature;
  }
  state.signature = signature;
  state.signedMessage = messageText;
  renderResult();
  doVerify();
}

function doVerify() {
  if (!state.signature) throw new Error('nothing to verify yet: sign a message first');
  const text = $('message').value;
  const ok = wasm.verifySignature(state.publicKey, new TextEncoder().encode(text), state.signature);
  const badge = $('r-verify').querySelector('.badge');
  badge.dataset.state = ok ? 'ok' : 'bad';
  badge.textContent = ok
    ? 'valid ECDSA signature (secp256k1, SHA-256)'
    : text === state.signedMessage
      ? 'invalid signature'
      : 'invalid for the edited message';
}

async function action(fn) {
  if (state.busy) return;
  hideError();
  state.busy = true;
  updateButtons();
  try {
    await fn();
  } catch (err) {
    showError(err.message ?? String(err));
  } finally {
    state.busy = false;
    updateButtons();
  }
}

// ---------------------------------------------------------------------------------------------
// Rendering

function renderResult() {
  const set = (id, text) => {
    $(id).textContent = text ?? '—';
    $(id).classList.toggle('muted', !text);
  };
  set('r-pk', state.publicKey ? hex(state.publicKey) : null);
  set('r-msg', state.signature ? state.signedMessage : null);
  set('r-r', state.signature ? hex(state.signature.subarray(0, 32)) : null);
  set('r-s', state.signature ? hex(state.signature.subarray(32)) : null);
  const badge = $('r-verify').querySelector('.badge');
  badge.dataset.state = 'idle';
  badge.textContent = 'not verified';
}

let renderPending = false;
function scheduleRender() {
  if (renderPending) return;
  renderPending = true;
  requestAnimationFrame(() => {
    renderPending = false;
    renderTimeline();
    if (state.rows.some((r) => r.open)) scheduleRender();
  });
}

function renderTimeline() {
  const origin = state.timelineOrigin;
  if (origin === null) return;
  const now = clock();
  let end = origin + 1;
  for (const row of state.rows) for (const b of row.blocks) end = Math.max(end, b.end ?? now);
  const span = end - origin;
  const pct = (t) => `${(((t - origin) / span) * 100).toFixed(3)}%`;
  const width = (a, b) => `${(((b - a) / span) * 100).toFixed(3)}%`;

  for (const row of state.rows) {
    const frag = document.createDocumentFragment();
    for (const b of row.blocks) {
      const blockEnd = b.end ?? now;
      const el = document.createElement('div');
      el.className = `block stage-${b.stage}${b.failed ? ' failed' : ''}${b.end ? '' : ' running'}`;
      el.style.left = pct(b.start);
      el.style.width = width(b.start, blockEnd);
      const duration = blockEnd - b.start;
      el.title = `${STAGE_LABELS[b.stage]}: ${fmtMs(duration)}${b.busyMs !== undefined ? ` (computing ${fmtMs(b.busyMs)})` : ''}`;
      for (const [a, z] of b.waits) {
        const w = document.createElement('div');
        w.className = 'wait';
        w.style.left = `${((a - b.start) / duration) * 100}%`;
        w.style.width = `${((z - a) / duration) * 100}%`;
        el.append(w);
      }
      for (const m of b.marks) {
        const tick = document.createElement('div');
        tick.className = 'tick';
        tick.style.left = `${((m.t - b.start) / duration) * 100}%`;
        tick.title = m.name ?? 'round';
        el.append(tick);
      }
      if (b.end && duration / span > 0.06) {
        const label = document.createElement('span');
        label.textContent = fmtMs(duration);
        el.append(label);
      }
      frag.append(el);
    }
    row.track.replaceChildren(frag);
  }
  renderAxis(span);
}

function renderAxis(span) {
  const axis = $('axis');
  axis.replaceChildren();
  if (!span) return;
  for (let k = 0; k <= 4; k++) {
    const s = document.createElement('span');
    s.style.left = `${k * 25}%`;
    s.textContent = fmtMs((span * k) / 4);
    axis.append(s);
  }
}

let statsPending = false;
function renderStatsSoon() {
  if (statsPending) return;
  statsPending = true;
  requestAnimationFrame(() => {
    statsPending = false;
    renderStats();
  });
}

function renderStats() {
  const body = $('stats');
  const rounds = $('round-stats');
  body.replaceChildren();
  rounds.replaceChildren();
  const cell = (tr, text) => tr.append(Object.assign(document.createElement('td'), { textContent: text }));
  for (const s of state.stats) {
    const tr = document.createElement('tr');
    const roundKeys = Object.keys(s.rounds);
    cell(tr, STAGE_LABELS[s.stage]);
    cell(tr, roundKeys.length || '—');
    cell(tr, s.envelopes || '—');
    cell(tr, s.delivered || '—');
    cell(tr, s.bytes ? fmtBytes(s.bytes) : '—');
    cell(tr, s.wall === null ? (state.active?.stats === s ? 'running…' : 'failed') : fmtMs(s.wall));
    body.append(tr);
    for (const r of roundKeys) {
      const rr = document.createElement('tr');
      const v = s.rounds[r];
      cell(rr, STAGE_LABELS[s.stage]);
      cell(rr, r);
      cell(rr, v.envelopes);
      cell(rr, v.delivered);
      cell(rr, fmtBytes(v.bytes));
      rounds.append(rr);
    }
  }
}

let logQueue = [];
function log(stage, round, from, to, size) {
  logQueue.push({ stage, round, from, to, size, t: clock() });
  if (logQueue.length === 1) requestAnimationFrame(flushLog);
}

function flushLog() {
  const list = $('log');
  const frag = document.createDocumentFragment();
  for (const m of logQueue) {
    const li = document.createElement('li');
    const rel = state.timelineOrigin === null ? 0 : m.t - state.timelineOrigin;
    li.innerHTML = `<time></time><span class="tag stage-${m.stage}"></span><span class="route"></span><span class="size"></span>`;
    li.querySelector('time').textContent = `+${(rel / 1000).toFixed(2)}s`;
    li.querySelector('.tag').textContent = `${STAGE_LABELS[m.stage]} r${m.round}`;
    li.querySelector('.route').textContent = `P${m.from} → ${m.to === null ? 'all' : `P${m.to}`}`;
    li.querySelector('.size').textContent = fmtBytes(m.size);
    frag.append(li);
  }
  logQueue = [];
  list.append(frag);
  while (list.children.length > LOG_LIMIT) list.firstElementChild.remove();
  list.scrollTop = list.scrollHeight;
}

function renderLegend() {
  const legend = $('legend');
  for (const stage of ['keygen', 'paillier', 'aux', 'sign', 'presign']) {
    const s = document.createElement('span');
    s.className = `swatch stage-${stage}`;
    s.textContent = STAGE_LABELS[stage];
    legend.append(s);
  }
  const wait = document.createElement('span');
  wait.className = 'swatch waiting';
  wait.textContent = 'waiting for peers';
  legend.append(wait);
}

function updateButtons() {
  const ready = Boolean(wasmModule) && !state.busy;
  $('btn-all').disabled = !ready;
  $('btn-keygen').disabled = !ready;
  $('btn-aux').disabled = !ready || !state.keygenDone;
  $('btn-sign').disabled = !ready || !state.auxDone || selectedSigners().length < state.t;
  $('btn-verify').disabled = !ready || !state.signature;
  $('btn-reset').disabled = !wasmModule || state.busy;
  document.body.classList.toggle('busy', state.busy);
}

function showError(message) {
  const el = $('error');
  el.textContent = message;
  el.hidden = false;
}

function hideError() {
  $('error').hidden = true;
}

// ---------------------------------------------------------------------------------------------
// Wiring

function onParamsChanged() {
  saveSettings();
  $('ranks-field').hidden = !$('htss').checked;
  try {
    const { n, t } = readParams();
    if (n !== state.n || t !== state.t) {
      state.n = n;
      state.t = t;
      renderSigners();
    }
    hideError();
  } catch (err) {
    showError(err.message);
  }
  // new parameters need a new key
  if (state.keygenDone) {
    state.keygenDone = state.auxDone = false;
    state.signature = null;
    state.publicKey = null;
    renderResult();
  }
  updateButtons();
}

async function main() {
  loadSettings();
  $('ranks-field').hidden = !$('htss').checked;
  try {
    const { n, t } = readParams();
    state.n = n;
    state.t = t;
  } catch {
    /* keep defaults */
  }
  renderSigners();
  renderLegend();
  updateButtons();
  for (const id of ['n', 't', 'htss', 'ranks']) $(id).addEventListener('change', onParamsChanged);
  $('mode').addEventListener('change', saveSettings);
  $('message').addEventListener('input', () => {
    if (state.signature) doVerify();
  });

  $('btn-keygen').addEventListener('click', () => action(doKeygen));
  $('btn-aux').addEventListener('click', () => action(doAux));
  $('btn-sign').addEventListener('click', () => action(doSign));
  $('btn-verify').addEventListener('click', () => action(async () => doVerify()));
  $('btn-all').addEventListener('click', () =>
    action(async () => {
      await doKeygen();
      await doAux();
      await doSign();
    }),
  );
  $('btn-reset').addEventListener('click', () => action(createParties));
  $('btn-clear-log').addEventListener('click', () => $('log').replaceChildren());

  if (await loadWasm()) {
    await action(createParties);
  }
}

main();
