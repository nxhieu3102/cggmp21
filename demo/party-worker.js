// One protocol party. Runs in its own Web Worker and keeps its secrets here: the main thread
// only sees envelopes (which a real network would carry) and public results.
import init, {
  KeygenSession,
  AuxInfoSession,
  SigningSession,
  PresigningSession,
  generatePaillierKey,
  completeKeyShare,
  keyShareInfo,
  issuePartialSignature,
} from './pkg/cggmp21_wasm.js';

const SESSIONS = {
  keygen: KeygenSession,
  aux: AuxInfoSession,
  sign: SigningSession,
  presign: PresigningSession,
};

let party = -1;
let poisoned = false;
// Secrets of this party; never posted to the main thread.
const secrets = { incompleteShare: null, paillierKey: null, keyShare: null, presignature: null };
// Running protocol session
let current = null; // { stage, session, busyMs }

const now = () => performance.timeOrigin + performance.now();
const post = (msg, transfer) => self.postMessage({ party, ...msg }, transfer ?? []);

function fail(stage, err) {
  current = null;
  // A wasm trap (RuntimeError) leaves the instance in an undefined state.
  if (err instanceof WebAssembly.RuntimeError) poisoned = true;
  post({ type: 'error', stage, message: err?.message ?? String(err), fatal: poisoned });
}

// Runs one call into a session and forwards what it produced.
function drive(call) {
  const { stage } = current;
  const t0 = performance.now();
  const step = call();
  current.busyMs += performance.now() - t0;

  if (step.events.length) {
    const offset = performance.timeOrigin;
    post({ type: 'trace', stage, events: step.events.map((e) => ({ ...e, t: e.t + offset })) });
  }
  if (step.outgoing.length) {
    post({ type: 'out', stage, envelopes: step.outgoing }, step.outgoing.map((e) => e.payload.buffer));
  }
  if (step.output) finish(stage, step.output, current.busyMs);
}

function finish(stage, output, busyMs) {
  current = null;
  let result;
  switch (stage) {
    case 'keygen': {
      secrets.incompleteShare = output.keyShare;
      secrets.keyShare = null;
      const info = keyShareInfo(output.keyShare);
      result = { publicKey: output.publicKey, shareBytes: output.keyShare.length, t: info.t, ranks: info.ranks };
      break;
    }
    case 'aux':
      secrets.paillierKey = null; // a Paillier key is used for one aux info generation only
      secrets.keyShare = completeKeyShare(secrets.incompleteShare, output.auxInfo);
      result = { auxBytes: output.auxInfo.length, shareBytes: secrets.keyShare.length };
      break;
    case 'sign':
      result = { signature: output.signature, publicKey: output.publicKey };
      break;
    case 'presign':
      secrets.presignature = output.presignature;
      result = { presignatureBytes: output.presignature.length };
      break;
  }
  post({ type: 'done', stage, result, busyMs, t: now() });
}

function startSession(stage, config) {
  const Session = SESSIONS[stage];
  current = { stage, session: new Session(config), busyMs: 0 };
  post({ type: 'started', stage, t: now() });
  drive(() => current.session.start());
}

const handlers = {
  async init({ module, index }) {
    party = index;
    await init({ module_or_path: module });
    post({ type: 'ready' });
  },

  keygen({ eid, n, t, ranks }) {
    startSession('keygen', { executionId: eid, i: party, n, t, ranks: ranks ?? null });
  },

  paillier() {
    const stage = 'paillier';
    post({ type: 'started', stage, t: now() });
    const t0 = performance.now();
    secrets.paillierKey = generatePaillierKey((event) => post({ type: 'progress', stage, event }), 100);
    post({ type: 'done', stage, result: {}, busyMs: performance.now() - t0, t: now() });
  },

  aux({ eid, n }) {
    if (!secrets.incompleteShare) throw new Error('run keygen first');
    if (!secrets.paillierKey) throw new Error('no Paillier key generated');
    startSession('aux', { executionId: eid, i: party, n, paillierKey: secrets.paillierKey });
  },

  sign({ eid, signers, message }) {
    if (!secrets.keyShare) throw new Error('run keygen and aux info first');
    startSession('sign', { executionId: eid, i: signers.indexOf(party), signers, keyShare: secrets.keyShare, message });
  },

  presign({ eid, signers }) {
    if (!secrets.keyShare) throw new Error('run keygen and aux info first');
    startSession('presign', { executionId: eid, i: signers.indexOf(party), signers, keyShare: secrets.keyShare });
  },

  partial({ message }) {
    if (!secrets.presignature) throw new Error('no presignature available');
    const presignature = secrets.presignature;
    secrets.presignature = null; // never reuse a presignature
    const partial = issuePartialSignature(presignature, message);
    post({ type: 'done', stage: 'partial', result: { partial }, busyMs: 0, t: now() });
  },

  msg({ stage, envelope }) {
    if (!current || current.stage !== stage) return; // stale message of an aborted stage
    drive(() => current.session.handleIncoming(envelope));
  },

  abort() {
    current = null;
  },
};

self.onmessage = async ({ data }) => {
  const handler = handlers[data.type];
  if (!handler) return;
  if (poisoned && data.type !== 'init') {
    post({ type: 'error', stage: data.stage ?? data.type, message: 'party crashed earlier; reset parties', fatal: true });
    return;
  }
  try {
    await handler(data);
  } catch (err) {
    fail(current?.stage ?? data.stage ?? data.type, err);
  }
};
