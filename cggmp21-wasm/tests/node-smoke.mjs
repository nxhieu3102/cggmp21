// Headless smoke test of the built wasm package (demo/pkg), single thread, n = 3, t = 2:
// keygen -> Paillier keys -> aux info -> signing -> presigning + partial signatures -> verify.
//
//   cggmp21-wasm/build.sh && node cggmp21-wasm/tests/node-smoke.mjs
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

const pkg = new URL('../../demo/pkg/', import.meta.url);
const wasm = await import(new URL('cggmp21_wasm.js', pkg));
wasm.initSync({ module: await readFile(new URL('cggmp21_wasm_bg.wasm', pkg)) });

const N = 3;
const T = 2;
const eid = (tag) => new TextEncoder().encode(`node smoke ${tag} ${Date.now()}`);
const hex = (b) => Buffer.from(b).toString('hex');
const timings = {};

async function timed(name, fn) {
  const t0 = performance.now();
  const out = await fn();
  timings[name] = Math.round(performance.now() - t0);
  return out;
}

// Routes envelopes between in-process sessions; `members[k]` is the session of envelope index k.
function run(sessions) {
  const queue = [];
  const outputs = new Array(sessions.length);
  let messages = 0;
  let bytes = 0;
  const absorb = (k, step) => {
    for (const e of step.outgoing) {
      assert.equal(e.sender, k);
      queue.push(e);
    }
    if (step.output) outputs[k] = step.output;
  };
  sessions.forEach((s, k) => absorb(k, s.start()));
  while (queue.length) {
    const e = queue.shift();
    const to = e.recipient === null ? sessions.map((_, k) => k).filter((k) => k !== e.sender) : [e.recipient];
    for (const k of to) {
      messages += 1;
      bytes += e.payload.length;
      absorb(k, sessions[k].handleIncoming(e));
    }
  }
  sessions.forEach((s, k) => assert.ok(s.finished && outputs[k], `party ${k} did not finish`));
  return { outputs, messages, bytes };
}

const keygen = await timed('keygen', () => {
  const id = eid('keygen');
  return run([...Array(N).keys()].map((i) => new wasm.KeygenSession({ executionId: id, i, n: N, t: T })));
});
const publicKey = keygen.outputs[0].publicKey;
assert.equal(publicKey.length, 33);
for (const o of keygen.outputs) assert.equal(hex(o.publicKey), hex(publicKey));

const paillierKeys = [];
for (let i = 0; i < N; i++) {
  let progressEvents = 0;
  paillierKeys.push(await timed(`paillier key ${i}`, () => wasm.generatePaillierKey(() => (progressEvents += 1), 0)));
  assert.ok(progressEvents > 0, 'no Paillier keygen progress events');
}

const aux = await timed('aux info', () => {
  const id = eid('aux');
  return run([...Array(N).keys()].map((i) => new wasm.AuxInfoSession({ executionId: id, i, n: N, paillierKey: paillierKeys[i] })));
});
const shares = keygen.outputs.map((k, i) => wasm.completeKeyShare(k.keyShare, aux.outputs[i].auxInfo));
const info = wasm.keyShareInfo(shares[2]);
assert.deepEqual([info.complete, info.i, info.n, info.t], [true, 2, N, T]);

const message = new TextEncoder().encode('signed by wasm in node');
const signers = [0, 2];
const sign = await timed('signing', () => {
  const id = eid('sign');
  return run(signers.map((p, i) => new wasm.SigningSession({ executionId: id, i, signers, keyShare: shares[p], message })));
});
const signature = sign.outputs[0].signature;
assert.ok(wasm.verifySignature(publicKey, message, signature));
assert.ok(!wasm.verifySignature(publicKey, new TextEncoder().encode('other'), signature));

const presign = await timed('presigning', () => {
  const id = eid('presign');
  return run([1, 2].map((p, i) => new wasm.PresigningSession({ executionId: id, i, signers: [1, 2], keyShare: shares[p] })));
});
const partials = presign.outputs.map((o) => wasm.issuePartialSignature(o.presignature, message));
const combined = wasm.combinePartialSignatures(publicKey, message, partials);
assert.ok(wasm.verifySignature(publicKey, message, combined));

assert.throws(() => new wasm.KeygenSession({ executionId: eid('bad'), i: 5, n: N, t: T }), /invalid input/);
assert.throws(() => wasm.completeKeyShare(aux.outputs[0].auxInfo, keygen.outputs[0].keyShare), /invalid/);

console.log(
  JSON.stringify(
    {
      ok: true,
      timingsMs: timings,
      traffic: {
        keygen: { messages: keygen.messages, bytes: keygen.bytes },
        aux: { messages: aux.messages, bytes: aux.bytes },
        signing: { messages: sign.messages, bytes: sign.bytes },
        presigning: { messages: presign.messages, bytes: presign.bytes },
      },
      sizes: { keyShare: shares[0].length, auxInfo: aux.outputs[0].auxInfo.length },
    },
    null,
    2,
  ),
);
