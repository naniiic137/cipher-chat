import { describe, expect, it } from 'vitest';
import {
  b64u,
  createPrekeyBundle,
  fromUtf8,
  generateIdentity,
  initInitiator,
  initResponder,
  ratchetDecrypt,
  ratchetEncrypt,
  safetyNumber,
  publicIdentity,
  formatSafetyNumber,
  checkVerificationPayload,
  verificationPayload,
  toHex,
  utf8,
  verifyBundle,
  x3dhInitiate,
  x3dhRespond,
  type RatchetMessage,
  type RatchetState,
  type SuiteId,
} from '../src/index.ts';

const suite: SuiteId = 'xchacha20-poly1305';

function setup() {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const { bundle, spkPriv } = createPrekeyBundle(bob);
  const a = x3dhInitiate(alice, bundle);
  const b = x3dhRespond(bob, spkPriv, bundle, a.init);
  return {
    alice,
    bob,
    bundle,
    ad: a.ad,
    sk: [a.sk, b.sk] as const,
    adB: b.ad,
    aState: initInitiator(a.sk, bundle.spk),
    bState: initResponder(b.sk, spkPriv, bundle.spk),
  };
}

async function send(s: RatchetState, text: string, ad: Uint8Array) {
  return ratchetEncrypt(s, utf8(text), ad, suite);
}
async function recv(s: RatchetState, m: RatchetMessage, ad: Uint8Array) {
  const r = await ratchetDecrypt(s, m, ad, suite);
  return { state: r.state, text: fromUtf8(r.plaintext) };
}

describe('X3DH handshake', () => {
  it('both sides derive the same shared secret and associated data', () => {
    const s = setup();
    expect(toHex(s.sk[0])).toBe(toHex(s.sk[1]));
    expect(toHex(s.ad)).toBe(toHex(s.adB));
  });

  it('rejects a prekey bundle whose signature does not verify (substituted SPK)', () => {
    const bob = generateIdentity();
    const { bundle } = createPrekeyBundle(bob);
    const evil = createPrekeyBundle(generateIdentity()).bundle;
    const tampered = { ...bundle, spk: evil.spk };
    expect(verifyBundle(bundle)).toBe(true);
    expect(verifyBundle(tampered)).toBe(false);
    expect(() => x3dhInitiate(generateIdentity(), tampered)).toThrow(/signature/);
  });

  it('a different initiator identity yields a different secret', () => {
    const bob = generateIdentity();
    const { bundle } = createPrekeyBundle(bob);
    const a1 = x3dhInitiate(generateIdentity(), bundle);
    const a2 = x3dhInitiate(generateIdentity(), bundle);
    expect(toHex(a1.sk)).not.toBe(toHex(a2.sk));
  });
});

describe('Double Ratchet (lite)', () => {
  it('ping-pong conversation decrypts in both directions', async () => {
    let { aState, bState, ad } = setup();
    for (let round = 0; round < 5; round++) {
      const m1 = await send(aState, `a->b ${round}`, ad);
      aState = m1.state;
      const r1 = await recv(bState, m1.msg, ad);
      bState = r1.state;
      expect(r1.text).toBe(`a->b ${round}`);
      const m2 = await send(bState, `b->a ${round}`, ad);
      bState = m2.state;
      const r2 = await recv(aState, m2.msg, ad);
      aState = r2.state;
      expect(r2.text).toBe(`b->a ${round}`);
    }
  });

  it('every message uses a new key: identical plaintexts give different ciphertexts and counters', async () => {
    let { aState, ad } = setup();
    const cts = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const m = await send(aState, 'same', ad);
      aState = m.state;
      expect(m.msg.h.n).toBe(i);
      cts.add(m.msg.ct);
    }
    expect(cts.size).toBe(10);
  });

  it('handles out-of-order delivery with skipped message keys', async () => {
    let { aState, bState, ad } = setup();
    const msgs: RatchetMessage[] = [];
    for (let i = 0; i < 4; i++) {
      const m = await send(aState, `m${i}`, ad);
      aState = m.state;
      msgs.push(m.msg);
    }
    for (const i of [2, 0, 3, 1]) {
      const r = await recv(bState, msgs[i]!, ad);
      bState = r.state;
      expect(r.text).toBe(`m${i}`);
    }
  });

  it('rejects replays of an already-decrypted message', async () => {
    let { aState, bState, ad } = setup();
    const m = await send(aState, 'once', ad);
    aState = m.state;
    bState = (await recv(bState, m.msg, ad)).state;
    await expect(recv(bState, m.msg, ad)).rejects.toThrow();
  });

  it('a tampered message is rejected and does not corrupt the session', async () => {
    let { aState, bState, ad } = setup();
    const m = await send(aState, 'hello', ad);
    aState = m.state;
    const bad = { ...m.msg, ct: m.msg.ct.slice(0, -4) + (m.msg.ct.endsWith('AAAA') ? 'BBBB' : 'AAAA') };
    await expect(recv(bState, bad, ad)).rejects.toThrow();
    const ok = await recv(bState, m.msg, ad); // state was untouched by the failure
    expect(ok.text).toBe('hello');
  });

  it('messages are bound to the session AD (identity keys)', async () => {
    const { aState, bState, ad } = setup();
    const m = await send(aState, 'hello', ad);
    const otherAd = setup().ad;
    await expect(recv(bState, m.msg, otherAd)).rejects.toThrow();
  });

  it('FORWARD SECRECY: a later state cannot decrypt earlier messages', async () => {
    let { aState, bState, ad } = setup();
    const old: RatchetMessage[] = [];
    for (let i = 0; i < 3; i++) {
      const m = await send(aState, `past ${i}`, ad);
      aState = m.state;
      old.push(m.msg);
      bState = (await recv(bState, m.msg, ad)).state;
    }
    // Bob replies and Alice answers, rotating the DH ratchet twice.
    const r = await send(bState, 'reply', ad);
    bState = r.state;
    aState = (await recv(aState, r.msg, ad)).state;
    const n = await send(aState, 'new', ad);
    aState = n.state;
    bState = (await recv(bState, n.msg, ad)).state;

    // Attacker steals Bob's CURRENT state: none of the past messages open.
    const stolen: RatchetState = JSON.parse(JSON.stringify(bState));
    for (const m of old) await expect(ratchetDecrypt(stolen, m, ad, suite)).rejects.toThrow();
    // ...and no key material from those chains remains in the state.
    expect(Object.keys(stolen.skipped)).toHaveLength(0);
  });

  it('POST-COMPROMISE RECOVERY: a stolen state stops working after a DH ratchet round trip', async () => {
    let { aState, bState, ad } = setup();
    const first = await send(aState, 'first', ad);
    aState = first.state;
    bState = (await recv(bState, first.msg, ad)).state;

    // Compromise: a passive attacker copies Bob's whole state and keeps
    // following the conversation, updating her copy whenever she can decrypt.
    let eve: RatchetState = JSON.parse(JSON.stringify(bState));

    // Same chain: Eve CAN read it (expected - no fresh DH yet).
    const a1 = await send(aState, 'same chain', ad);
    aState = a1.state;
    const e1 = await recv(eve, a1.msg, ad);
    eve = e1.state;
    expect(e1.text).toBe('same chain');
    bState = (await recv(bState, a1.msg, ad)).state;

    // Bob replies with a ratchet key generated BEFORE the compromise, so
    // Alice's next message is still readable by Eve.
    const b1 = await send(bState, 'reply 1', ad);
    bState = b1.state;
    aState = (await recv(aState, b1.msg, ad)).state;
    const a2 = await send(aState, 'still exposed', ad);
    aState = a2.state;
    const e2 = await recv(eve, a2.msg, ad);
    eve = e2.state;
    expect(e2.text).toBe('still exposed');
    bState = (await recv(bState, a2.msg, ad)).state;

    // Receiving a2 made Bob generate a NEW ratchet key pair Eve never saw.
    const b2 = await send(bState, 'reply 2', ad);
    bState = b2.state;
    aState = (await recv(aState, b2.msg, ad)).state;
    const a3 = await send(aState, 'after healing', ad);
    aState = a3.state;

    await expect(ratchetDecrypt(eve, a3.msg, ad, suite)).rejects.toThrow();
    expect((await recv(bState, a3.msg, ad)).text).toBe('after healing');
  });

  it('responder cannot send before receiving the first message', async () => {
    const { bState, ad } = setup();
    await expect(send(bState, 'too early', ad)).rejects.toThrow(/no sending chain/);
  });

  it('refuses to skip an unreasonable number of messages (DoS bound)', async () => {
    let { aState, bState, ad } = setup();
    let last: RatchetMessage | undefined;
    for (let i = 0; i < 70; i++) {
      const m = await send(aState, 'x', ad);
      aState = m.state;
      last = m.msg;
    }
    await expect(recv(bState, last!, ad)).rejects.toThrow(/skipped/);
  });
});

describe('safety numbers', () => {
  const a = publicIdentity(generateIdentity());
  const b = publicIdentity(generateIdentity());

  it('are symmetric, 60 digits, shown as 12 groups of 5', () => {
    const n = safetyNumber(a, b);
    expect(n).toMatch(/^\d{60}$/);
    expect(safetyNumber(b, a)).toBe(n);
    expect(formatSafetyNumber(n)).toHaveLength(12);
  });

  it('change when either key changes (key-change warnings)', () => {
    const c = publicIdentity(generateIdentity());
    expect(safetyNumber(a, c)).not.toBe(safetyNumber(a, b));
    expect(safetyNumber(a, { ...b, x: c.x })).not.toBe(safetyNumber(a, b));
  });

  it('QR verification payload checks both keys and the number', () => {
    const payloadFromB = verificationPayload(b, a);
    expect(checkVerificationPayload(payloadFromB, a, b)).toBe(true);
    const mitm = publicIdentity(generateIdentity());
    expect(checkVerificationPayload(verificationPayload(mitm, a), a, b)).toBe(false);
    expect(checkVerificationPayload('nonsense', a, b)).toBe(false);
    expect(b64u(new Uint8Array([1]))).toBe('AQ');
  });
});
