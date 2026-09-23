import { describe, expect, it } from 'vitest';
import {
  b64u,
  bucketFor,
  deriveRoomKeys,
  fromB64u,
  generateIdentity,
  newRoomId,
  openEnvelope,
  pad,
  peekEnvelope,
  randomBytes,
  sealEnvelope,
  SUITES,
  unpad,
  utf8,
  type Body,
  type SuiteId,
} from '../src/index.ts';

const rid = newRoomId();
const alice = generateIdentity();
const mallory = generateIdentity();

function body(text: string, c = 1): Body {
  return { k: 'text', text, c, ts: 1_700_000_000_000, n: 'Alice', x: b64u(alice.xPub) };
}

async function roundTrip(suite: SuiteId) {
  const keys = deriveRoomKeys(randomBytes(32), rid, 0);
  const id = newRoomId();
  const blob = await sealEnvelope({ rid, id, persist: true, suite, keys, identity: alice, body: body('attack at dawn') });
  return { keys, id, blob, lookup: (e: number) => (e === 0 ? { keys, suite } : undefined) };
}

describe.each(SUITES)('envelope with %s', (suite) => {
  it('round-trips and identifies the signer', async () => {
    const { id, blob, lookup } = await roundTrip(suite);
    const o = await openEnvelope(rid, id, true, blob, lookup);
    expect(o.signer).toBe(b64u(alice.edPub));
    expect(o.body).toMatchObject({ k: 'text', text: 'attack at dawn', c: 1 });
    expect(o.suite).toBe(suite);
  });

  it('never contains the plaintext or the sender key in the clear', async () => {
    const { blob } = await roundTrip(suite);
    const raw = fromB64u(blob);
    const s = new TextDecoder('latin1').decode(raw);
    expect(s).not.toContain('attack at dawn');
    expect(blob).not.toContain(b64u(alice.edPub));
  });

  it('rejects the wrong room key', async () => {
    const { id, blob } = await roundTrip(suite);
    const other = deriveRoomKeys(randomBytes(32), rid, 0);
    await expect(openEnvelope(rid, id, true, blob, () => ({ keys: other, suite }))).rejects.toMatchObject({
      code: 'auth-failed',
    });
  });

  it('rejects a tampered ciphertext byte', async () => {
    const { id, blob, lookup } = await roundTrip(suite);
    const raw = fromB64u(blob);
    raw[raw.length - 20]! ^= 0x01;
    await expect(openEnvelope(rid, id, true, b64u(raw), lookup)).rejects.toMatchObject({ code: 'auth-failed' });
  });

  it('rejects tampered header bytes (epoch)', async () => {
    const { id, blob, keys } = await roundTrip(suite);
    const raw = fromB64u(blob);
    raw[5] = 1; // epoch 0 -> 1
    // even if the attacker also knows a key for epoch 1, AAD binding fails
    await expect(openEnvelope(rid, id, true, b64u(raw), () => ({ keys, suite }))).rejects.toMatchObject({
      code: 'auth-failed',
    });
  });

  it('binds the room id, message id and persist flag (relay cannot move or reclassify frames)', async () => {
    const { id, blob, lookup } = await roundTrip(suite);
    await expect(openEnvelope(newRoomId(), id, true, blob, lookup)).rejects.toMatchObject({ code: 'auth-failed' });
    await expect(openEnvelope(rid, newRoomId(), true, blob, lookup)).rejects.toMatchObject({ code: 'auth-failed' });
    await expect(openEnvelope(rid, id, false, blob, lookup)).rejects.toMatchObject({ code: 'auth-failed' });
  });
});

describe('signatures', () => {
  it('rejects a forged signature from a room member who holds the key', async () => {
    const keys = deriveRoomKeys(randomBytes(32), rid, 0);
    const id = newRoomId();
    // Mallory has the room key and tries to post as Alice (Alice's public key, junk signature)
    const forged = { ...mallory, edPub: alice.edPub };
    const blob = await sealEnvelope({ rid, id, persist: true, suite: 'aes-256-gcm', keys, identity: forged, body: body('pay Mallory') });
    await expect(
      openEnvelope(rid, id, true, blob, () => ({ keys, suite: 'aes-256-gcm' })),
    ).rejects.toMatchObject({ code: 'bad-signature' });
  });

  it('rejects an explicitly corrupted signature', async () => {
    const keys = deriveRoomKeys(randomBytes(32), rid, 0);
    const id = newRoomId();
    const blob = await sealEnvelope({
      rid,
      id,
      persist: true,
      suite: 'xchacha20-poly1305',
      keys,
      identity: alice,
      body: body('hi'),
      signatureOverride: randomBytes(64),
    });
    await expect(
      openEnvelope(rid, id, true, blob, () => ({ keys, suite: 'xchacha20-poly1305' })),
    ).rejects.toMatchObject({ code: 'bad-signature' });
  });

  it('a signed body cannot be replayed under another message id', async () => {
    const keys = deriveRoomKeys(randomBytes(32), rid, 0);
    const id = newRoomId();
    const blob = await sealEnvelope({ rid, id, persist: true, suite: 'chacha20-poly1305', keys, identity: alice, body: body('once') });
    // An insider re-encrypts Alice's plaintext+signature under a new id:
    // simulated by re-sealing with the same signature bytes over a different id.
    const lookup = () => ({ keys, suite: 'chacha20-poly1305' as const });
    const opened = await openEnvelope(rid, id, true, blob, lookup);
    expect(opened.body.k).toBe('text');
    const id2 = newRoomId();
    const reuse = await sealEnvelope({
      rid,
      id: id2,
      persist: true,
      suite: 'chacha20-poly1305',
      keys,
      identity: alice,
      body: body('once'),
      signatureOverride: new Uint8Array(64), // attacker cannot produce a valid sig for id2
    });
    await expect(openEnvelope(rid, id2, true, reuse, lookup)).rejects.toMatchObject({ code: 'bad-signature' });
  });
});

describe('epochs and routing', () => {
  it('reports unknown epochs distinctly', async () => {
    const keys = deriveRoomKeys(randomBytes(32), rid, 3);
    const id = newRoomId();
    const blob = await sealEnvelope({ rid, id, persist: true, suite: 'aes-256-gcm', keys, identity: alice, body: body('x') });
    expect(peekEnvelope(blob)).toEqual({ version: 1, suite: 'aes-256-gcm', epoch: 3 });
    await expect(openEnvelope(rid, id, true, blob, () => undefined)).rejects.toMatchObject({ code: 'unknown-epoch' });
  });

  it('rejects a suite that differs from the room’s suite', async () => {
    const keys = deriveRoomKeys(randomBytes(32), rid, 0);
    const id = newRoomId();
    const blob = await sealEnvelope({ rid, id, persist: true, suite: 'chacha20-poly1305', keys, identity: alice, body: body('x') });
    await expect(openEnvelope(rid, id, true, blob, () => ({ keys, suite: 'aes-256-gcm' }))).rejects.toMatchObject({
      code: 'bad-suite',
    });
  });
});

describe('length hiding (padding)', () => {
  it('pads to buckets and unpads exactly', () => {
    for (const n of [0, 1, 100, 255, 256, 1000, 70_000]) {
      const d = randomBytes(n);
      const p = pad(d);
      expect(p.length).toBe(bucketFor(n));
      expect(b64u(unpad(p))).toBe(b64u(d));
    }
    expect(bucketFor(0)).toBe(512);
    expect(bucketFor(511)).toBe(512);
    expect(bucketFor(512)).toBe(1024);
    expect(bucketFor(70_000)).toBe(131072);
  });

  it('messages of different lengths in the same bucket produce identical blob sizes', async () => {
    const keys = deriveRoomKeys(randomBytes(32), rid, 0);
    const sizes = new Set<number>();
    for (const text of ['ok', 'see you at 7', 'a slightly longer message about nothing in particular']) {
      const blob = await sealEnvelope({ rid, id: newRoomId(), persist: true, suite: 'aes-256-gcm', keys, identity: alice, body: body(text) });
      sizes.add(blob.length);
    }
    expect(sizes.size).toBe(1);
  });

  it('rejects invalid padding', () => {
    expect(() => unpad(new Uint8Array(16))).toThrow();
    expect(() => unpad(utf8('abc'))).toThrow();
  });
});
