import { describe, expect, it } from 'vitest';
import {
  b64u,
  checkKdfParams,
  checkMembership,
  checkRekey,
  checkReplay,
  deriveRoomKeys,
  generatePassphrase,
  generateIdentity,
  newKdfParams,
  newRoomId,
  openHeader,
  passphraseStrength,
  passphraseToRoomSecret,
  proveMembership,
  randomBytes,
  recordCounter,
  REPLAY_WINDOW,
  sealHeader,
  signRekey,
  toHex,
  type KdfParams,
  type ReplayState,
  type SecretHeader,
} from '../src/index.ts';

describe('room key hierarchy (HKDF key separation)', () => {
  const rk = randomBytes(32);
  const rid = newRoomId();

  it('derives distinct enc / meta / file / auth keys', () => {
    const k = deriveRoomKeys(rk, rid, 0);
    const all = [k.enc, k.meta, k.file, k.authPriv, k.authPub].map(toHex);
    expect(new Set(all).size).toBe(5);
    expect(all.every((h) => h.length === 64)).toBe(true);
  });

  it('is deterministic and bound to room id and epoch', () => {
    const a = deriveRoomKeys(rk, rid, 0);
    expect(toHex(deriveRoomKeys(rk, rid, 0).enc)).toBe(toHex(a.enc));
    expect(toHex(deriveRoomKeys(rk, rid, 1).enc)).not.toBe(toHex(a.enc));
    expect(toHex(deriveRoomKeys(rk, newRoomId(), 0).enc)).not.toBe(toHex(a.enc));
  });

  it('the verifier (auth public key) reveals none of the secret keys', () => {
    const k = deriveRoomKeys(rk, rid, 0);
    const v = toHex(k.authPub);
    for (const secret of [rk, k.enc, k.meta, k.file, k.authPriv]) expect(toHex(secret)).not.toBe(v);
  });
});

describe('passphrase KDFs', () => {
  it('Argon2id: same passphrase + salt -> same key; different salt or passphrase -> different key', async () => {
    const p = newKdfParams('argon2id');
    const k1 = await passphraseToRoomSecret('orbit-velvet-cactus-lantern', p);
    const k2 = await passphraseToRoomSecret('orbit-velvet-cactus-lantern', p);
    const k3 = await passphraseToRoomSecret('orbit-velvet-cactus-lantern', newKdfParams('argon2id'));
    const k4 = await passphraseToRoomSecret('orbit-velvet-cactus-lanterN', p);
    expect(k1.length).toBe(32);
    expect(toHex(k1)).toBe(toHex(k2));
    expect(toHex(k1)).not.toBe(toHex(k3));
    expect(toHex(k1)).not.toBe(toHex(k4));
  });

  it('PBKDF2-SHA-256 fallback uses 600k iterations by default and is deterministic', async () => {
    const p = newKdfParams('pbkdf2-sha256');
    expect(p).toMatchObject({ alg: 'pbkdf2-sha256', iter: 600_000 });
    const k1 = await passphraseToRoomSecret('hunter2-but-longer', p);
    expect(toHex(await passphraseToRoomSecret('hunter2-but-longer', p))).toBe(toHex(k1));
  });

  it('Argon2id defaults meet OWASP guidance (>= 19 MiB, t >= 2)', () => {
    const p = newKdfParams('argon2id');
    expect(p.alg === 'argon2id' && p.m >= 19456 && p.t >= 2).toBe(true);
  });

  it('refuses downgraded parameters supplied by a malicious relay', () => {
    const salt = b64u(randomBytes(16));
    const weak: KdfParams[] = [
      { alg: 'argon2id', salt, m: 8, t: 1, p: 1 },
      { alg: 'argon2id', salt, m: 65536, t: 1, p: 1 },
      { alg: 'pbkdf2-sha256', salt, iter: 1000 },
      { alg: 'argon2id', salt: b64u(randomBytes(4)), m: 65536, t: 3, p: 1 },
    ];
    for (const p of weak) expect(() => checkKdfParams(p)).toThrow();
    expect(() => checkKdfParams({ alg: 'argon2id', salt, m: 10_000_000, t: 3, p: 1 })).toThrow(); // memory DoS
  });

  it('strength meter ranks passphrases sensibly', () => {
    expect(passphraseStrength('password').score).toBe(0);
    expect(passphraseStrength('abc12345').score).toBeLessThanOrEqual(1);
    expect(passphraseStrength('Tr0ub4dor&3').score).toBeGreaterThanOrEqual(2);
    expect(passphraseStrength('correct horse battery staple').score).toBeGreaterThanOrEqual(3);
    expect(passphraseStrength(generatePassphrase()).score).toBe(4);
  });

  it('generates 5x5-character passphrases from a 32-symbol alphabet (125 bits)', () => {
    const p = generatePassphrase();
    expect(p).toMatch(/^[a-z2-9]{5}(-[a-z2-9]{5}){4}$/);
    expect(generatePassphrase()).not.toBe(p);
  });
});

describe('membership proof (server learns only a verifier)', () => {
  const rid = newRoomId();
  const keys = deriveRoomKeys(randomBytes(32), rid, 0);
  const verifier = b64u(keys.authPub);

  it('accepts a proof made with the right key', () => {
    const nonce = randomBytes(32);
    expect(checkMembership(verifier, rid, nonce, 0, proveMembership(keys.authPriv, rid, nonce, 0))).toBe(true);
  });

  it('rejects a proof made with the wrong key', () => {
    const nonce = randomBytes(32);
    const wrong = deriveRoomKeys(randomBytes(32), rid, 0);
    expect(checkMembership(verifier, rid, nonce, 0, proveMembership(wrong.authPriv, rid, nonce, 0))).toBe(false);
  });

  it('a captured proof cannot be replayed against a new nonce, room or epoch', () => {
    const nonce = randomBytes(32);
    const sig = proveMembership(keys.authPriv, rid, nonce, 0);
    expect(checkMembership(verifier, rid, randomBytes(32), 0, sig)).toBe(false);
    expect(checkMembership(verifier, newRoomId(), nonce, 0, sig)).toBe(false);
    expect(checkMembership(verifier, rid, nonce, 1, sig)).toBe(false);
  });

  it('rekey requests must be signed by the current key and bound to the session nonce', async () => {
    const next = deriveRoomKeys(randomBytes(32), rid, 1);
    const header = await sealHeader(rid, { v: 1, suite: 'aes-256-gcm', epoch: 1 }, secret(), next);
    const session = randomBytes(32);
    const nv = b64u(next.authPub);
    const sig = signRekey(keys.authPriv, rid, 1, nv, header, session);
    expect(checkRekey(verifier, rid, 1, nv, header, session, sig)).toBe(true);
    expect(checkRekey(verifier, rid, 1, nv, header, randomBytes(32), sig)).toBe(false);
    expect(checkRekey(verifier, rid, 2, nv, header, session, sig)).toBe(false);
    const outsider = deriveRoomKeys(randomBytes(32), rid, 0);
    expect(checkRekey(verifier, rid, 1, nv, header, session, signRekey(outsider.authPriv, rid, 1, nv, header, session))).toBe(false);
  });
});

function secret(): SecretHeader {
  return { name: 'Project Nightingale', mode: 'link', ttl: 0, createdAt: 1, createdBy: 'Alice' };
}

describe('room header (encrypted + authenticated public part)', () => {
  const rid = newRoomId();
  const keys = deriveRoomKeys(randomBytes(32), rid, 0);

  it('round-trips and hides the room name', async () => {
    const h = await sealHeader(rid, { v: 1, suite: 'xchacha20-poly1305', epoch: 0 }, secret(), keys);
    expect(JSON.stringify(h)).not.toContain('Nightingale');
    expect((await openHeader(rid, h, keys)).name).toBe('Project Nightingale');
  });

  it('detects a relay swapping the cipher suite or KDF parameters', async () => {
    const h = await sealHeader(rid, { v: 1, suite: 'aes-256-gcm', epoch: 0, kdf: newKdfParams('argon2id') }, secret(), keys);
    const swappedSuite = { ...h, pub: { ...h.pub, suite: 'chacha20-poly1305' as const } };
    await expect(openHeader(rid, swappedSuite, keys)).rejects.toThrow();
    const weakened = { ...h, pub: { ...h.pub, kdf: { ...h.pub.kdf!, t: 1 } as KdfParams } };
    await expect(openHeader(rid, weakened, keys)).rejects.toMatchObject({ code: 'auth-failed' });
  });

  it('wrong key cannot read the header', async () => {
    const h = await sealHeader(rid, { v: 1, suite: 'aes-256-gcm', epoch: 0 }, secret(), keys);
    await expect(openHeader(rid, h, deriveRoomKeys(randomBytes(32), rid, 0))).rejects.toMatchObject({ code: 'auth-failed' });
  });
});

describe('replay window', () => {
  const alice = b64u(generateIdentity().edPub);

  it('accepts increasing counters and rejects duplicates', () => {
    const s: ReplayState = {};
    for (const c of [1, 2, 3]) {
      expect(checkReplay(s, alice, c)).toBe('ok');
      recordCounter(s, alice, c);
    }
    expect(checkReplay(s, alice, 2)).toBe('duplicate');
    expect(checkReplay(s, alice, 3)).toBe('duplicate');
  });

  it('tolerates re-ordering inside the window', () => {
    const s: ReplayState = {};
    recordCounter(s, alice, 10);
    expect(checkReplay(s, alice, 7)).toBe('ok');
    recordCounter(s, alice, 7);
    expect(checkReplay(s, alice, 7)).toBe('duplicate');
  });

  it('rejects counters older than the window and invalid counters', () => {
    const s: ReplayState = {};
    recordCounter(s, alice, REPLAY_WINDOW + 10);
    expect(checkReplay(s, alice, 5)).toBe('too-old');
    expect(checkReplay(s, alice, 0)).toBe('too-old');
    expect(checkReplay(s, alice, -1)).toBe('too-old');
    expect(checkReplay(s, alice, 1.5)).toBe('too-old');
  });

  it('tracks senders independently', () => {
    const s: ReplayState = {};
    const bob = b64u(generateIdentity().edPub);
    recordCounter(s, alice, 5);
    expect(checkReplay(s, bob, 5)).toBe('ok');
  });
});
