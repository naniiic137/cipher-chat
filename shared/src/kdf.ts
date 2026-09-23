/**
 * Key derivation.
 *
 *   room secret RK (32 B, per epoch)
 *        | HKDF-SHA-256, salt = "cipherchat/v1/room:<rid>:<epoch>"
 *        +-- "enc"  -> message encryption key
 *        +-- "meta" -> room-header encryption key
 *        +-- "file" -> file-chunk key material
 *        +-- "auth" -> seed of an Ed25519 key pair used ONLY to prove membership
 *
 * Passphrase rooms derive RK with Argon2id (hash-wasm, WebAssembly) or
 * PBKDF2-SHA-256 (Web Crypto, 600k iterations) from a per-room random salt.
 */
import { argon2id } from 'hash-wasm';
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { b64u, fromB64u, randomBytes, utf8, type Bytes } from './encoding.ts';
import { CryptoError } from './suites.ts';

export function hkdf(ikm: Bytes, salt: Bytes, info: string | Bytes, length = 32): Bytes {
  return nobleHkdf(sha256, ikm, salt, typeof info === 'string' ? utf8(info) : info, length);
}

export interface RoomKeys {
  epoch: number;
  enc: Bytes;
  meta: Bytes;
  file: Bytes;
  /** Ed25519 private key derived from the room secret (never leaves the device). */
  authPriv: Bytes;
  /** The "verifier" the relay stores: it can check proofs but cannot derive RK. */
  authPub: Bytes;
}

export function deriveRoomKeys(rk: Bytes, rid: string, epoch: number): RoomKeys {
  if (rk.length !== 32) throw new CryptoError('bad-format', 'room secret must be 32 bytes');
  const salt = utf8(`cipherchat/v1/room:${rid}:${epoch}`);
  const authPriv = hkdf(rk, salt, 'cipherchat/v1/auth');
  return {
    epoch,
    enc: hkdf(rk, salt, 'cipherchat/v1/enc'),
    meta: hkdf(rk, salt, 'cipherchat/v1/meta'),
    file: hkdf(rk, salt, 'cipherchat/v1/file'),
    authPriv,
    authPub: ed25519.getPublicKey(authPriv),
  };
}

// ---------------------------------------------------------------- passphrases

export type KdfParams =
  | { alg: 'argon2id'; salt: string; m: number; t: number; p: number }
  | { alg: 'pbkdf2-sha256'; salt: string; iter: number };

/** Defaults: Argon2id 64 MiB, 3 passes (above OWASP 2024 minimums). */
export const ARGON2_DEFAULT = { m: 65536, t: 3, p: 1 } as const;
export const PBKDF2_DEFAULT_ITER = 600_000;

/**
 * Bounds enforced by clients. The relay stores the KDF parameters (they are
 * needed before anyone has the key), so a malicious relay could try to
 * downgrade them to make offline guessing cheap. Clients refuse weak params.
 */
export const KDF_BOUNDS = {
  argon2: { minM: 19456, maxM: 262144, minT: 2, maxT: 10, minP: 1, maxP: 4 },
  pbkdf2: { minIter: 600_000, maxIter: 5_000_000 },
  saltBytes: 16,
} as const;

export function newKdfParams(alg: KdfParams['alg'] = 'argon2id'): KdfParams {
  const salt = b64u(randomBytes(KDF_BOUNDS.saltBytes));
  return alg === 'argon2id'
    ? { alg, salt, ...ARGON2_DEFAULT }
    : { alg, salt, iter: PBKDF2_DEFAULT_ITER };
}

export function checkKdfParams(p: KdfParams, opts: { allowWeak?: boolean } = {}): void {
  let salt: Bytes;
  try {
    salt = fromB64u(p.salt);
  } catch {
    throw new CryptoError('bad-format', 'invalid KDF salt');
  }
  if (salt.length < KDF_BOUNDS.saltBytes) throw new CryptoError('bad-format', 'KDF salt too short');
  if (opts.allowWeak) return;
  if (p.alg === 'argon2id') {
    const b = KDF_BOUNDS.argon2;
    if (p.m < b.minM || p.m > b.maxM || p.t < b.minT || p.t > b.maxT || p.p < b.minP || p.p > b.maxP) {
      throw new CryptoError('bad-format', 'Argon2id parameters outside the accepted range (possible downgrade)');
    }
  } else if (p.alg === 'pbkdf2-sha256') {
    if (p.iter < KDF_BOUNDS.pbkdf2.minIter || p.iter > KDF_BOUNDS.pbkdf2.maxIter) {
      throw new CryptoError('bad-format', 'PBKDF2 iteration count outside the accepted range (possible downgrade)');
    }
  } else {
    throw new CryptoError('bad-format', 'unknown KDF');
  }
}

export async function argon2idRaw(
  password: Bytes | string,
  salt: Bytes,
  m: number,
  t: number,
  p: number,
  length = 32,
): Promise<Bytes> {
  return argon2id({
    password: typeof password === 'string' ? utf8(password.normalize('NFKC')) : password,
    salt,
    memorySize: m,
    iterations: t,
    parallelism: p,
    hashLength: length,
    outputType: 'binary',
  });
}

export async function pbkdf2Sha256(password: Bytes | string, salt: Bytes, iter: number, length = 32): Promise<Bytes> {
  const subtle = globalThis.crypto.subtle;
  const pw = typeof password === 'string' ? utf8(password.normalize('NFKC')) : password;
  const base = await subtle.importKey('raw', pw as BufferSource, 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations: iter },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** Derive a 32-byte room secret from a passphrase using the room's KDF params. */
export async function passphraseToRoomSecret(
  passphrase: string,
  params: KdfParams,
  opts: { allowWeak?: boolean } = {},
): Promise<Bytes> {
  checkKdfParams(params, opts);
  const salt = fromB64u(params.salt);
  return params.alg === 'argon2id'
    ? argon2idRaw(passphrase, salt, params.m, params.t, params.p)
    : pbkdf2Sha256(passphrase, salt, params.iter);
}

// ------------------------------------------------------------ strength meter

const COMMON = new Set(
  (
    'password 123456 12345678 123456789 qwerty abc123 password1 111111 iloveyou admin welcome letmein ' +
    'monkey dragon football baseball sunshine princess azerty master shadow superman trustno1 hello ' +
    'freedom whatever qazwsx 654321 michael secret login starwars passw0rd 1q2w3e4r zaq12wsx'
  ).split(' '),
);

export interface Strength {
  /** 0 (terrible) .. 4 (excellent) */
  score: 0 | 1 | 2 | 3 | 4;
  bits: number;
  label: string;
  hints: string[];
}

/**
 * A small, honest entropy estimator (not zxcvbn). It deliberately under-rates
 * patterns: repeated characters, keyboard/alphabet runs and common passwords.
 */
export function passphraseStrength(pw: string): Strength {
  const hints: string[] = [];
  if (!pw) return { score: 0, bits: 0, label: 'Empty', hints: ['Enter a passphrase'] };
  const lower = pw.toLowerCase();
  if (COMMON.has(lower.replace(/[^a-z0-9]/g, ''))) {
    return { score: 0, bits: 4, label: 'Very weak', hints: ['This is one of the most common passwords'] };
  }
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9\s]/.test(pw)) pool += 33;
  if (/\s/.test(pw)) pool += 1;
  if (/[^\u0000-\u007f]/.test(pw)) pool += 100;

  // Effective length: collapse runs and sequences.
  let eff = 0;
  for (let i = 0; i < pw.length; i++) {
    const c = pw.charCodeAt(i);
    const prev = pw.charCodeAt(i - 1);
    if (i > 0 && (c === prev || c === prev + 1 || c === prev - 1)) eff += 0.25;
    else eff += 1;
  }
  let bits = eff * Math.log2(Math.max(pool, 2));
  const words = pw.trim().split(/[\s\-_.]+/).filter((w) => w.length >= 3);
  if (words.length >= 4) bits = Math.max(bits, words.length * 11); // diceware-style credit
  if (pw.length < 10) hints.push('Use at least 10-12 characters - a few random words work well');
  if (pool <= 26 && words.length < 4) hints.push('Mix in more words, digits or symbols');
  if (/(.)\1{2,}/.test(pw)) hints.push('Avoid repeated characters');
  if (/(0123|1234|2345|abcd|qwer|asdf)/i.test(pw)) hints.push('Avoid keyboard and alphabet runs');
  bits = Math.round(bits);
  const score: Strength['score'] = bits < 28 ? 0 : bits < 40 ? 1 : bits < 56 ? 2 : bits < 72 ? 3 : 4;
  const label = ['Very weak', 'Weak', 'Fair', 'Strong', 'Excellent'][score]!;
  return { score, bits, label, hints };
}

/** Generates a 125-bit passphrase such as "k7m2q-9xaf3-..." (5 groups of 5 base32 chars). */
export function generatePassphrase(groups = 5): string {
  const alphabet = 'abcdefghijkmnpqrstuvwxyz23456789'; // 32 symbols, no look-alikes
  const out: string[] = [];
  for (let g = 0; g < groups; g++) {
    let s = '';
    for (const b of randomBytes(5)) s += alphabet[b & 31];
    out.push(s);
  }
  return out.join('-');
}
