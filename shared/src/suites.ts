/**
 * AEAD cipher suites. Every room picks one; the choice is carried in the
 * authenticated (AAD-bound) public part of the room header, so a relay that
 * rewrites it only produces decryption failures.
 *
 *  - AES-256-GCM          : Web Crypto (hardware accelerated), 96-bit random nonce
 *  - ChaCha20-Poly1305    : @noble/ciphers, 96-bit random nonce (RFC 8439)
 *  - XChaCha20-Poly1305   : @noble/ciphers, 192-bit random nonce
 */
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes, type Bytes } from './encoding.ts';

export const SUITES = ['aes-256-gcm', 'chacha20-poly1305', 'xchacha20-poly1305'] as const;
export type SuiteId = (typeof SUITES)[number];

export interface SuiteInfo {
  id: SuiteId;
  code: number;
  label: string;
  nonceBytes: number;
  impl: string;
  blurb: string;
}

export const SUITE_INFO: Record<SuiteId, SuiteInfo> = {
  'aes-256-gcm': {
    id: 'aes-256-gcm',
    code: 1,
    label: 'AES-256-GCM',
    nonceBytes: 12,
    impl: 'Web Crypto',
    blurb: 'Industry default, hardware-accelerated on most CPUs.',
  },
  'chacha20-poly1305': {
    id: 'chacha20-poly1305',
    code: 2,
    label: 'ChaCha20-Poly1305',
    nonceBytes: 12,
    impl: '@noble/ciphers',
    blurb: 'Constant-time in pure software; fast on phones without AES instructions.',
  },
  'xchacha20-poly1305': {
    id: 'xchacha20-poly1305',
    code: 3,
    label: 'XChaCha20-Poly1305',
    nonceBytes: 24,
    impl: '@noble/ciphers',
    blurb: '192-bit nonces: random nonces never realistically collide.',
  },
};

export const TAG_BYTES = 16;

export function isSuite(x: unknown): x is SuiteId {
  return typeof x === 'string' && (SUITES as readonly string[]).includes(x);
}

export function suiteByCode(code: number): SuiteId {
  const s = SUITES.find((id) => SUITE_INFO[id].code === code);
  if (!s) throw new CryptoError('bad-suite', `unknown cipher suite code ${code}`);
  return s;
}

export type CryptoErrorCode =
  | 'auth-failed'
  | 'bad-suite'
  | 'bad-format'
  | 'bad-signature'
  | 'replay'
  | 'expired'
  | 'unknown-epoch'
  | 'ratchet'
  | 'too-large';

export class CryptoError extends Error {
  constructor(
    public readonly code: CryptoErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'CryptoError';
  }
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('Web Crypto (crypto.subtle) is unavailable - use HTTPS or localhost');
  return s;
}

function checkKey(key: Bytes): void {
  if (key.length !== 32) throw new CryptoError('bad-format', 'AEAD keys must be 32 bytes');
}

// Cache imported (non-extractable) AES keys per raw-key object.
const aesCache = new WeakMap<Bytes, Promise<CryptoKey>>();
function aesKey(key: Bytes): Promise<CryptoKey> {
  let k = aesCache.get(key);
  if (!k) {
    k = subtle().importKey('raw', key as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    aesCache.set(key, k);
  }
  return k;
}

/** Encrypt with a fresh random nonce. Returns nonce and ciphertext||tag. */
export async function seal(
  suite: SuiteId,
  key: Bytes,
  plaintext: Bytes,
  aad: Bytes,
  nonce: Bytes = randomBytes(SUITE_INFO[suite].nonceBytes),
): Promise<{ nonce: Bytes; ct: Bytes }> {
  checkKey(key);
  if (nonce.length !== SUITE_INFO[suite].nonceBytes) throw new CryptoError('bad-format', 'wrong nonce length');
  switch (suite) {
    case 'aes-256-gcm': {
      const ct = await subtle().encrypt(
        { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
        await aesKey(key),
        plaintext as BufferSource,
      );
      return { nonce, ct: new Uint8Array(ct) };
    }
    case 'chacha20-poly1305':
      return { nonce, ct: chacha20poly1305(key, nonce, aad).encrypt(plaintext) };
    case 'xchacha20-poly1305':
      return { nonce, ct: xchacha20poly1305(key, nonce, aad).encrypt(plaintext) };
  }
}

/** Decrypt and authenticate. Throws CryptoError('auth-failed') on any tampering. */
export async function open(suite: SuiteId, key: Bytes, nonce: Bytes, ct: Bytes, aad: Bytes): Promise<Bytes> {
  checkKey(key);
  if (nonce.length !== SUITE_INFO[suite].nonceBytes || ct.length < TAG_BYTES) {
    throw new CryptoError('bad-format', 'malformed ciphertext');
  }
  try {
    switch (suite) {
      case 'aes-256-gcm': {
        const pt = await subtle().decrypt(
          { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
          await aesKey(key),
          ct as BufferSource,
        );
        return new Uint8Array(pt);
      }
      case 'chacha20-poly1305':
        return chacha20poly1305(key, nonce, aad).decrypt(ct);
      case 'xchacha20-poly1305':
        return xchacha20poly1305(key, nonce, aad).decrypt(ct);
    }
  } catch {
    throw new CryptoError('auth-failed', 'authentication failed: wrong key or tampered data');
  }
}

/** Convenience: nonce || ciphertext in one buffer. */
export async function sealPacked(suite: SuiteId, key: Bytes, pt: Bytes, aad: Bytes): Promise<Bytes> {
  const { nonce, ct } = await seal(suite, key, pt, aad);
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

export async function openPacked(suite: SuiteId, key: Bytes, packed: Bytes, aad: Bytes): Promise<Bytes> {
  const n = SUITE_INFO[suite].nonceBytes;
  if (packed.length < n + TAG_BYTES) throw new CryptoError('bad-format', 'ciphertext too short');
  return open(suite, key, packed.subarray(0, n), packed.subarray(n), aad);
}
