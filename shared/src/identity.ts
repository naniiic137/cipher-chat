/**
 * Per-device identity: an Ed25519 key pair for signatures and an X25519 key
 * pair for key agreement (X3DH). Private keys never leave the device.
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { b64u, concat, fromB64u, randomBytes, utf8, type Bytes } from './encoding.ts';

export interface Identity {
  edPriv: Bytes;
  edPub: Bytes;
  xPriv: Bytes;
  xPub: Bytes;
}

export interface PublicIdentity {
  ed: string; // b64u Ed25519 public key
  x: string; // b64u X25519 public key
}

export interface IdentityJSON {
  edPriv: string;
  xPriv: string;
}

export function generateIdentity(): Identity {
  const edPriv = randomBytes(32);
  const xPriv = randomBytes(32);
  return { edPriv, edPub: ed25519.getPublicKey(edPriv), xPriv, xPub: x25519.getPublicKey(xPriv) };
}

export function identityToJSON(id: Identity): IdentityJSON {
  return { edPriv: b64u(id.edPriv), xPriv: b64u(id.xPriv) };
}

export function identityFromJSON(j: IdentityJSON): Identity {
  const edPriv = fromB64u(j.edPriv);
  const xPriv = fromB64u(j.xPriv);
  return { edPriv, edPub: ed25519.getPublicKey(edPriv), xPriv, xPub: x25519.getPublicKey(xPriv) };
}

export function publicIdentity(id: Identity): PublicIdentity {
  return { ed: b64u(id.edPub), x: b64u(id.xPub) };
}

export function sign(priv: Bytes, msg: Bytes): Bytes {
  return ed25519.sign(msg, priv);
}

export function verify(pub: Bytes, msg: Bytes, sig: Bytes): boolean {
  try {
    return sig.length === 64 && pub.length === 32 && ed25519.verify(sig, msg, pub);
  } catch {
    return false;
  }
}

export function x25519Keypair(): { priv: Bytes; pub: Bytes } {
  const priv = randomBytes(32);
  return { priv, pub: x25519.getPublicKey(priv) };
}

export function dh(priv: Bytes, pub: Bytes): Bytes {
  return x25519.getSharedSecret(priv, pub);
}

// ------------------------------------------------------------- safety numbers

const FP_ITERATIONS = 1024;

/**
 * 30-digit fingerprint of one identity: iterated SHA-512 over a version tag and
 * both public keys (Signal-style), then six 5-digit chunks.
 */
export function fingerprintDigits(pub: PublicIdentity): string {
  const keys = concat(fromB64u(pub.ed), fromB64u(pub.x));
  let h = sha512(concat(utf8('cipherchat/v1/fingerprint'), keys));
  for (let i = 1; i < FP_ITERATIONS; i++) h = sha512(concat(h, keys));
  let digits = '';
  for (let i = 0; i < 6; i++) {
    const c = h.subarray(i * 5, i * 5 + 5);
    const n = (c[0]! * 2 ** 32 + ((c[1]! << 24) >>> 0) + (c[2]! << 16) + (c[3]! << 8) + c[4]!) % 100000;
    digits += n.toString().padStart(5, '0');
  }
  return digits;
}

/**
 * Safety number for a pair of identities: both fingerprints, sorted so both
 * sides see the same 60 digits. Displayed as 12 groups of 5.
 */
export function safetyNumber(a: PublicIdentity, b: PublicIdentity): string {
  const fa = fingerprintDigits(a);
  const fb = fingerprintDigits(b);
  return fa < fb ? fa + fb : fb + fa;
}

export function formatSafetyNumber(n: string): string[] {
  return n.match(/.{5}/g) ?? [];
}

/** Short, human-friendly key id (first 8 base32-ish chars of the Ed25519 key hash). */
export function shortId(pub: PublicIdentity): string {
  return fingerprintDigits(pub).slice(0, 10).replace(/(\d{5})(\d{5})/, '$1 $2');
}

export const VERIFY_QR_PREFIX = 'cipherchat-verify:v1:';

/** Payload of the verification QR: my keys + the safety number I compute. */
export function verificationPayload(me: PublicIdentity, them: PublicIdentity): string {
  return `${VERIFY_QR_PREFIX}${me.ed}.${me.x}.${safetyNumber(me, them)}`;
}

/** Scanning the other device's QR: it must name their current keys and the same number. */
export function checkVerificationPayload(payload: string, me: PublicIdentity, them: PublicIdentity): boolean {
  if (!payload.startsWith(VERIFY_QR_PREFIX)) return false;
  const [ed, x, num] = payload.slice(VERIFY_QR_PREFIX.length).trim().split('.');
  return ed === them.ed && x === them.x && num === safetyNumber(me, them);
}
