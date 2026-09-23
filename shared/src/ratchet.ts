/**
 * Double Ratchet "lite" for 1:1 rooms.
 *
 *  - Symmetric-key ratchet: every message uses a fresh message key derived
 *    from a chain key (HMAC-SHA-256), and the chain key moves forward. Old
 *    message keys are deleted -> forward secrecy.
 *  - DH ratchet: every time the conversation changes direction the replying
 *    side generates a new X25519 key pair and mixes a fresh DH output into the
 *    root key -> post-compromise recovery ("self-healing").
 *
 * State is plain JSON (base64url strings) so it can be persisted in IndexedDB.
 * All operations are functional: they return a NEW state and only when the
 * message authenticates, so a forged message can never corrupt a session.
 *
 * Simplified vs Signal: no header encryption inside the ratchet (the whole
 * ratchet message is itself wrapped in the room-key envelope instead), a small
 * skipped-key cache (MAX_SKIP), one session per peer, no Sesame multi-device.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { b64u, canonicalJson, concat, fromB64u, utf8, type Bytes } from './encoding.ts';
import { dh, x25519Keypair } from './identity.ts';
import { hkdf } from './kdf.ts';
import { CryptoError, openPacked, sealPacked, type SuiteId } from './suites.ts';

export const MAX_SKIP = 64;
const MAX_SKIPPED_TOTAL = 256;

export interface RatchetState {
  rk: string;
  dhsPriv: string;
  dhsPub: string;
  dhr: string | null;
  cks: string | null;
  ckr: string | null;
  ns: number;
  nr: number;
  pn: number;
  /** "<ratchetPub>:<n>" -> message key, for out-of-order delivery */
  skipped: Record<string, string>;
}

export interface RatchetHeader {
  dh: string;
  pn: number;
  n: number;
}

export interface RatchetMessage {
  h: RatchetHeader;
  ct: string;
}

function kdfRk(rk: Bytes, dhOut: Bytes): [Bytes, Bytes] {
  const out = hkdf(dhOut, rk, 'cipherchat/v1/ratchet', 64);
  return [out.slice(0, 32), out.slice(32)];
}

function kdfCk(ck: Bytes): [Bytes, Bytes] {
  const mk = hmac(sha256, ck, new Uint8Array([1]));
  const next = hmac(sha256, ck, new Uint8Array([2]));
  return [next, mk];
}

const clone = (s: RatchetState): RatchetState => ({ ...s, skipped: { ...s.skipped } });

/** Initiator (sent the X3DH init): starts with a sending chain towards the responder's SPK. */
export function initInitiator(sk: Bytes, responderSpk: string): RatchetState {
  const kp = x25519Keypair();
  const [rk, cks] = kdfRk(sk, dh(kp.priv, fromB64u(responderSpk)));
  return {
    rk: b64u(rk),
    dhsPriv: b64u(kp.priv),
    dhsPub: b64u(kp.pub),
    dhr: responderSpk,
    cks: b64u(cks),
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: {},
  };
}

/** Responder: its first ratchet key pair is the signed prekey. */
export function initResponder(sk: Bytes, spkPriv: Bytes, spkPub: string): RatchetState {
  return {
    rk: b64u(sk),
    dhsPriv: b64u(spkPriv),
    dhsPub: spkPub,
    dhr: null,
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: {},
  };
}

function aadFor(ad: Bytes, h: RatchetHeader): Bytes {
  return concat(ad, utf8(canonicalJson(h)));
}

export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: Bytes,
  ad: Bytes,
  suite: SuiteId,
): Promise<{ state: RatchetState; msg: RatchetMessage }> {
  const s = clone(state);
  if (!s.cks) {
    // Responder that has not received anything yet cannot send (no chain).
    throw new CryptoError('ratchet', 'no sending chain yet - wait for the first message');
  }
  const [cks, mk] = kdfCk(fromB64u(s.cks));
  const h: RatchetHeader = { dh: s.dhsPub, pn: s.pn, n: s.ns };
  s.cks = b64u(cks);
  s.ns += 1;
  const ct = await sealPacked(suite, mk, plaintext, aadFor(ad, h));
  mk.fill(0);
  return { state: s, msg: { h, ct: b64u(ct) } };
}

function skipKeys(s: RatchetState, until: number): void {
  if (!s.ckr) return;
  if (until - s.nr > MAX_SKIP) throw new CryptoError('ratchet', 'too many skipped messages');
  let ck = fromB64u(s.ckr);
  while (s.nr < until) {
    const [next, mk] = kdfCk(ck);
    s.skipped[`${s.dhr}:${s.nr}`] = b64u(mk);
    ck = next;
    s.nr += 1;
  }
  s.ckr = b64u(ck);
  const keys = Object.keys(s.skipped);
  for (let i = 0; i < keys.length - MAX_SKIPPED_TOTAL; i++) delete s.skipped[keys[i]!];
}

function dhRatchet(s: RatchetState, h: RatchetHeader): void {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = h.dh;
  const [rk1, ckr] = kdfRk(fromB64u(s.rk), dh(fromB64u(s.dhsPriv), fromB64u(h.dh)));
  const kp = x25519Keypair();
  s.dhsPriv = b64u(kp.priv);
  s.dhsPub = b64u(kp.pub);
  const [rk2, cks] = kdfRk(rk1, dh(kp.priv, fromB64u(h.dh)));
  s.rk = b64u(rk2);
  s.ckr = b64u(ckr);
  s.cks = b64u(cks);
}

export async function ratchetDecrypt(
  state: RatchetState,
  msg: RatchetMessage,
  ad: Bytes,
  suite: SuiteId,
): Promise<{ state: RatchetState; plaintext: Bytes }> {
  const s = clone(state);
  const { h } = msg;
  if (!Number.isInteger(h.n) || !Number.isInteger(h.pn) || h.n < 0 || h.pn < 0 || typeof h.dh !== 'string') {
    throw new CryptoError('bad-format', 'bad ratchet header');
  }
  const ct = fromB64u(msg.ct);
  const skippedId = `${h.dh}:${h.n}`;
  const skippedKey = s.skipped[skippedId];
  if (skippedKey) {
    const plaintext = await openPacked(suite, fromB64u(skippedKey), ct, aadFor(ad, h)).catch(() => {
      throw new CryptoError('auth-failed', 'ratchet message failed to authenticate');
    });
    delete s.skipped[skippedId];
    return { state: s, plaintext };
  }
  if (h.dh !== s.dhr) {
    skipKeys(s, h.pn);
    dhRatchet(s, h);
  }
  skipKeys(s, h.n);
  if (!s.ckr) throw new CryptoError('ratchet', 'no receiving chain');
  if (h.n < s.nr) throw new CryptoError('replay', 'message key already used (replay or duplicate)');
  const [ckr, mk] = kdfCk(fromB64u(s.ckr));
  s.ckr = b64u(ckr);
  s.nr += 1;
  let plaintext: Bytes;
  try {
    plaintext = await openPacked(suite, mk, ct, aadFor(ad, h));
  } catch {
    throw new CryptoError('auth-failed', 'ratchet message failed to authenticate');
  } finally {
    mk.fill(0);
  }
  return { state: s, plaintext };
}
