/**
 * X3DH-style handshake (simplified - see SECURITY.md).
 *
 * The responder (room creator) publishes a prekey bundle inside the encrypted
 * room header: identity keys + a signed prekey (SPK). The initiator computes
 *
 *   DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)   DH3 = DH(EK_A, SPK_B)
 *   SK  = HKDF(0xFF*32 || DH1 || DH2 || DH3)
 *
 * Differences from Signal's X3DH: no one-time prekeys (DH4) and no prekey
 * server - the bundle travels in the (room-key encrypted) header.
 */
import { b64u, concat, fromB64u, utf8, type Bytes } from './encoding.ts';
import { dh, sign, verify, x25519Keypair, type Identity } from './identity.ts';
import { hkdf } from './kdf.ts';
import { CryptoError } from './suites.ts';

export interface PrekeyBundle {
  /** Ed25519 identity (signing) key */
  ed: string;
  /** X25519 identity key */
  x: string;
  /** X25519 signed prekey */
  spk: string;
  /** Ed25519 signature over "cipherchat/v1/spk" || x || spk */
  sig: string;
}

export interface X3dhInit {
  /** initiator's Ed25519 + X25519 identity keys and ephemeral key */
  ed: string;
  x: string;
  ek: string;
}

function spkTranscript(x: Bytes, spk: Bytes): Bytes {
  return concat(utf8('cipherchat/v1/spk'), x, spk);
}

export function createPrekeyBundle(me: Identity): { bundle: PrekeyBundle; spkPriv: Bytes } {
  const spk = x25519Keypair();
  return {
    spkPriv: spk.priv,
    bundle: {
      ed: b64u(me.edPub),
      x: b64u(me.xPub),
      spk: b64u(spk.pub),
      sig: b64u(sign(me.edPriv, spkTranscript(me.xPub, spk.pub))),
    },
  };
}

export function verifyBundle(b: PrekeyBundle): boolean {
  try {
    return verify(fromB64u(b.ed), spkTranscript(fromB64u(b.x), fromB64u(b.spk)), fromB64u(b.sig));
  } catch {
    return false;
  }
}

function deriveSk(dh1: Bytes, dh2: Bytes, dh3: Bytes): Bytes {
  const f = new Uint8Array(32).fill(0xff);
  return hkdf(concat(f, dh1, dh2, dh3), new Uint8Array(32), 'cipherchat/v1/x3dh', 32);
}

/** Associated data binding the session to both parties' identity keys. */
export function sessionAd(initiator: { ed: string; x: string }, responder: { ed: string; x: string }): Bytes {
  return concat(
    fromB64u(initiator.ed),
    fromB64u(initiator.x),
    fromB64u(responder.ed),
    fromB64u(responder.x),
  );
}

export function x3dhInitiate(me: Identity, bundle: PrekeyBundle): { sk: Bytes; ad: Bytes; init: X3dhInit } {
  if (!verifyBundle(bundle)) throw new CryptoError('bad-signature', 'prekey bundle signature is invalid');
  const ek = x25519Keypair();
  const ikB = fromB64u(bundle.x);
  const spkB = fromB64u(bundle.spk);
  const sk = deriveSk(dh(me.xPriv, spkB), dh(ek.priv, ikB), dh(ek.priv, spkB));
  ek.priv.fill(0);
  const init: X3dhInit = { ed: b64u(me.edPub), x: b64u(me.xPub), ek: b64u(ek.pub) };
  return { sk, ad: sessionAd(init, bundle), init };
}

export function x3dhRespond(
  me: Identity,
  spkPriv: Bytes,
  bundle: PrekeyBundle,
  init: X3dhInit,
): { sk: Bytes; ad: Bytes } {
  const ikA = fromB64u(init.x);
  const ekA = fromB64u(init.ek);
  const sk = deriveSk(dh(spkPriv, ikA), dh(me.xPriv, ekA), dh(spkPriv, ekA));
  return { sk, ad: sessionAd(init, bundle) };
}
