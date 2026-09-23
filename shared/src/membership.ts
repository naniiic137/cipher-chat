/**
 * Membership proof without revealing the key.
 *
 * A naive "HMAC(authKey, nonce)" challenge-response would force the relay to
 * know authKey. Instead the auth sub-key is used as the seed of an Ed25519 key
 * pair: the relay stores only the PUBLIC key (the "verifier") and checks a
 * signature over a fresh server nonce. So:
 *   - the relay can gate a room without learning any key material,
 *   - a leaked relay database does not let anyone join (it holds public keys),
 *   - a captured proof cannot be replayed (nonce is single-use, bound to rid+epoch).
 * Key separation (HKDF) means the auth key reveals nothing about the enc key.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { b64u, canonicalJson, concat, fromB64u, u32be, utf8, type Bytes } from './encoding.ts';
import { sign, verify } from './identity.ts';
import type { RoomHeaderWire } from './protocol.ts';

const SEP = new Uint8Array([0]);

export function joinTranscript(rid: string, nonce: Bytes, epoch: number): Bytes {
  return concat(utf8('cipherchat/v1/join'), SEP, utf8(rid), SEP, nonce, u32be(epoch));
}

export function proveMembership(authPriv: Bytes, rid: string, nonce: Bytes, epoch: number): string {
  return b64u(sign(authPriv, joinTranscript(rid, nonce, epoch)));
}

export function checkMembership(verifier: string, rid: string, nonce: Bytes, epoch: number, sig: string): boolean {
  try {
    return verify(fromB64u(verifier), joinTranscript(rid, nonce, epoch), fromB64u(sig));
  } catch {
    return false;
  }
}

/** Rekey authorisation: signed with the CURRENT epoch's auth key, bound to the connection's nonce. */
export function rekeyTranscript(
  rid: string,
  newEpoch: number,
  newVerifier: string,
  header: RoomHeaderWire,
  connNonce: Bytes,
): Bytes {
  return concat(
    utf8('cipherchat/v1/rekey'),
    SEP,
    utf8(rid),
    SEP,
    u32be(newEpoch),
    fromB64u(newVerifier),
    sha256(utf8(canonicalJson(header))),
    connNonce,
  );
}

export function signRekey(
  authPriv: Bytes,
  rid: string,
  newEpoch: number,
  newVerifier: string,
  header: RoomHeaderWire,
  connNonce: Bytes,
): string {
  return b64u(sign(authPriv, rekeyTranscript(rid, newEpoch, newVerifier, header, connNonce)));
}

export function checkRekey(
  currentVerifier: string,
  rid: string,
  newEpoch: number,
  newVerifier: string,
  header: RoomHeaderWire,
  connNonce: Bytes,
  sig: string,
): boolean {
  try {
    return verify(
      fromB64u(currentVerifier),
      rekeyTranscript(rid, newEpoch, newVerifier, header, connNonce),
      fromB64u(sig),
    );
  } catch {
    return false;
  }
}
