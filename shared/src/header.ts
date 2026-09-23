/**
 * Room header = public part (suite, epoch, KDF params - needed before anyone
 * has the key) + secret part (room name, key mode, disappearing timer, 1:1
 * prekey bundle) encrypted under the room "meta" key. The public part is the
 * AAD, so the relay cannot swap the cipher suite or KDF params undetected.
 */
import { b64u, canonicalJson, concat, fromB64u, fromUtf8, utf8 } from './encoding.ts';
import type { RoomKeys } from './kdf.ts';
import type { KeyMode, PublicHeader, RoomHeaderWire } from './protocol.ts';
import { CryptoError, openPacked, sealPacked } from './suites.ts';
import type { PrekeyBundle } from './x3dh.ts';

export interface SecretHeader {
  name: string;
  mode: KeyMode;
  /** Disappearing-message timer in seconds (0 = off). */
  ttl: number;
  createdAt: number;
  createdBy: string;
  /** Present in public-key (1:1) rooms: the creator's signed prekey bundle. */
  bundle?: PrekeyBundle;
}

function headerAad(rid: string, pub: PublicHeader): Uint8Array {
  return concat(utf8('cipherchat/v1/header'), new Uint8Array([0]), utf8(rid), new Uint8Array([0]), utf8(canonicalJson(pub)));
}

export async function sealHeader(
  rid: string,
  pub: PublicHeader,
  secret: SecretHeader,
  keys: RoomKeys,
): Promise<RoomHeaderWire> {
  if (keys.epoch !== pub.epoch) throw new Error('epoch mismatch');
  const box = await sealPacked(pub.suite, keys.meta, utf8(JSON.stringify(secret)), headerAad(rid, pub));
  return { pub, box: b64u(box) };
}

export async function openHeader(rid: string, header: RoomHeaderWire, keys: RoomKeys): Promise<SecretHeader> {
  const pt = await openPacked(header.pub.suite, keys.meta, fromB64u(header.box), headerAad(rid, header.pub));
  let s: unknown;
  try {
    s = JSON.parse(fromUtf8(pt));
  } catch {
    throw new CryptoError('bad-format', 'corrupt room header');
  }
  const h = s as SecretHeader;
  if (typeof h.name !== 'string' || typeof h.ttl !== 'number' || typeof h.mode !== 'string') {
    throw new CryptoError('bad-format', 'corrupt room header');
  }
  return h;
}
