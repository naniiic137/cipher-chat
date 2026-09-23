/**
 * Message envelope: sign-then-encrypt, padded, AEAD-sealed.
 *
 *   blob = version(1) | suite(1) | epoch(4) | nonce | AEAD(enc_key,
 *            pad( signerEd25519Pub(32) | signature(64) | body JSON ),
 *            aad = "cipherchat/v1/frame" | rid | msgId | version | suite | epoch | persist)
 *
 *   signature = Ed25519(device key, "cipherchat/v1/msg" | rid | msgId | epoch | body)
 *
 * The signature lives INSIDE the ciphertext so the relay cannot even tell
 * which member sent a message. Binding rid + msgId + epoch into the signature
 * stops a member from re-posting someone else's signed body elsewhere.
 */
import { b64u, concat, fromB64u, fromUtf8, readU32be, u32be, utf8, type Bytes } from './encoding.ts';
import { sign, verify, type Identity } from './identity.ts';
import type { RoomKeys } from './kdf.ts';
import { pad, unpad } from './padding.ts';
import type { FileManifest } from './files.ts';
import type { RatchetMessage } from './ratchet.ts';
import type { X3dhInit } from './x3dh.ts';
import { CryptoError, open, seal, SUITE_INFO, suiteByCode, type SuiteId } from './suites.ts';

export const ENVELOPE_VERSION = 1;
const SEP = new Uint8Array([0]);

/** Content types that can travel inside a room envelope. */
export type BodyContent =
  | { k: 'text'; text: string; reply?: string }
  | { k: 'file'; file: FileManifest }
  | { k: 'typing'; on: boolean }
  | { k: 'read'; ids: string[] }
  | { k: 'rekey'; epoch: number; key: string }
  | { k: 'dr'; dr: RatchetMessage; init?: X3dhInit };

export interface BodyMeta {
  /** per-sender counter (replay protection) */
  c: number;
  /** sender timestamp (ms) */
  ts: number;
  /** sender display name (self-asserted - trust comes from the key) */
  n: string;
  /** sender X25519 identity key (for safety numbers) */
  x: string;
  /** disappearing-message deadline (ms since epoch) */
  exp?: number;
}

export type Body = BodyContent & BodyMeta;

export interface OpenedEnvelope {
  /** Ed25519 public key of the signer (base64url) */
  signer: string;
  body: Body;
  epoch: number;
  suite: SuiteId;
}

function frameAad(rid: string, id: string, head: Bytes, persist: boolean): Bytes {
  return concat(utf8('cipherchat/v1/frame'), SEP, utf8(rid), SEP, utf8(id), SEP, head, new Uint8Array([persist ? 1 : 0]));
}

function sigTranscript(rid: string, id: string, epoch: number, body: Bytes): Bytes {
  return concat(utf8('cipherchat/v1/msg'), SEP, utf8(rid), SEP, utf8(id), u32be(epoch), body);
}

export interface SealParams {
  rid: string;
  id: string;
  persist: boolean;
  suite: SuiteId;
  keys: RoomKeys;
  identity: Identity;
  body: Body;
  /** For tests only: override the signature (e.g. forged). */
  signatureOverride?: Bytes;
}

export async function sealEnvelope(p: SealParams): Promise<string> {
  const bodyBytes = utf8(JSON.stringify(p.body));
  const sig = p.signatureOverride ?? sign(p.identity.edPriv, sigTranscript(p.rid, p.id, p.keys.epoch, bodyBytes));
  const plaintext = pad(concat(p.identity.edPub, sig, bodyBytes));
  const head = concat(new Uint8Array([ENVELOPE_VERSION, SUITE_INFO[p.suite].code]), u32be(p.keys.epoch));
  const { nonce, ct } = await seal(p.suite, p.keys.enc, plaintext, frameAad(p.rid, p.id, head, p.persist));
  return b64u(concat(head, nonce, ct));
}

/** Reads only the unauthenticated routing prefix (epoch/suite) - used to pick keys. */
export function peekEnvelope(blob: string): { version: number; suite: SuiteId; epoch: number } {
  const raw = fromB64u(blob);
  if (raw.length < 6) throw new CryptoError('bad-format', 'envelope too short');
  return { version: raw[0]!, suite: suiteByCode(raw[1]!), epoch: readU32be(raw, 2) };
}

export async function openEnvelope(
  rid: string,
  id: string,
  persist: boolean,
  blob: string,
  keysFor: (epoch: number) => { keys: RoomKeys; suite: SuiteId } | undefined,
): Promise<OpenedEnvelope> {
  const raw = fromB64u(blob);
  if (raw.length < 6) throw new CryptoError('bad-format', 'envelope too short');
  if (raw[0] !== ENVELOPE_VERSION) throw new CryptoError('bad-format', 'unsupported envelope version');
  const suite = suiteByCode(raw[1]!);
  const epoch = readU32be(raw, 2);
  const entry = keysFor(epoch);
  if (!entry) throw new CryptoError('unknown-epoch', `no key for epoch ${epoch} on this device`);
  if (entry.suite !== suite) throw new CryptoError('bad-suite', 'cipher suite does not match the room');
  const n = SUITE_INFO[suite].nonceBytes;
  const head = raw.subarray(0, 6);
  const nonce = raw.subarray(6, 6 + n);
  const ct = raw.subarray(6 + n);
  const plaintext = unpad(await open(suite, entry.keys.enc, nonce, ct, frameAad(rid, id, head, persist)));
  if (plaintext.length < 96) throw new CryptoError('bad-format', 'envelope body too short');
  const signer = plaintext.subarray(0, 32);
  const sig = plaintext.subarray(32, 96);
  const bodyBytes = plaintext.subarray(96);
  if (!verify(signer, sigTranscript(rid, id, epoch, bodyBytes), sig)) {
    throw new CryptoError('bad-signature', 'signature does not match the claimed sender');
  }
  let body: Body;
  try {
    body = JSON.parse(fromUtf8(bodyBytes)) as Body;
  } catch {
    throw new CryptoError('bad-format', 'corrupt message body');
  }
  if (typeof body.k !== 'string' || !Number.isSafeInteger(body.c) || typeof body.n !== 'string' || typeof body.x !== 'string') {
    throw new CryptoError('bad-format', 'malformed message body');
  }
  return { signer: b64u(signer), body, epoch, suite };
}
