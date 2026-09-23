/**
 * Wire protocol between clients and the blind relay. Everything the relay can
 * see is defined here - which is exactly what the "What the server sees"
 * inspector shows. Payloads (`blob`, `header.box`) are opaque ciphertext.
 */
import { isSuite, type SuiteId } from './suites.ts';
import type { KdfParams } from './kdf.ts';

export const PROTOCOL_VERSION = 1;

export const LIMITS = {
  /** Max size of one WebSocket text frame (JSON). */
  maxFrameBytes: 200_000,
  /** Max size of a ciphertext blob (base64url chars). */
  maxBlobChars: 180_000,
  /** Plaintext bytes per file chunk; padded chunks are exactly 64 KiB. */
  chunkBytes: 65_520,
  maxFileBytes: 5 * 1024 * 1024,
  maxChunks: 96,
  maxMessageChars: 8_000,
  /** Messages kept per room (oldest dropped first). */
  maxStoredPerRoom: 500,
  maxFilesPerRoom: 40,
  maxMembersPerRoom: 64,
  maxRoomsPerConnection: 32,
} as const;

export type KeyMode = 'link' | 'passphrase' | 'pk' | 'keyfile';

/** Public (server-visible) half of the room header - authenticated as AAD. */
export interface PublicHeader {
  v: 1;
  suite: SuiteId;
  epoch: number;
  kdf?: KdfParams;
}

export interface RoomHeaderWire {
  pub: PublicHeader;
  /** nonce||ciphertext of the SecretHeader under the room "meta" key. */
  box: string;
}

/** Stored ciphertext as the relay keeps it. */
export interface WireMsg {
  id: string;
  blob: string;
  ts: number;
  exp?: number;
}

// ------------------------------------------------------------------ frames

export type ClientFrame =
  | { t: 'create'; rid: string; verifier: string; header: RoomHeaderWire }
  | { t: 'join'; rid: string }
  | { t: 'auth'; rid: string; sig: string }
  | { t: 'send'; rid: string; id: string; blob: string; persist: boolean; exp?: number }
  | { t: 'chunk'; rid: string; fid: string; idx: number; total: number; blob: string; exp?: number }
  | { t: 'getFile'; rid: string; fid: string }
  | { t: 'rekey'; rid: string; epoch: number; verifier: string; header: RoomHeaderWire; sig: string }
  | { t: 'leave'; rid: string }
  | { t: 'ping' };

export type ServerFrame =
  | { t: 'welcome'; v: number; conn: string; limits: typeof LIMITS; demo?: boolean }
  | { t: 'challenge'; rid: string; nonce: string; pub: PublicHeader }
  | { t: 'joined'; rid: string; header: RoomHeaderWire; history: WireMsg[]; members: number; nonce: string }
  | { t: 'msg'; rid: string; id: string; blob: string; ts: number; exp?: number; persist: boolean }
  | { t: 'file'; rid: string; fid: string; chunks: string[] | null }
  | { t: 'rekeyed'; rid: string; epoch: number; header: RoomHeaderWire }
  | { t: 'presence'; rid: string; members: number }
  | { t: 'left'; rid: string }
  | { t: 'error'; code: ErrorCode; msg: string; rid?: string }
  | { t: 'pong' };

export type ErrorCode =
  | 'bad-frame'
  | 'too-large'
  | 'rate-limited'
  | 'no-room'
  | 'exists'
  | 'not-member'
  | 'auth-failed'
  | 'room-full'
  | 'quota'
  | 'stale-epoch'
  | 'forbidden-origin';

// -------------------------------------------------------------- validation

const ID22 = /^[A-Za-z0-9_-]{22}$/; // 16 random bytes, base64url
const KEY43 = /^[A-Za-z0-9_-]{43}$/; // 32 bytes
const SIG86 = /^[A-Za-z0-9_-]{86}$/; // 64 bytes
const B64U = /^[A-Za-z0-9_-]+$/;

export const isId = (x: unknown): x is string => typeof x === 'string' && ID22.test(x);
const isKey = (x: unknown): x is string => typeof x === 'string' && KEY43.test(x);
const isSig = (x: unknown): x is string => typeof x === 'string' && SIG86.test(x);
const isBlob = (x: unknown, max: number = LIMITS.maxBlobChars): x is string =>
  typeof x === 'string' && x.length > 0 && x.length <= max && B64U.test(x);
const isInt = (x: unknown, min: number, max: number): x is number =>
  typeof x === 'number' && Number.isInteger(x) && x >= min && x <= max;
const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

export function isKdfParams(x: unknown): x is KdfParams {
  if (!isObj(x) || typeof x.salt !== 'string' || !B64U.test(x.salt) || x.salt.length > 64) return false;
  if (x.alg === 'argon2id') return isInt(x.m, 8, 4_194_304) && isInt(x.t, 1, 100) && isInt(x.p, 1, 16);
  if (x.alg === 'pbkdf2-sha256') return isInt(x.iter, 1, 50_000_000);
  return false;
}

export function isPublicHeader(x: unknown): x is PublicHeader {
  return (
    isObj(x) &&
    x.v === 1 &&
    isSuite(x.suite) &&
    isInt(x.epoch, 0, 1_000_000) &&
    (x.kdf === undefined || isKdfParams(x.kdf))
  );
}

export function isHeaderWire(x: unknown): x is RoomHeaderWire {
  return isObj(x) && isPublicHeader(x.pub) && isBlob(x.box, 8_000);
}

/** Strict parser for untrusted client frames. Returns null for anything unexpected. */
export function parseClientFrame(raw: string): ClientFrame | null {
  if (raw.length > LIMITS.maxFrameBytes) return null;
  let f: unknown;
  try {
    f = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isObj(f) || typeof f.t !== 'string') return null;
  const expOk = f.exp === undefined || isInt(f.exp, 0, 8.64e15);
  switch (f.t) {
    case 'create':
      return isId(f.rid) && isKey(f.verifier) && isHeaderWire(f.header)
        ? { t: 'create', rid: f.rid, verifier: f.verifier, header: f.header }
        : null;
    case 'join':
    case 'leave':
      return isId(f.rid) ? { t: f.t, rid: f.rid } : null;
    case 'auth':
      return isId(f.rid) && isSig(f.sig) ? { t: 'auth', rid: f.rid, sig: f.sig } : null;
    case 'send':
      return isId(f.rid) && isId(f.id) && isBlob(f.blob) && typeof f.persist === 'boolean' && expOk
        ? { t: 'send', rid: f.rid, id: f.id, blob: f.blob, persist: f.persist, ...(f.exp !== undefined ? { exp: f.exp as number } : {}) }
        : null;
    case 'chunk':
      return isId(f.rid) &&
        isId(f.fid) &&
        isInt(f.total, 1, LIMITS.maxChunks) &&
        isInt(f.idx, 0, (f.total as number) - 1) &&
        isBlob(f.blob) &&
        expOk
        ? {
            t: 'chunk',
            rid: f.rid,
            fid: f.fid,
            idx: f.idx as number,
            total: f.total as number,
            blob: f.blob,
            ...(f.exp !== undefined ? { exp: f.exp as number } : {}),
          }
        : null;
    case 'getFile':
      return isId(f.rid) && isId(f.fid) ? { t: 'getFile', rid: f.rid, fid: f.fid } : null;
    case 'rekey':
      return isId(f.rid) && isInt(f.epoch, 1, 1_000_000) && isKey(f.verifier) && isHeaderWire(f.header) && isSig(f.sig)
        ? { t: 'rekey', rid: f.rid, epoch: f.epoch as number, verifier: f.verifier, header: f.header, sig: f.sig }
        : null;
    case 'ping':
      return { t: 'ping' };
    default:
      return null;
  }
}
