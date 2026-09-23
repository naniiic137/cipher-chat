/**
 * Encrypted file sharing. Files are split into fixed 64 KiB (padded) chunks
 * encrypted client-side. The per-file key mixes the room "file" sub-key with a
 * random per-file secret that only travels inside the (encrypted, signed)
 * manifest message - in 1:1 rooms that manifest rides the Double Ratchet, so
 * files inherit its forward secrecy. The relay stores opaque chunks keyed by a
 * random file id; it never sees names, types or contents.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { b64u, concat, fromB64u, randomBytes, toHex, u32be, utf8, type Bytes } from './encoding.ts';
import { hkdf } from './kdf.ts';
import { pad, unpad } from './padding.ts';
import { LIMITS } from './protocol.ts';
import { CryptoError, openPacked, sealPacked, type SuiteId } from './suites.ts';

export interface FileManifest {
  fid: string;
  name: string;
  mime: string;
  size: number;
  chunks: number;
  /** random per-file secret (base64url) */
  secret: string;
  /** SHA-256 of the plaintext (hex) - integrity of the reassembled file */
  sha256: string;
  epoch: number;
}

const PADDED_CHUNK = 65536;

function chunkKey(roomFileKey: Bytes, fid: string, secret: Bytes): Bytes {
  return hkdf(concat(roomFileKey, secret), utf8(`cipherchat/v1/file:${fid}`), 'cipherchat/v1/chunk');
}

function chunkAad(rid: string, fid: string, idx: number, total: number): Bytes {
  return concat(utf8('cipherchat/v1/chunk'), new Uint8Array([0]), utf8(rid), new Uint8Array([0]), utf8(fid), u32be(idx), u32be(total));
}

export async function encryptFile(
  data: Bytes,
  meta: { name: string; mime: string },
  opts: { rid: string; suite: SuiteId; roomFileKey: Bytes; epoch: number },
): Promise<{ manifest: FileManifest; chunks: string[] }> {
  if (data.length > LIMITS.maxFileBytes) {
    throw new CryptoError('too-large', `files are limited to ${LIMITS.maxFileBytes / 1024 / 1024} MB`);
  }
  const fid = b64u(randomBytes(16));
  const secret = randomBytes(32);
  const key = chunkKey(opts.roomFileKey, fid, secret);
  const total = Math.max(1, Math.ceil(data.length / LIMITS.chunkBytes));
  const chunks: string[] = [];
  for (let i = 0; i < total; i++) {
    const part = data.subarray(i * LIMITS.chunkBytes, (i + 1) * LIMITS.chunkBytes);
    const packed = await sealPacked(opts.suite, key, pad(part, PADDED_CHUNK), chunkAad(opts.rid, fid, i, total));
    chunks.push(b64u(packed));
  }
  key.fill(0);
  return {
    manifest: {
      fid,
      name: meta.name.slice(0, 200),
      mime: meta.mime.slice(0, 100) || 'application/octet-stream',
      size: data.length,
      chunks: total,
      secret: b64u(secret),
      sha256: toHex(sha256(data)),
      epoch: opts.epoch,
    },
    chunks,
  };
}

export async function decryptFile(
  chunks: string[],
  manifest: FileManifest,
  opts: { rid: string; suite: SuiteId; roomFileKey: Bytes },
): Promise<Bytes> {
  if (chunks.length !== manifest.chunks) throw new CryptoError('bad-format', 'missing file chunks');
  const key = chunkKey(opts.roomFileKey, manifest.fid, fromB64u(manifest.secret));
  const parts: Bytes[] = [];
  for (let i = 0; i < chunks.length; i++) {
    const pt = await openPacked(opts.suite, key, fromB64u(chunks[i]!), chunkAad(opts.rid, manifest.fid, i, chunks.length));
    parts.push(unpad(pt));
  }
  key.fill(0);
  const data = concat(...parts);
  if (data.length !== manifest.size || toHex(sha256(data)) !== manifest.sha256) {
    throw new CryptoError('auth-failed', 'file integrity check failed');
  }
  return data;
}
