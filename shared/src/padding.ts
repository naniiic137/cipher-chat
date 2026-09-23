/**
 * Length hiding. Plaintexts are padded (ISO/IEC 7816-4: 0x80 then zeros) up to
 * a bucket size before encryption, so the relay only learns a coarse size
 * class ("short message", "long message", "file chunk"), not the exact length.
 */
import { CryptoError } from './suites.ts';
import type { Bytes } from './encoding.ts';

export const BUCKETS = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] as const;

export function bucketFor(len: number): number {
  // Need at least one byte for the 0x80 marker.
  const need = len + 1;
  for (const b of BUCKETS) if (need <= b) return b;
  const big = BUCKETS[BUCKETS.length - 1]!;
  return Math.ceil(need / big) * big;
}

export function pad(data: Bytes, size = bucketFor(data.length)): Bytes {
  if (size < data.length + 1) throw new CryptoError('too-large', 'padding bucket too small');
  const out = new Uint8Array(size);
  out.set(data, 0);
  out[data.length] = 0x80;
  return out;
}

export function unpad(data: Bytes): Bytes {
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0) i--;
  if (i < 0 || data[i] !== 0x80) throw new CryptoError('bad-format', 'invalid padding');
  return data.subarray(0, i);
}
