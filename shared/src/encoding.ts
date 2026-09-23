/**
 * Byte/encoding helpers shared by every module. Kept dependency-free so the
 * same code runs in browsers, Node 22 and the in-browser demo relay.
 */

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

export type Bytes = Uint8Array;

export function utf8(s: string): Bytes {
  return te.encode(s);
}

export function fromUtf8(b: Bytes): string {
  return td.decode(b);
}

export function concat(...parts: Bytes[]): Bytes {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Constant-time comparison (for equal-length inputs). */
export function equalBytes(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function randomBytes(n: number): Bytes {
  const out = new Uint8Array(n);
  // getRandomValues is capped at 65536 bytes per call.
  for (let off = 0; off < n; off += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(off, Math.min(n, off + 65536)));
  }
  return out;
}

export function u32be(n: number): Bytes {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

export function readU32be(b: Bytes, off = 0): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, false);
}

export function toHex(b: Bytes): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(h: string): Bytes {
  const clean = h.replace(/\s+/g, '');
  if (clean.length % 2 !== 0 || /[^0-9a-f]/i.test(clean)) throw new Error('invalid hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < B64.length; i++) B64_LOOKUP[B64.charCodeAt(i)] = i;
// Accept the standard alphabet too when decoding.
B64_LOOKUP['+'.charCodeAt(0)] = 62;
B64_LOOKUP['/'.charCodeAt(0)] = 63;

/** base64url without padding (RFC 4648 section 5). */
export function b64u(b: Bytes): string {
  let out = '';
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + B64[n & 63]!;
  }
  const rem = b.length - i;
  if (rem === 1) {
    const n = b[i]! << 16;
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]!;
  } else if (rem === 2) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8);
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]!;
  }
  return out;
}

export function fromB64u(s: string): Bytes {
  const clean = s.replace(/=+$/, '');
  if (clean.length % 4 === 1) throw new Error('invalid base64');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (let i = 0; i < clean.length; i++) {
    const c = clean.charCodeAt(i);
    const v = c < 128 ? B64_LOOKUP[c]! : -1;
    if (v < 0) throw new Error('invalid base64');
    acc = ((acc << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/** Deterministic JSON (sorted object keys) so both sides hash identical bytes. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

/** Best-effort zeroisation of secrets we no longer need (JS gives no hard guarantees). */
export function wipe(...bufs: (Bytes | undefined | null)[]): void {
  for (const b of bufs) b?.fill(0);
}
