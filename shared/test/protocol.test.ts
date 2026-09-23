import { describe, expect, it } from 'vitest';
import { b64u, LIMITS, newRoomId, parseClientFrame, randomBytes } from '../src/index.ts';

const rid = newRoomId();
const id = newRoomId();
const key = b64u(randomBytes(32));
const sig = b64u(randomBytes(64));
const header = { pub: { v: 1, suite: 'aes-256-gcm', epoch: 0 }, box: 'AAAA' };
const p = (f: unknown) => parseClientFrame(JSON.stringify(f));

describe('parseClientFrame', () => {
  it.each([
    { t: 'create', rid, verifier: key, header },
    { t: 'join', rid },
    { t: 'leave', rid },
    { t: 'auth', rid, sig },
    { t: 'send', rid, id, blob: 'AAAA', persist: true },
    { t: 'send', rid, id, blob: 'AAAA', persist: false, exp: 123 },
    { t: 'chunk', rid, fid: id, idx: 0, total: 1, blob: 'AAAA' },
    { t: 'getFile', rid, fid: id },
    { t: 'rekey', rid, epoch: 1, verifier: key, header: { ...header, pub: { ...header.pub, epoch: 1 } }, sig },
    { t: 'ping' },
  ])('accepts $t', (f) => {
    expect(p(f)).toEqual(f);
  });

  it('drops unknown extra fields', () => {
    expect(p({ t: 'join', rid, evil: 'x' })).toEqual({ t: 'join', rid });
  });

  it('accepts argon2id and pbkdf2 KDF params in headers', () => {
    const salt = b64u(randomBytes(16));
    expect(p({ t: 'create', rid, verifier: key, header: { ...header, pub: { ...header.pub, kdf: { alg: 'argon2id', salt, m: 65536, t: 3, p: 1 } } } })).not.toBeNull();
    expect(p({ t: 'create', rid, verifier: key, header: { ...header, pub: { ...header.pub, kdf: { alg: 'pbkdf2-sha256', salt, iter: 600000 } } } })).not.toBeNull();
    expect(p({ t: 'create', rid, verifier: key, header: { ...header, pub: { ...header.pub, kdf: { alg: 'md5', salt } } } })).toBeNull();
  });

  it.each([
    ['oversized frame', JSON.stringify({ t: 'send', rid, id, blob: 'A'.repeat(LIMITS.maxFrameBytes), persist: true })],
    ['negative exp', JSON.stringify({ t: 'send', rid, id, blob: 'AAAA', persist: true, exp: -1 })],
    ['fractional exp', JSON.stringify({ t: 'send', rid, id, blob: 'AAAA', persist: true, exp: 1.5 })],
    ['idx >= total', JSON.stringify({ t: 'chunk', rid, fid: id, idx: 2, total: 2, blob: 'AAAA' })],
    ['negative idx', JSON.stringify({ t: 'chunk', rid, fid: id, idx: -1, total: 2, blob: 'AAAA' })],
    ['total 0', JSON.stringify({ t: 'chunk', rid, fid: id, idx: 0, total: 0, blob: 'AAAA' })],
    ['too many chunks', JSON.stringify({ t: 'chunk', rid, fid: id, idx: 0, total: LIMITS.maxChunks + 1, blob: 'AAAA' })],
    ['rekey to epoch 0', JSON.stringify({ t: 'rekey', rid, epoch: 0, verifier: key, header, sig })],
    ['unknown suite', JSON.stringify({ t: 'create', rid, verifier: key, header: { ...header, pub: { ...header.pub, suite: 'rot13' } } })],
    ['header version 2', JSON.stringify({ t: 'create', rid, verifier: key, header: { ...header, pub: { ...header.pub, v: 2 } } })],
    ['empty blob', JSON.stringify({ t: 'send', rid, id, blob: '', persist: true })],
    ['null', 'null'],
    ['string', '"join"'],
  ])('rejects %s', (_n, raw) => {
    expect(parseClientFrame(raw)).toBeNull();
  });
});
