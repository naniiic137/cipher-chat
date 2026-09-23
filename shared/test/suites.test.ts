import { describe, expect, it } from 'vitest';
import {
  b64u,
  CryptoError,
  open,
  openPacked,
  randomBytes,
  seal,
  sealPacked,
  SUITE_INFO,
  SUITES,
  utf8,
  fromUtf8,
} from '../src/index.ts';

describe.each(SUITES)('AEAD suite %s', (suite) => {
  const key = randomBytes(32);
  const aad = utf8('header');

  it('round-trips (empty, short and 100 KB plaintexts)', async () => {
    for (const pt of [new Uint8Array(0), utf8('attack at dawn'), randomBytes(100_000)]) {
      const { nonce, ct } = await seal(suite, key, pt, aad);
      expect(nonce.length).toBe(SUITE_INFO[suite].nonceBytes);
      expect(ct.length).toBe(pt.length + 16);
      expect(b64u(await open(suite, key, nonce, ct, aad))).toBe(b64u(pt));
    }
  });

  it('rejects the wrong key', async () => {
    const { nonce, ct } = await seal(suite, key, utf8('secret'), aad);
    await expect(open(suite, randomBytes(32), nonce, ct, aad)).rejects.toMatchObject({ code: 'auth-failed' });
  });

  it('rejects any flipped ciphertext or tag bit', async () => {
    const { nonce, ct } = await seal(suite, key, utf8('secret message'), aad);
    for (const i of [0, 5, ct.length - 1]) {
      const bad = ct.slice();
      bad[i]! ^= 0x80;
      await expect(open(suite, key, nonce, bad, aad)).rejects.toBeInstanceOf(CryptoError);
    }
  });

  it('rejects modified associated data (authenticated header)', async () => {
    const { nonce, ct } = await seal(suite, key, utf8('secret'), aad);
    await expect(open(suite, key, nonce, ct, utf8('headeR'))).rejects.toMatchObject({ code: 'auth-failed' });
  });

  it('rejects a modified nonce', async () => {
    const { nonce, ct } = await seal(suite, key, utf8('secret'), aad);
    const n2 = nonce.slice();
    n2[0]! ^= 1;
    await expect(open(suite, key, n2, ct, aad)).rejects.toMatchObject({ code: 'auth-failed' });
  });

  it('uses a fresh nonce every time (2,000 encryptions, no repeats, different ciphertexts)', async () => {
    const nonces = new Set<string>();
    const cts = new Set<string>();
    const pt = utf8('same plaintext');
    for (let i = 0; i < 2000; i++) {
      const packed = await sealPacked(suite, key, pt, aad);
      const n = SUITE_INFO[suite].nonceBytes;
      nonces.add(b64u(packed.subarray(0, n)));
      cts.add(b64u(packed.subarray(n)));
    }
    expect(nonces.size).toBe(2000);
    expect(cts.size).toBe(2000);
  });

  it('packed helpers round-trip', async () => {
    const packed = await sealPacked(suite, key, utf8('hi'), aad);
    expect(fromUtf8(await openPacked(suite, key, packed, aad))).toBe('hi');
  });

  it('refuses keys that are not 256-bit', async () => {
    await expect(seal(suite, randomBytes(16), utf8('x'), aad)).rejects.toMatchObject({ code: 'bad-format' });
  });
});

it('different suites cannot open each other’s ciphertexts', async () => {
  const key = randomBytes(32);
  const packed = await sealPacked('chacha20-poly1305', key, utf8('x'), new Uint8Array());
  await expect(openPacked('aes-256-gcm', key, packed, new Uint8Array())).rejects.toBeInstanceOf(CryptoError);
});
