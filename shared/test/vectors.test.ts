/**
 * Published test vectors for every primitive CipherChat builds on, plus a
 * cross-check of the two independent Argon2id implementations.
 */
import { describe, expect, it } from 'vitest';
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { argon2idRaw, fromHex, hkdf, pbkdf2Sha256, toHex, utf8, seal } from '../src/index.ts';

describe('HKDF-SHA-256 (RFC 5869)', () => {
  it('test case 1', () => {
    const ikm = fromHex('0b'.repeat(22));
    const salt = fromHex('000102030405060708090a0b0c');
    const info = fromHex('f0f1f2f3f4f5f6f7f8f9');
    expect(toHex(hkdf(ikm, salt, info, 42))).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });
});

describe('X25519 (RFC 7748 section 6.1)', () => {
  const aPriv = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const bPriv = fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  it('public keys', () => {
    expect(toHex(x25519.getPublicKey(aPriv))).toBe('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    expect(toHex(x25519.getPublicKey(bPriv))).toBe('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  });
  it('shared secret', () => {
    const k = x25519.getSharedSecret(aPriv, x25519.getPublicKey(bPriv));
    expect(toHex(k)).toBe('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
  });
});

describe('Ed25519 (RFC 8032 test 1)', () => {
  const sk = fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  it('public key and signature of the empty message', () => {
    expect(toHex(ed25519.getPublicKey(sk))).toBe('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    expect(toHex(ed25519.sign(new Uint8Array(0), sk))).toBe(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    );
  });
});

describe('ChaCha20-Poly1305 (RFC 8439 section 2.8.2)', () => {
  it('AEAD test vector', () => {
    const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    const nonce = fromHex('070000004041424344454647');
    const aad = fromHex('50515253c0c1c2c3c4c5c6c7');
    const pt = utf8(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    );
    const ct = chacha20poly1305(key, nonce, aad).encrypt(pt);
    expect(toHex(ct.slice(-16))).toBe('1ae10b594f09e26a7e902ecbd0600691');
    expect(toHex(ct.slice(0, 16))).toBe('d31a8d34648e60db7b86afbc53ef7ec2');
  });
  it('our seal() wrapper produces the same bytes for a fixed nonce', async () => {
    const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    const nonce = fromHex('070000004041424344454647');
    const { ct } = await seal('chacha20-poly1305', key, utf8('Ladies'), fromHex('50515253c0c1c2c3c4c5c6c7'), nonce);
    expect(toHex(ct.slice(0, 6))).toBe('d31a8d34648e');
  });
});

describe('PBKDF2-HMAC-SHA-256 (RFC 7914 section 11)', () => {
  it('P="passwd", S="salt", c=1', async () => {
    const dk = await pbkdf2Sha256('passwd', utf8('salt'), 1, 64);
    expect(toHex(dk)).toBe(
      '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
    );
  });
  it('P="Password", S="NaCl", c=80000', async () => {
    const dk = await pbkdf2Sha256('Password', utf8('NaCl'), 80000, 64);
    expect(toHex(dk)).toBe(
      '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d',
    );
  });
});

describe('Argon2id', () => {
  it('reference implementation matches RFC 9106 section 5.3', () => {
    const out = nobleArgon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), {
      t: 3,
      m: 32,
      p: 4,
      dkLen: 32,
      key: new Uint8Array(8).fill(3),
      personalization: new Uint8Array(12).fill(4),
    });
    expect(toHex(out)).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  });

  it('hash-wasm (WebAssembly, used by the app) agrees with the reference implementation', async () => {
    const cases = [
      { pw: 'correct horse battery staple', salt: 'saltsaltsaltsalt', m: 64, t: 2, p: 1 },
      { pw: 'pässwörd', salt: '0123456789abcdef', m: 256, t: 3, p: 2 },
    ];
    for (const c of cases) {
      const ours = await argon2idRaw(c.pw, utf8(c.salt), c.m, c.t, c.p);
      const ref = nobleArgon2id(utf8(c.pw.normalize('NFKC')), utf8(c.salt), { m: c.m, t: c.t, p: c.p, dkLen: 32 });
      expect(toHex(ours)).toBe(toHex(ref));
    }
  });
});
