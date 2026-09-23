import { describe, expect, it } from 'vitest';
import {
  atbash,
  caesar,
  caesarBruteForce,
  DEFAULT_ENIGMA,
  enigma,
  letterFrequency,
  parsePlugboard,
  posLabel,
  vigenere,
  xorDecrypt,
  xorEncrypt,
  type EnigmaSettings,
} from '../src/classic/index.ts';

describe('Caesar', () => {
  it('HELLO + 3 = KHOOR and back', () => {
    expect(caesar('HELLO', 3)).toBe('KHOOR');
    expect(caesar('KHOOR', 3, true)).toBe('HELLO');
  });
  it('preserves case and punctuation, wraps around', () => {
    expect(caesar('Hello, World! xyz', 3)).toBe('Khoor, Zruog! abc');
    expect(caesar(caesar('Mixed Case 123.', 17), 17, true)).toBe('Mixed Case 123.');
  });
  it('brute force finds the answer at the right shift', () => {
    const all = caesarBruteForce(caesar('attack at dawn', 11));
    expect(all).toHaveLength(26);
    expect(all[11]).toEqual({ shift: 11, text: 'attack at dawn' });
  });
});

describe('Vigenere', () => {
  it('ATTACKATDAWN / LEMON = LXFOPVEFRNHR', () => {
    expect(vigenere('ATTACKATDAWN', 'LEMON')).toBe('LXFOPVEFRNHR');
    expect(vigenere('LXFOPVEFRNHR', 'LEMON', true)).toBe('ATTACKATDAWN');
  });
  it('non-letters do not advance the key', () => {
    expect(vigenere('ATTACK AT DAWN!', 'LEMON')).toBe('LXFOPV EF RNHR!');
    expect(vigenere('LXFOPV EF RNHR!', 'lemon', true)).toBe('ATTACK AT DAWN!');
  });
  it('an empty/non-letter key is a no-op', () => {
    expect(vigenere('abc', '123')).toBe('abc');
  });
});

describe('Atbash', () => {
  it('HELLO = SVOOL and is an involution', () => {
    expect(atbash('HELLO')).toBe('SVOOL');
    expect(atbash('abc XYZ')).toBe('zyx CBA');
    expect(atbash(atbash('Round trip, ok?'))).toBe('Round trip, ok?');
  });
});

describe('XOR', () => {
  it('round-trips UTF-8 and outputs lowercase hex', () => {
    const ct = xorEncrypt('héllo wörld ✓', 'key');
    expect(ct).toMatch(/^[0-9a-f]+$/);
    expect(ct.length % 2).toBe(0);
    expect(xorDecrypt(ct, 'key')).toBe('héllo wörld ✓');
  });
  it('known byte: "A" xor "a" = 0x20', () => {
    expect(xorEncrypt('A', 'a')).toBe('20');
  });
  it('empty key yields empty output', () => {
    expect(xorEncrypt('x', '')).toBe('');
    expect(xorDecrypt('20', '')).toBe('');
  });
});

describe('letterFrequency', () => {
  it('sums to 1 and counts letters only', () => {
    const f = letterFrequency('Hello, World!');
    expect(f).toHaveLength(26);
    expect(f.reduce((a, b) => a + b, 0)).toBeCloseTo(1, 10);
    expect(f[11]).toBeCloseTo(3 / 10); // L
    expect(letterFrequency('123').every((x) => x === 0)).toBe(true);
  });
});

describe('Enigma I', () => {
  const s = (over: Partial<EnigmaSettings> = {}): EnigmaSettings => ({ ...DEFAULT_ENIGMA, ...over });

  it('I-II-III, B, rings AAA, start AAA: AAAAA -> BDZGO', () => {
    expect(enigma('AAAAA', s()).output).toBe('BDZGO');
    expect(enigma('BDZGO', s()).output).toBe('AAAAA');
  });

  it('double-steps the middle rotor: ADU -> ADV, AEW, BFX, BFY', () => {
    const { steps } = enigma('AAAA', s({ positions: [0, 3, 20] }));
    expect(steps.map((x) => posLabel(x.positions))).toEqual(['ADV', 'AEW', 'BFX', 'BFY']);
  });

  it('is reciprocal with a plugboard and non-zero rings', () => {
    const cfg = s({
      rotors: ['IV', 'II', 'V'],
      reflector: 'C',
      rings: [5, 12, 23],
      positions: [7, 4, 19],
      plugboard: 'AB CD EF GH IJ KL MN OP QR ST',
    });
    const pt = 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG';
    const ct = enigma(pt, cfg).output;
    expect(ct).not.toBe(pt);
    expect(enigma(ct, cfg).output).toBe(pt);
  });

  it('never encrypts a letter to itself', () => {
    let text = '';
    for (let i = 0; i < 2000; i++) text += String.fromCharCode(65 + ((i * 7919 + (i >> 3)) % 26));
    const { steps } = enigma(text, s({ plugboard: 'QW ER TY', positions: [3, 9, 17], rings: [1, 2, 3] }));
    expect(steps).toHaveLength(2000);
    for (const st of steps) expect(st.output).not.toBe(st.input);
  });

  it('non-letters pass through without stepping; trace has 10 hops', () => {
    const r = enigma('AA A', s());
    expect(r.output).toBe('BD Z');
    expect(r.steps[0]!.path).toHaveLength(10);
    expect(r.steps[0]!.path[0]).toBe('A');
    expect(r.steps[0]!.path[9]).toBe('B');
  });

  it('rejects invalid plugboard pairs', () => {
    expect(() => parsePlugboard('AA')).toThrow();
    expect(() => parsePlugboard('AB AC')).toThrow();
    expect(() => enigma('X', s({ plugboard: 'AB BC' }))).toThrow();
    expect(parsePlugboard('ab cd').get(0)).toBe(1);
  });
});
