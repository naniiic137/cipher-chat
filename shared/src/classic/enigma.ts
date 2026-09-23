/**
 * Simplified Enigma I: 3 rotors (I-V), reflector B or C, ring settings and a
 * plugboard - including the famous middle-rotor "double step". NOT SECURE.
 * Returns a per-letter trace so the UI can visualise the signal path.
 */

export const ROTORS = {
  I: { wiring: 'EKMFLGDQVZNTOWYHXUSPAIBRCJ', notch: 'Q' },
  II: { wiring: 'AJDKSIRUXBLHWTMCQGZNPYFVOE', notch: 'E' },
  III: { wiring: 'BDFHJLCPRTXVZNYEIWGAKMUSQO', notch: 'V' },
  IV: { wiring: 'ESOVPZJAYQUIRHXLNFTGKDCMWB', notch: 'J' },
  V: { wiring: 'VZBRGITYUPSDNHLXAWMJQOFECK', notch: 'Z' },
} as const;
export type RotorName = keyof typeof ROTORS;

export const REFLECTORS = {
  B: 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
  C: 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
} as const;
export type ReflectorName = keyof typeof REFLECTORS;

export interface EnigmaSettings {
  /** left, middle, right */
  rotors: [RotorName, RotorName, RotorName];
  reflector: ReflectorName;
  /** ring settings (Ringstellung), 0-25, left..right */
  rings: [number, number, number];
  /** start positions (Grundstellung), 0-25, left..right */
  positions: [number, number, number];
  /** e.g. "AB CD EF" */
  plugboard: string;
}

export interface EnigmaStep {
  input: string;
  output: string;
  /** rotor positions AFTER stepping, before encrypting this letter (left..right) */
  positions: [number, number, number];
  /** letters along the path: in, plug, R, M, L, reflector, L, M, R, plug(out) */
  path: string[];
}

const L = (i: number) => String.fromCharCode(65 + (((i % 26) + 26) % 26));
const I = (c: string) => c.charCodeAt(0) - 65;
const mod = (n: number) => ((n % 26) + 26) % 26;

export function parsePlugboard(spec: string): Map<number, number> {
  const map = new Map<number, number>();
  const pairs = spec.toUpperCase().match(/[A-Z]{2}/g) ?? [];
  for (const p of pairs) {
    const x = I(p[0]!);
    const y = I(p[1]!);
    if (x === y || map.has(x) || map.has(y)) throw new Error(`invalid plugboard pair ${p}`);
    map.set(x, y);
    map.set(y, x);
  }
  if (map.size > 26) throw new Error('too many plugboard pairs');
  return map;
}

function rotorPass(wiring: string, c: number, pos: number, ring: number, backwards: boolean): number {
  const shift = pos - ring;
  if (!backwards) {
    const x = I(wiring[mod(c + shift)]!);
    return mod(x - shift);
  }
  const x = wiring.indexOf(L(c + shift));
  return mod(x - shift);
}

/** Advance rotors (with double-stepping). Mutates and returns positions. */
export function stepRotors(s: EnigmaSettings, pos: [number, number, number]): [number, number, number] {
  const [, m, r] = s.rotors;
  const mAtNotch = L(pos[1]) === ROTORS[m].notch;
  const rAtNotch = L(pos[2]) === ROTORS[r].notch;
  if (mAtNotch) {
    pos[0] = mod(pos[0] + 1);
    pos[1] = mod(pos[1] + 1); // the double step
  } else if (rAtNotch) {
    pos[1] = mod(pos[1] + 1);
  }
  pos[2] = mod(pos[2] + 1);
  return pos;
}

/** Encrypt/decrypt (Enigma is reciprocal). Non-letters pass through without stepping. */
export function enigma(text: string, s: EnigmaSettings): { output: string; steps: EnigmaStep[] } {
  const plug = parsePlugboard(s.plugboard);
  const pos: [number, number, number] = [...s.positions];
  const steps: EnigmaStep[] = [];
  let out = '';
  for (const ch of text.toUpperCase()) {
    if (ch < 'A' || ch > 'Z') {
      out += ch === ' ' ? ' ' : ch;
      continue;
    }
    stepRotors(s, pos);
    const path: string[] = [ch];
    let c = I(ch);
    c = plug.get(c) ?? c;
    path.push(L(c));
    for (const idx of [2, 1, 0] as const) {
      c = rotorPass(ROTORS[s.rotors[idx]].wiring, c, pos[idx], s.rings[idx], false);
      path.push(L(c));
    }
    c = I(REFLECTORS[s.reflector][c]!);
    path.push(L(c));
    for (const idx of [0, 1, 2] as const) {
      c = rotorPass(ROTORS[s.rotors[idx]].wiring, c, pos[idx], s.rings[idx], true);
      path.push(L(c));
    }
    c = plug.get(c) ?? c;
    path.push(L(c));
    out += L(c);
    steps.push({ input: ch, output: L(c), positions: [...pos], path });
  }
  return { output: out, steps };
}

export const DEFAULT_ENIGMA: EnigmaSettings = {
  rotors: ['I', 'II', 'III'],
  reflector: 'B',
  rings: [0, 0, 0],
  positions: [0, 0, 0],
  plugboard: '',
};

export const posLabel = (p: [number, number, number]): string => p.map(L).join('');
