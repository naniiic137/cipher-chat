/** Caesar, Vigenere, Atbash and repeating-key XOR. NOT SECURE - educational. */

const A = 65;
const a = 97;

function shiftChar(ch: string, k: number): string {
  const c = ch.charCodeAt(0);
  if (c >= A && c < A + 26) return String.fromCharCode(((c - A + k) % 26 + 26) % 26 + A);
  if (c >= a && c < a + 26) return String.fromCharCode(((c - a + k) % 26 + 26) % 26 + a);
  return ch;
}

export function caesar(text: string, shift: number, decrypt = false): string {
  const k = decrypt ? -shift : shift;
  return [...text].map((ch) => shiftChar(ch, k)).join('');
}

/** All 26 Caesar candidates - shows why a 26-key space is brute-forced instantly. */
export function caesarBruteForce(text: string): { shift: number; text: string }[] {
  return Array.from({ length: 26 }, (_, s) => ({ shift: s, text: caesar(text, s, true) }));
}

export function vigenere(text: string, key: string, decrypt = false): string {
  const shifts = [...key.toUpperCase()].filter((c) => c >= 'A' && c <= 'Z').map((c) => c.charCodeAt(0) - A);
  if (!shifts.length) return text;
  let i = 0;
  return [...text]
    .map((ch) => {
      if (!/[a-z]/i.test(ch)) return ch;
      const k = shifts[i++ % shifts.length]!;
      return shiftChar(ch, decrypt ? -k : k);
    })
    .join('');
}

export function atbash(text: string): string {
  return [...text]
    .map((ch) => {
      const c = ch.charCodeAt(0);
      if (c >= A && c < A + 26) return String.fromCharCode(A + 25 - (c - A));
      if (c >= a && c < a + 26) return String.fromCharCode(a + 25 - (c - a));
      return ch;
    })
    .join('');
}

/** Repeating-key XOR over UTF-8 bytes. Output as hex. */
export function xorEncrypt(text: string, key: string): string {
  const t = new TextEncoder().encode(text);
  const k = new TextEncoder().encode(key);
  if (!k.length) return '';
  return [...t].map((b, i) => (b ^ k[i % k.length]!).toString(16).padStart(2, '0')).join('');
}

export function xorDecrypt(hex: string, key: string): string {
  const clean = hex.replace(/[^0-9a-f]/gi, '');
  const k = new TextEncoder().encode(key);
  if (!k.length || clean.length % 2) return '';
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16) ^ k[i % k.length]!;
  return new TextDecoder().decode(bytes);
}

/** Letter frequency (A-Z) - the classic tool for breaking substitution ciphers. */
export function letterFrequency(text: string): number[] {
  const counts = new Array<number>(26).fill(0);
  let total = 0;
  for (const ch of text.toUpperCase()) {
    const c = ch.charCodeAt(0) - A;
    if (c >= 0 && c < 26) {
      counts[c]!++;
      total++;
    }
  }
  return counts.map((n) => (total ? n / total : 0));
}
