/**
 * Classic ciphers playground - EDUCATIONAL ONLY. Nothing here is used for chat
 * traffic; the point is to show why these ciphers fail and what modern AEAD fixes.
 */
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import {
  atbash,
  caesar,
  caesarBruteForce,
  DEFAULT_ENIGMA,
  enigma,
  letterFrequency,
  posLabel,
  REFLECTORS,
  ROTORS,
  vigenere,
  xorDecrypt,
  xorEncrypt,
  type EnigmaSettings,
  type ReflectorName,
  type RotorName,
} from '@cipher-chat/shared/classic';
import { Icon } from './Icon.tsx';
import './playground.css';

type TabId = 'caesar' | 'vigenere' | 'xor' | 'atbash' | 'enigma';
const TABS: { id: TabId; label: string }[] = [
  { id: 'caesar', label: 'Caesar' },
  { id: 'vigenere', label: 'Vigenère' },
  { id: 'xor', label: 'XOR' },
  { id: 'atbash', label: 'Atbash' },
  { id: 'enigma', label: 'Enigma' },
];

const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
const ROTOR_NAMES = Object.keys(ROTORS) as RotorName[];
const REFLECTOR_NAMES = Object.keys(REFLECTORS) as ReflectorName[];

/** Relative English letter frequencies (A-Z), used to rank brute-force candidates. */
const ENGLISH = [
  8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4, 6.7, 7.5, 1.9, 0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15,
  2.0, 0.074,
].map((p) => p / 100);

function letterCount(text: string): number {
  let n = 0;
  for (const ch of text.toUpperCase()) if (ch >= 'A' && ch <= 'Z') n++;
  return n;
}

/** Chi-squared distance from English - lower means "looks more like English". */
function chiSquared(text: string): number {
  const n = letterCount(text);
  if (!n) return Infinity;
  const f = letterFrequency(text);
  let score = 0;
  for (let i = 0; i < 26; i++) {
    const expected = ENGLISH[i]! * n;
    const observed = f[i]! * n;
    score += (observed - expected) ** 2 / expected;
  }
  return score;
}

/** Index of coincidence: ~0.066 for English, ~0.038 for uniformly random letters. */
function indexOfCoincidence(text: string): number {
  const n = letterCount(text);
  if (n < 2) return 0;
  const f = letterFrequency(text);
  let sum = 0;
  for (const p of f) {
    const c = p * n;
    sum += c * (c - 1);
  }
  return sum / (n * (n - 1));
}

function hexToBytes(hex: string): number[] {
  const clean = hex.replace(/[^0-9a-f]/gi, '');
  const out: number[] = [];
  for (let i = 0; i + 1 < clean.length; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));
  return out;
}

function xorHex(a: number[], b: number[]): string {
  const n = Math.min(a.length, b.length);
  let s = '';
  for (let i = 0; i < n; i++) s += ((a[i]! ^ b[i]!) & 0xff).toString(16).padStart(2, '0');
  return s;
}

function groupHex(hex: string): string {
  return hex.match(/.{1,2}/g)?.join(' ') ?? '';
}

function prefersReducedMotion(): boolean {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}

// ------------------------------------------------------------ small pieces

function ModeToggle({ decrypt, onChange, label }: { decrypt: boolean; onChange: (d: boolean) => void; label: string }) {
  return (
    <div className="field">
      <span className="label" id={`${label}-mode`}>
        Direction
      </span>
      <div className="seg" role="group" aria-labelledby={`${label}-mode`}>
        <button type="button" aria-pressed={!decrypt} onClick={() => onChange(false)}>
          <Icon name="lock" size={14} /> Encrypt
        </button>
        <button type="button" aria-pressed={decrypt} onClick={() => onChange(true)}>
          <Icon name="unlock" size={14} /> Decrypt
        </button>
      </div>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1400);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <button
      type="button"
      className="btn ghost sm"
      disabled={!text}
      onClick={() => {
        void navigator.clipboard
          ?.writeText(text)
          .then(() => setDone(true))
          .catch(() => {});
      }}
      aria-label="Copy output"
    >
      <Icon name={done ? 'check' : 'copy'} size={14} />
      {done ? 'Copied' : 'Copy'}
    </button>
  );
}

function IO({
  inputLabel,
  input,
  onInput,
  output,
  outputLabel,
  placeholder,
}: {
  inputLabel: string;
  input: string;
  onInput: (s: string) => void;
  output: string;
  outputLabel: string;
  placeholder?: string;
}) {
  const inId = useId();
  const outId = useId();
  return (
    <div className="pg-io">
      <div className="field">
        <label htmlFor={inId}>{inputLabel}</label>
        <textarea
          id={inId}
          className="textarea"
          value={input}
          spellCheck={false}
          placeholder={placeholder}
          onChange={(e) => onInput(e.target.value)}
        />
      </div>
      <div className="field">
        <div className="pg-out-head">
          <span className="label" id={outId}>
            {outputLabel}
          </span>
          <CopyButton text={output} />
        </div>
        <div className="out" role="status" aria-live="polite" aria-labelledby={outId}>
          {output || <span className="faint">-</span>}
        </div>
      </div>
    </div>
  );
}

function FreqBars({ text, caption, dim }: { text: string; caption: string; dim?: boolean }) {
  const f = letterFrequency(text);
  const max = Math.max(...f, 0.0001);
  const top = f
    .map((p, i) => ({ p, l: LETTERS[i]! }))
    .sort((a, b) => b.p - a.p)
    .slice(0, 3)
    .filter((x) => x.p > 0)
    .map((x) => x.l)
    .join(' ');
  return (
    <figure className="pg-freq" style={{ margin: 0 }}>
      <figcaption className="cap">
        <span>{caption}</span>
        <span className="mono muted">{top ? `top: ${top}` : 'no letters'}</span>
      </figcaption>
      <div className={`bars${dim ? ' dim' : ''}`} role="img" aria-label={`${caption} letter frequency histogram, most common: ${top || 'none'}`}>
        {f.map((p, i) => (
          <div key={i} style={{ height: `${(p / max) * 100}%` }} title={`${LETTERS[i]}: ${(p * 100).toFixed(1)}%`} />
        ))}
      </div>
      <div className="bars-l" aria-hidden>
        {LETTERS.map((l) => (
          <span key={l}>{l}</span>
        ))}
      </div>
    </figure>
  );
}

function BreakCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="card section" aria-label={title}>
      <h3 className="row">
        <Icon name="zap" size={16} />
        {title}
      </h3>
      {children}
    </section>
  );
}

// ------------------------------------------------------------ Caesar

function CaesarPanel() {
  const [decrypt, setDecrypt] = useState(false);
  const [text, setText] = useState('ATTACK AT DAWN');
  const [shift, setShift] = useState(3);
  const shiftId = useId();
  const output = caesar(text, shift, decrypt);
  const ciphertext = decrypt ? text : output;
  const candidates = useMemo(() => {
    const all = caesarBruteForce(ciphertext).filter((c) => c.shift > 0);
    const scored = all.map((c) => ({ ...c, score: chiSquared(c.text) }));
    const best = scored.reduce((b, c) => (c.score < b.score ? c : b), scored[0]!);
    return { rows: scored, best: best.shift };
  }, [ciphertext]);

  return (
    <>
      <div className="pg-controls">
        <ModeToggle decrypt={decrypt} onChange={setDecrypt} label="caesar" />
        <div className="field">
          <label htmlFor={shiftId}>Shift (the entire key)</label>
          <div className="pg-range">
            <input id={shiftId} type="range" min={1} max={25} value={shift} onChange={(e) => setShift(Number(e.target.value))} />
            <output htmlFor={shiftId}>{shift}</output>
          </div>
        </div>
      </div>
      <IO
        inputLabel={decrypt ? 'Ciphertext' : 'Plaintext'}
        input={text}
        onInput={setText}
        output={output}
        outputLabel={decrypt ? 'Plaintext' : 'Ciphertext'}
      />
      <BreakCard title="How it breaks: brute force in microseconds">
        <p className="small muted" style={{ margin: 0 }}>
          There are only 25 possible keys. An attacker simply tries all of them and ranks the results by how English they look
          (chi-squared against English letter frequencies). The highlighted row is the computer&apos;s best guess - no key needed.
        </p>
        <div className="pg-brute" tabIndex={0} aria-label="All 25 Caesar decryptions">
          <table>
            <thead>
              <tr>
                <th scope="col">Shift</th>
                <th scope="col">Candidate plaintext</th>
                <th scope="col">χ²</th>
              </tr>
            </thead>
            <tbody>
              {candidates.rows.map((c) => (
                <tr key={c.shift} className={c.shift === candidates.best ? 'best' : undefined}>
                  <td>{c.shift}</td>
                  <td className="txt">{c.text || ' '}</td>
                  <td>{Number.isFinite(c.score) ? c.score.toFixed(0) : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </BreakCard>
    </>
  );
}

// ------------------------------------------------------------ Vigenère

function VigenerePanel() {
  const [decrypt, setDecrypt] = useState(false);
  const [text, setText] = useState('ATTACK AT DAWN. THE ENEMY EXPECTS US AT THE NORTHERN GATE, SO WE MOVE SOUTH AT THE THIRD BELL.');
  const [key, setKey] = useState('LEMON');
  const keyId = useId();
  const output = vigenere(text, key, decrypt);
  const plain = decrypt ? output : text;
  const cipher = decrypt ? text : output;
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, '');

  return (
    <>
      <div className="pg-controls">
        <ModeToggle decrypt={decrypt} onChange={setDecrypt} label="vigenere" />
        <div className="field">
          <label htmlFor={keyId}>Keyword (letters only)</label>
          <input id={keyId} className="input mono" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" spellCheck={false} />
          {!cleanKey && <span className="pg-err">Enter at least one letter - with no key the text passes through unchanged.</span>}
        </div>
      </div>
      <IO
        inputLabel={decrypt ? 'Ciphertext' : 'Plaintext'}
        input={text}
        onInput={setText}
        output={output}
        outputLabel={decrypt ? 'Plaintext' : 'Ciphertext'}
      />
      <BreakCard title="How it breaks: Kasiski and Friedman">
        <p className="small muted" style={{ margin: 0 }}>
          The key repeats every {cleanKey.length || 'n'} letters, so the ciphertext is really {cleanKey.length || 'n'} interleaved
          Caesar ciphers. <b>Kasiski</b>: repeated fragments in the ciphertext sit a multiple of the key length apart.{' '}
          <b>Friedman</b>: the index of coincidence reveals the key length. Split the text into columns, then break each column like
          Caesar using letter frequencies.
        </p>
        <div className="pg-kv">
          <span>Index of coincidence (plaintext)</span>
          <b className="mono">{indexOfCoincidence(plain).toFixed(4)}</b>
          <span>Index of coincidence (ciphertext)</span>
          <b className="mono">{indexOfCoincidence(cipher).toFixed(4)}</b>
          <span>Reference</span>
          <span className="mono small">English ≈ 0.066 · random ≈ 0.038</span>
        </div>
        <div className="grid-2">
          <FreqBars text={plain} caption="Plaintext frequencies" />
          <FreqBars text={cipher} caption="Ciphertext frequencies (flatter)" />
        </div>
      </BreakCard>
    </>
  );
}

// ------------------------------------------------------------ XOR

function XorPanel() {
  const [decrypt, setDecrypt] = useState(false);
  const [plain, setPlain] = useState('ATTACK AT DAWN');
  const [hex, setHex] = useState('');
  const [key, setKey] = useState('k3y');
  const [second, setSecond] = useState('RETREAT AT DUSK');
  const keyId = useId();
  const secondId = useId();

  const encrypted = xorEncrypt(plain, key);
  const input = decrypt ? hex || encrypted : plain;
  let output = '';
  let error = '';
  if (!key) error = 'Enter a key.';
  else if (decrypt) {
    const clean = input.replace(/\s+/g, '');
    if (/[^0-9a-f]/i.test(clean) || clean.length % 2) error = 'Ciphertext must be hex (pairs of 0-9, a-f).';
    else {
      try {
        output = xorDecrypt(clean, key);
      } catch {
        error = 'Could not decode the bytes as UTF-8.';
      }
    }
  } else output = groupHex(encrypted);

  const enc = new TextEncoder();
  const c1 = hexToBytes(xorEncrypt(plain, key));
  const c2 = hexToBytes(xorEncrypt(second, key));
  const cx = xorHex(c1, c2);
  const px = xorHex([...enc.encode(plain)], [...enc.encode(second)]);

  return (
    <>
      <div className="pg-controls">
        <ModeToggle
          decrypt={decrypt}
          onChange={(d) => {
            setDecrypt(d);
            if (d && !hex) setHex(groupHex(encrypted));
          }}
          label="xor"
        />
        <div className="field">
          <label htmlFor={keyId}>Repeating key</label>
          <input id={keyId} className="input mono" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" spellCheck={false} />
        </div>
      </div>
      <IO
        inputLabel={decrypt ? 'Ciphertext (hex)' : 'Plaintext (UTF-8)'}
        input={decrypt ? hex : plain}
        onInput={decrypt ? setHex : setPlain}
        output={error ? '' : output}
        outputLabel={decrypt ? 'Plaintext' : 'Ciphertext (hex)'}
      />
      {error && (
        <p className="pg-err" role="alert" style={{ margin: 0 }}>
          {error}
        </p>
      )}
      <BreakCard title="How it breaks: key reuse cancels out">
        <p className="small muted" style={{ margin: 0 }}>
          Encrypt a second message with the same key. XOR-ing the two ciphertexts removes the key entirely:{' '}
          <span className="mono">C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2</span>. With a guessable word in one message (a
          &ldquo;crib&rdquo;) the other falls out. This is why AEAD ciphers need a unique nonce for every message.
        </p>
        <div className="field">
          <label htmlFor={secondId}>Second plaintext (same key)</label>
          <input id={secondId} className="input mono" value={second} onChange={(e) => setSecond(e.target.value)} spellCheck={false} />
        </div>
        <div className="pg-kv">
          <span>C1 ⊕ C2</span>
          <div className={`pg-hex${cx && cx === px ? ' match' : ''}`}>{groupHex(cx) || '-'}</div>
          <span>P1 ⊕ P2</span>
          <div className={`pg-hex${cx && cx === px ? ' match' : ''}`}>{groupHex(px) || '-'}</div>
        </div>
        <p className="small" role="status" aria-live="polite" style={{ margin: 0 }}>
          {cx && cx === px ? (
            <span className="chip accent">
              <Icon name="check" size={12} /> Identical - the key vanished
            </span>
          ) : (
            <span className="muted">Enter a key and two messages to compare.</span>
          )}
        </p>
      </BreakCard>
    </>
  );
}

// ------------------------------------------------------------ Atbash

function AtbashPanel() {
  const [text, setText] = useState('ATTACK AT DAWN');
  const output = atbash(text);
  return (
    <>
      <p className="small muted" style={{ margin: 0 }}>
        Atbash mirrors the alphabet (A↔Z, B↔Y, …). It is its own inverse, so encrypting and decrypting are the same operation.
      </p>
      <IO inputLabel="Input" input={text} onInput={setText} output={output} outputLabel="Output (apply again to reverse)" />
      <BreakCard title="How it breaks: there is no key at all">
        <p className="small muted" style={{ margin: 0 }}>
          Anyone who knows the method can read every message - it violates Kerckhoffs&apos;s principle (security must rest only on
          the key). The letter frequencies are simply mirrored: E, the most common English letter, always becomes V.
        </p>
        <div className="grid-2">
          <FreqBars text={text} caption="Input frequencies" />
          <FreqBars text={output} caption="Output frequencies (mirrored)" />
        </div>
      </BreakCard>
    </>
  );
}

// ------------------------------------------------------------ Enigma

const PATH_NODES = ['Key', 'Plugboard', 'Rotor R', 'Rotor M', 'Rotor L', 'Reflector', 'Rotor L', 'Rotor M', 'Rotor R', 'Plugboard', 'Lamp'];
const SLOT_NAMES = ['Left', 'Middle', 'Right'] as const;

function EnigmaPanel() {
  const [rotors, setRotors] = useState<[RotorName, RotorName, RotorName]>([...DEFAULT_ENIGMA.rotors]);
  const [rings, setRings] = useState<[number, number, number]>([...DEFAULT_ENIGMA.rings]);
  const [positions, setPositions] = useState<[number, number, number]>([...DEFAULT_ENIGMA.positions]);
  const [reflector, setReflector] = useState<ReflectorName>(DEFAULT_ENIGMA.reflector);
  const [plugboard, setPlugboard] = useState('');
  const [text, setText] = useState('HELLOWORLD');
  const [sel, setSel] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [recip, setRecip] = useState<null | { ok: boolean; back: string }>(null);
  const reduced = useMemo(prefersReducedMotion, []);
  const plugId = useId();
  const textId = useId();
  const outId = useId();
  const baseId = useId();

  const settings: EnigmaSettings = { rotors, rings, positions, reflector, plugboard };
  const result = useMemo(() => {
    try {
      return { res: enigma(text, { rotors, rings, positions, reflector, plugboard }), error: '' };
    } catch (e) {
      return { res: null, error: e instanceof Error ? e.message : String(e) };
    }
  }, [text, rotors, rings, positions, reflector, plugboard]);
  const steps = result.res?.steps ?? [];
  const output = result.res?.output ?? '';
  const current = steps[Math.min(sel, steps.length - 1)];
  const duplicates = new Set(rotors).size < 3;

  useEffect(() => {
    if (sel > 0 && sel >= steps.length) setSel(Math.max(0, steps.length - 1));
  }, [steps.length, sel]);
  useEffect(() => setRecip(null), [text, rotors, rings, positions, reflector, plugboard]);

  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => {
      setSel((s) => {
        if (s + 1 >= steps.length) {
          setPlaying(false);
          return s;
        }
        return s + 1;
      });
    }, 500);
    return () => clearInterval(t);
  }, [playing, steps.length]);

  const setTuple = <T,>(arr: [T, T, T], i: number, v: T): [T, T, T] => {
    const n: [T, T, T] = [...arr];
    n[i] = v;
    return n;
  };

  const windows: [number, number, number] = current ? current.positions : positions;

  const verify = () => {
    try {
      const back = enigma(output, settings).output;
      const norm = (s: string) => s.toUpperCase().replace(/[^A-Z]/g, '');
      setRecip({ ok: norm(back) === norm(text), back });
    } catch {
      setRecip({ ok: false, back: '' });
    }
  };

  return (
    <>
      <div className="pg-rotor-settings" role="group" aria-label="Rotor settings, left to right">
        {SLOT_NAMES.map((slot, i) => (
          <div className="rotor" key={slot}>
            <div className="rotor-title">{slot}</div>
            <div className="field">
              <label className="label" htmlFor={`${baseId}-r${i}`}>
                Rotor
              </label>
              <select
                id={`${baseId}-r${i}`}
                className="select mono"
                value={rotors[i]}
                onChange={(e) => setRotors(setTuple(rotors, i, e.target.value as RotorName))}
              >
                {ROTOR_NAMES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label className="label" htmlFor={`${baseId}-g${i}`}>
                Ring
              </label>
              <select
                id={`${baseId}-g${i}`}
                className="select mono"
                value={rings[i]}
                onChange={(e) => setRings(setTuple(rings, i, Number(e.target.value)))}
              >
                {LETTERS.map((l, k) => (
                  <option key={l} value={k}>
                    {l} ({String(k + 1).padStart(2, '0')})
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label className="label" htmlFor={`${baseId}-p${i}`}>
                Start
              </label>
              <select
                id={`${baseId}-p${i}`}
                className="select mono"
                value={positions[i]}
                onChange={(e) => {
                  setPositions(setTuple(positions, i, Number(e.target.value)));
                  setSel(0);
                }}
              >
                {LETTERS.map((l, k) => (
                  <option key={l} value={k}>
                    {l}
                  </option>
                ))}
              </select>
            </div>
          </div>
        ))}
      </div>
      {duplicates && (
        <div className="callout warn" role="note">
          <Icon name="alert" size={16} />
          <div>A real Enigma I used three different rotors - duplicates work mathematically here but were impossible on the machine.</div>
        </div>
      )}
      <div className="pg-controls">
        <div className="field" style={{ flex: '0 0 auto', minWidth: 0 }}>
          <span className="label" id={`${baseId}-refl`}>
            Reflector
          </span>
          <div className="seg" role="group" aria-labelledby={`${baseId}-refl`}>
            {REFLECTOR_NAMES.map((r) => (
              <button type="button" key={r} aria-pressed={reflector === r} onClick={() => setReflector(r)}>
                UKW-{r}
              </button>
            ))}
          </div>
        </div>
        <div className="field">
          <label htmlFor={plugId}>Plugboard pairs</label>
          <input
            id={plugId}
            className="input mono"
            value={plugboard}
            placeholder="e.g. AB CD EF"
            onChange={(e) => setPlugboard(e.target.value.toUpperCase())}
            aria-invalid={!!result.error}
            aria-describedby={result.error ? `${plugId}-err` : undefined}
            autoComplete="off"
            spellCheck={false}
          />
          {result.error && (
            <span className="pg-err" id={`${plugId}-err`} role="alert">
              {result.error} - each letter may appear in at most one pair.
            </span>
          )}
        </div>
      </div>

      <div className="pg-io">
        <div className="field">
          <label htmlFor={textId}>Input (letters only; spaces pass through)</label>
          <textarea
            id={textId}
            className="textarea"
            value={text}
            spellCheck={false}
            onChange={(e) => {
              setText(e.target.value);
              setSel(0);
            }}
          />
        </div>
        <div className="field">
          <div className="pg-out-head">
            <span className="label" id={outId}>
              Output
            </span>
            <div className="row">
              <button type="button" className="btn ghost sm" onClick={verify} disabled={!output}>
                <Icon name="rotate" size={14} /> Verify reciprocity
              </button>
              <CopyButton text={output} />
            </div>
          </div>
          <div className="out" role="status" aria-live="polite" aria-labelledby={outId}>
            {output || <span className="faint">-</span>}
          </div>
          {recip && (
            <p className="small" role="status" style={{ margin: 0 }}>
              {recip.ok ? (
                <span className="chip accent">
                  <Icon name="check" size={12} /> Same settings turn the output back into the input
                </span>
              ) : (
                <span className="chip">Did not round-trip{recip.back ? `: ${recip.back}` : ''}</span>
              )}
            </p>
          )}
        </div>
      </div>

      <section className="card section" aria-label="Step-by-step visualisation">
        <h3 className="row">
          <Icon name="sparkle" size={16} /> Step-by-step
        </h3>
        <div className="enigma-machine" aria-label="Rotor windows">
          {SLOT_NAMES.map((slot, i) => {
            const name = rotors[i] ?? 'I';
            const letter = LETTERS[windows[i] ?? 0] ?? 'A';
            return (
              <div className="rotor" key={slot}>
                <div className="rl">
                  {slot} · {name}
                </div>
                <div className="window" aria-label={`${slot} rotor shows ${letter}`}>
                  {letter}
                </div>
                <div className="notch">notch {ROTORS[name].notch}</div>
              </div>
            );
          })}
          <div className="rotor refl">
            <div className="rl">Reflector</div>
            <div className="window">UKW-{reflector}</div>
            <div className="notch">{current ? `${current.path[4]} → ${current.path[5]}` : 'fixed'}</div>
          </div>
        </div>

        {steps.length > 0 ? (
          <>
            <div className="tape" role="group" aria-label="Encrypted letters - choose a step">
              {steps.map((s, i) => (
                <button
                  type="button"
                  key={i}
                  aria-pressed={i === sel}
                  aria-label={`Step ${i + 1}: ${s.input} becomes ${s.output}`}
                  onClick={() => {
                    setPlaying(false);
                    setSel(i);
                  }}
                >
                  {s.input}
                  <small>{s.output}</small>
                </button>
              ))}
            </div>
            <div className="pg-transport">
              <button type="button" className="btn sm" onClick={() => setSel((s) => Math.max(0, s - 1))} disabled={sel === 0}>
                <Icon name="back" size={14} /> Prev
              </button>
              <button
                type="button"
                className="btn sm"
                onClick={() => setSel((s) => Math.min(steps.length - 1, s + 1))}
                disabled={sel >= steps.length - 1}
              >
                Next
              </button>
              <button
                type="button"
                className="btn sm primary"
                disabled={reduced || steps.length < 2}
                title={reduced ? 'Animation disabled (prefers-reduced-motion) - use Next' : undefined}
                onClick={() => {
                  if (playing) setPlaying(false);
                  else {
                    if (sel >= steps.length - 1) setSel(0);
                    setPlaying(true);
                  }
                }}
              >
                <Icon name={playing ? 'x' : 'zap'} size={14} /> {playing ? 'Stop' : 'Play'}
              </button>
              <span className="pos" aria-live="polite">
                Step <b>{Math.min(sel, steps.length - 1) + 1}</b>/{steps.length} · rotors at <b>{current ? posLabel(current.positions) : '-'}</b>
              </span>
            </div>
            {current && (
              <div className="pg-path-wrap">
                <div className="path" aria-label={`Signal path for ${current.input}`}>
                  {PATH_NODES.map((n, i) => {
                    const letter = i < 10 ? current.path[i] : current.output;
                    const cls = i === 0 || i === 10 ? 'node on' : i === 5 ? 'node mid' : 'node';
                    return (
                      <div className={cls} key={i}>
                        <div className="l" aria-hidden>
                          {letter}
                        </div>
                        <div className="n">{n}</div>
                        <span className="sr-only">
                          {n}: {letter}
                        </span>
                      </div>
                    );
                  })}
                </div>
                <div className="pg-path-legend">
                  <span>→ forward through R, M, L</span>
                  <span>↩ bounce off the reflector</span>
                  <span>← back through L, M, R and the plugboard to the lamp</span>
                </div>
              </div>
            )}
          </>
        ) : (
          <p className="muted small" style={{ margin: 0 }}>
            Type some letters to see each keypress travel through the machine.
          </p>
        )}
      </section>

      <div className="pg-notes">
        <div className="card">
          <b>
            <Icon name="rotate" size={14} /> Stepping and the double step
          </b>
          The right rotor steps before every letter. At its notch it kicks the middle rotor; the middle rotor at its own notch steps
          itself and the left rotor on the next key - so it moves twice in a row (try start positions A D U).
        </div>
        <div className="card">
          <b>
            <Icon name="key" size={14} /> Reciprocal
          </b>
          Thanks to the reflector, the machine is its own inverse: set the same start positions, type the ciphertext and the
          plaintext lights up. Convenient for operators - and a structural weakness.
        </div>
        <div className="card">
          <b>
            <Icon name="alert" size={14} /> The fatal flaw
          </b>
          A letter can never encrypt to itself. Codebreakers at Bletchley Park slid guessed words (cribs) along intercepts and
          discarded every alignment where a letter matched - the basis of the Bombe.
        </div>
      </div>
    </>
  );
}

// ------------------------------------------------------------ page

export function Playground() {
  const [tab, setTab] = useState<TabId>('caesar');
  const baseId = useId();
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const idx = TABS.findIndex((t) => t.id === tab);
    let next = idx;
    if (e.key === 'ArrowRight') next = (idx + 1) % TABS.length;
    else if (e.key === 'ArrowLeft') next = (idx - 1 + TABS.length) % TABS.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = TABS.length - 1;
    else return;
    e.preventDefault();
    setTab(TABS[next]!.id);
    tabRefs.current[next]?.focus();
  };

  return (
    <div className="page">
      <div className="page-inner">
        <header className="pg-head">
          <div className="row">
            <div className="pg-icon">
              <Icon name="flask" size={20} />
            </div>
            <div>
              <h2>Classic ciphers playground</h2>
              <p className="lead">
                Play with the ciphers that came before modern cryptography - and see exactly how each one is broken.
              </p>
            </div>
          </div>
        </header>

        <div className="insecure-banner" role="note">
          <Icon name="alert" size={20} />
          <div>
            <strong>NOT SECURE</strong> — educational only. These ciphers are broken; CipherChat never uses them for real messages.
            Real chats use AES-256-GCM or (X)ChaCha20-Poly1305 with Ed25519 signatures.
          </div>
        </div>

        <div className="card section" style={{ gap: 0 }}>
          <div className="tabs" role="tablist" aria-label="Cipher" onKeyDown={onKey}>
            {TABS.map((t, i) => (
              <button
                key={t.id}
                ref={(el) => {
                  tabRefs.current[i] = el;
                }}
                type="button"
                role="tab"
                id={`${baseId}-tab-${t.id}`}
                aria-selected={tab === t.id}
                aria-controls={`${baseId}-panel-${t.id}`}
                tabIndex={tab === t.id ? 0 : -1}
                onClick={() => setTab(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div
            className="pg-panel"
            role="tabpanel"
            id={`${baseId}-panel-${tab}`}
            aria-labelledby={`${baseId}-tab-${tab}`}
            tabIndex={0}
          >
            {tab === 'caesar' && <CaesarPanel />}
            {tab === 'vigenere' && <VigenerePanel />}
            {tab === 'xor' && <XorPanel />}
            {tab === 'atbash' && <AtbashPanel />}
            {tab === 'enigma' && <EnigmaPanel />}
          </div>
        </div>
      </div>
    </div>
  );
}
