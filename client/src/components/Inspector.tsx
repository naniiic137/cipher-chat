import { useState, type ReactNode } from 'react';
import type { CipherClient, FrameEvent } from '@cipher-chat/shared';
import { Icon } from './Icon.tsx';
import { bytes } from '../lib/util.ts';

const CIPHER_KEYS = new Set(['blob', 'box', 'sig', 'verifier', 'nonce', 'chunks']);
const HIDE = new Set(['ping', 'pong']);
/** Protocol field names/values - a message that is exactly one of these is not a leak. */
const PROTOCOL_WORDS =
  /^(welcome|challenge|joined|presence|persist|header|verifier|create|join|auth|send|chunk|getFile|rekey|rekeyed|leave|left|error|limits|members|history|nonce|blob|box|pub|suite|epoch|true|false|file|chunks|conn|demo|msg)$/;

/** Renders JSON with long ciphertext strings shortened and highlighted. */
function renderValue(v: unknown, key: string | null, depth: number): ReactNode {
  const pad = '  '.repeat(depth);
  if (typeof v === 'string') {
    const cipher = key !== null && CIPHER_KEYS.has(key);
    const shown = v.length > 72 ? `${v.slice(0, 56)}… (+${v.length - 56} chars)` : v;
    return <span className={cipher ? 'cipher' : 's'}>"{shown}"</span>;
  }
  if (Array.isArray(v)) {
    if (!v.length) return '[]';
    if (v.length > 4 && typeof v[0] === 'string') {
      return (
        <>
          [{renderValue(v[0], key, depth)}, <span className="k">… {v.length - 1} more</span>]
        </>
      );
    }
    return (
      <>
        [{'\n'}
        {v.map((x, i) => (
          <span key={i}>
            {pad}  {renderValue(x, key, depth + 1)}
            {i < v.length - 1 ? ',' : ''}
            {'\n'}
          </span>
        ))}
        {pad}]
      </>
    );
  }
  if (v && typeof v === 'object') {
    const entries = Object.entries(v as Record<string, unknown>);
    return (
      <>
        {'{'}
        {'\n'}
        {entries.map(([k, x], i) => (
          <span key={k}>
            {pad}  <span className="k">{k}</span>: {renderValue(x, k, depth + 1)}
            {i < entries.length - 1 ? ',' : ''}
            {'\n'}
          </span>
        ))}
        {pad}
        {'}'}
      </>
    );
  }
  return String(v);
}

function FrameRow({ f, open, onToggle }: { f: FrameEvent; open: boolean; onToggle: () => void }) {
  let parsed: Record<string, unknown> = {};
  try {
    parsed = JSON.parse(f.raw) as Record<string, unknown>;
  } catch {
    /* ignore */
  }
  const t = String(parsed.t ?? '?');
  return (
    <div className={`frame${f.tampered ? ' tampered' : ''}`}>
      <button className="frame-top" onClick={onToggle} aria-expanded={open}>
        <span className={`frame-dir dir-${f.dir}`} title={f.dir === 'out' ? 'sent to relay' : 'received from relay'}>
          <Icon name={f.dir === 'out' ? 'upload' : 'download'} size={13} />
          <span className="sr-only">{f.dir === 'out' ? 'sent to relay' : 'received from relay'}</span>
        </span>
        <span className="frame-t">{t}</span>
        {f.tampered && <span className="chip danger" style={{ height: 18 }}>bit flipped</span>}
        <span className="spacer" />
        <span className="faint">{bytes(f.raw.length)}</span>
        <span className="faint">{new Date(f.at).toLocaleTimeString([], { hour12: false })}</span>
      </button>
      {open && <pre>{renderValue(parsed, null, 0)}</pre>}
    </div>
  );
}

export function Inspector({
  client,
  frames,
  onClose,
  demo,
}: {
  client: CipherClient;
  frames: FrameEvent[];
  tick: number;
  onClose: () => void;
  demo: boolean;
}) {
  const [openIdx, setOpenIdx] = useState<number | null>(0);
  const [armed, setArmed] = useState(client.tamperNext);
  const shown = frames.filter((f) => !HIDE.has(safeT(f.raw)));
  const total = shown.reduce((n, f) => n + f.raw.length, 0);
  // Live self-check: search every observed frame for plaintext this device knows.
  const needles = new Set<string>();
  if (client.displayName.length >= 3) needles.add(client.displayName);
  for (const r of client.rooms.values()) {
    if (r.name.length >= 3) needles.add(r.name);
    for (const m of r.messages.slice(-60)) {
      if (m.text && m.text.length >= 4 && m.kind !== 'system') needles.add(m.text);
      if (m.file?.name) needles.add(m.file.name);
    }
  }
  for (const n of needles) if (n.length < 4 || PROTOCOL_WORDS.test(n)) needles.delete(n);
  const leaks = shown.filter((f) => [...needles].some((n) => f.raw.includes(n))).length;

  return (
    <aside className="inspector" aria-label="What the server sees">
      <div className="inspector-head">
        <div className="row">
          <h3 className="grow">
            <span className="live" aria-hidden /> What the server sees
          </h3>
          <button className="btn ghost sm icon" onClick={onClose} aria-label="Close inspector">
            <Icon name="x" />
          </button>
        </div>
        <p className="small muted" style={{ margin: 0 }}>
          Live frames between this {demo ? 'tab and the demo relay' : 'device and the relay'}, exactly as transmitted. Payloads are
          ciphertext; room names, messages, file names and keys never appear.
        </p>
        <div className="stat-row">
          <div className="stat">
            <div className="v">{shown.length}</div>
            <div className="l">frames</div>
          </div>
          <div className="stat">
            <div className="v">{bytes(total)}</div>
            <div className="l">observed</div>
          </div>
          <div className="stat" title={`Searched every frame for ${needles.size} known plaintext strings (room names, recent messages, file names, your name)`}>
            <div className="v" style={{ color: leaks ? 'var(--danger)' : 'var(--accent)' }}>{leaks}</div>
            <div className="l">plaintext leaks</div>
          </div>
        </div>
        <button
          className={`btn sm ${armed ? 'danger' : ''}`}
          onClick={() => {
            client.tamperNext = !client.tamperNext;
            setArmed(client.tamperNext);
          }}
          aria-pressed={armed}
          title="Flip one bit in the next incoming message, like a malicious relay would"
        >
          <Icon name="zap" size={14} /> {armed ? 'Armed: next incoming message will be corrupted' : 'Simulate a malicious relay (flip a bit)'}
        </button>
        <details className="legend">
          <summary className="small" style={{ cursor: 'pointer', color: 'var(--text-2)' }}>
            What can the relay learn?
          </summary>
          <div style={{ display: 'grid', gap: 4, marginTop: 6 }}>
            <div><b>rid</b> - random 128-bit room id (not the name)</div>
            <div><b>blob</b> - version | suite | epoch | nonce | AEAD ciphertext (padded, signed inside)</div>
            <div><b>header.box</b> - room name, mode and timer, encrypted</div>
            <div><b>verifier / sig</b> - Ed25519 public key and proof of key possession</div>
            <div><b>persist / exp</b> - storage flag and purge time (metadata)</div>
            <div><b>Visible metadata:</b> timing, sizes (bucketed), IP address, room size.</div>
          </div>
        </details>
      </div>
      <div className="frames">
        {shown.length === 0 && <p className="small muted" style={{ padding: 8 }}>No frames yet - send a message.</p>}
        {shown.slice(0, 150).map((f, i) => (
          <FrameRow key={`${f.at}-${i}-${f.raw.length}`} f={f} open={openIdx === i} onToggle={() => setOpenIdx(openIdx === i ? null : i)} />
        ))}
      </div>
    </aside>
  );
}

function safeT(raw: string): string {
  const m = /"t":"([a-zA-Z]+)"/.exec(raw);
  return m?.[1] ?? '';
}
