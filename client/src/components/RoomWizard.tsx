import { useId, useState } from 'react';
import {
  ARGON2_DEFAULT,
  generatePassphrase,
  passphraseStrength,
  PBKDF2_DEFAULT_ITER,
  SUITE_INFO,
  SUITES,
  type CipherClient,
  type KeyMode,
  type SuiteId,
} from '@cipher-chat/shared';
import { Callout, Modal } from './Modal.tsx';
import { Icon } from './Icon.tsx';
import { MODE_INFO } from './labels.ts';
import { ttlLabel } from '../lib/util.ts';

const TTLS = [0, 300, 3600, 86400, 604800];
const MODES: KeyMode[] = ['link', 'passphrase', 'pk', 'keyfile'];

export function StrengthMeter({ value }: { value: string }) {
  const s = passphraseStrength(value);
  return (
    <div className="col" style={{ gap: 5 }} aria-live="polite">
      <div className={`meter s${s.score}${value ? '' : ' empty'}`} role="meter" aria-valuemin={0} aria-valuemax={4} aria-valuenow={s.score} aria-label="Passphrase strength">
        <i /> <i /> <i /> <i /> <i />
      </div>
      <div className="row small">
        <span style={{ fontWeight: 600 }}>{value ? s.label : 'Strength'}</span>
        <span className="muted">{value ? `~${s.bits} bits` : ''}</span>
        <span className="spacer" />
        <span className="muted ellipsis">{s.hints[0] ?? (value ? 'Nice.' : '')}</span>
      </div>
    </div>
  );
}

export function RoomWizard({ client, onClose, onCreated }: { client: CipherClient; onClose: () => void; onCreated: (rid: string) => void }) {
  const [step, setStep] = useState(0);
  const [mode, setMode] = useState<KeyMode>('link');
  const [name, setName] = useState('');
  const [pass, setPass] = useState('');
  const [kdf, setKdf] = useState<'argon2id' | 'pbkdf2-sha256'>('argon2id');
  const [suite, setSuite] = useState<SuiteId>('xchacha20-poly1305');
  const [ttl, setTtl] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const ids = { name: useId(), pass: useId() };
  const strength = passphraseStrength(pass);

  const canNext =
    step === 0 ||
    (step === 1 && name.trim().length > 0 && (mode !== 'passphrase' || strength.score >= 2)) ||
    step === 2 ||
    step === 3;

  const create = async () => {
    setBusy(true);
    setErr('');
    try {
      const room = await client.createRoom({ name, mode, suite, ttl, ...(mode === 'passphrase' ? { passphrase: pass, kdf } : {}) });
      onCreated(room.rid);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };

  const titles = ['How will people get the key?', 'Name your room', 'Choose a cipher suite', 'Disappearing messages'];
  const subs = [
    'The key never touches the server. Pick how you will share it.',
    'The name is encrypted with the room key - the relay never sees it.',
    'All three are modern authenticated encryption (AEAD). Pick one per room.',
    'Clients delete expired messages and the relay purges the ciphertext.',
  ];

  return (
    <Modal
      title={titles[step]!}
      subtitle={subs[step]}
      onClose={busy ? undefined : onClose}
      wide
      steps={{ total: 4, current: step }}
      footer={
        <>
          {step > 0 && (
            <button className="btn ghost" onClick={() => setStep(step - 1)} disabled={busy}>
              Back
            </button>
          )}
          <span className="spacer" />
          {step < 3 ? (
            <button className="btn primary" onClick={() => setStep(step + 1)} disabled={!canNext}>
              Continue
            </button>
          ) : (
            <button className="btn primary" onClick={() => void create()} disabled={busy}>
              {busy ? (mode === 'passphrase' ? `Deriving key with ${kdf === 'argon2id' ? 'Argon2id' : 'PBKDF2'}…` : 'Creating…') : 'Create encrypted room'}
            </button>
          )}
        </>
      }
    >
      {step === 0 && (
        <div className="choice-grid" role="radiogroup" aria-label="Key mode">
          {MODES.map((m) => (
            <button key={m} className="choice" role="radio" aria-checked={mode === m} onClick={() => setMode(m)}>
              <span className="ctitle">
                <Icon name={MODE_INFO[m].icon} className="ci" /> {MODE_INFO[m].label}
              </span>
              <span className="cdesc">{MODE_INFO[m].desc}</span>
              <span className="cbest">{MODE_INFO[m].best}</span>
            </button>
          ))}
        </div>
      )}

      {step === 1 && (
        <>
          <div className="field">
            <label htmlFor={ids.name}>Room name</label>
            <input id={ids.name} className="input" value={name} maxLength={80} placeholder="e.g. Launch planning" onChange={(e) => setName(e.target.value)} autoFocus />
            <span className="hint">
              <Icon name="lock" size={11} /> Encrypted in the room header. The relay sees a random id instead.
            </span>
          </div>
          {mode === 'passphrase' && (
            <>
              <div className="field">
                <label htmlFor={ids.pass}>Room passphrase</label>
                <div className="row">
                  <input
                    id={ids.pass}
                    className="input mono"
                    value={pass}
                    onChange={(e) => setPass(e.target.value)}
                    placeholder="four or more random words"
                    autoComplete="new-password"
                    spellCheck={false}
                  />
                  <button className="btn" onClick={() => setPass(generatePassphrase())} title="Generate a 125-bit passphrase">
                    <Icon name="sparkle" size={15} /> Generate
                  </button>
                </div>
                <StrengthMeter value={pass} />
              </div>
              <div className="field">
                <span className="label" id="kdf-label">Key derivation</span>
                <div className="choice-grid" role="radiogroup" aria-labelledby="kdf-label">
                  <button className="choice" role="radio" aria-checked={kdf === 'argon2id'} onClick={() => setKdf('argon2id')}>
                    <span className="ctitle">Argon2id <span className="chip accent">recommended</span></span>
                    <span className="cdesc">
                      Memory-hard: {ARGON2_DEFAULT.m / 1024} MiB, {ARGON2_DEFAULT.t} passes. Makes GPU guessing expensive.
                    </span>
                  </button>
                  <button className="choice" role="radio" aria-checked={kdf === 'pbkdf2-sha256'} onClick={() => setKdf('pbkdf2-sha256')}>
                    <span className="ctitle">PBKDF2-SHA-256</span>
                    <span className="cdesc">{PBKDF2_DEFAULT_ITER.toLocaleString()} iterations via Web Crypto. Fallback for constrained devices.</span>
                  </button>
                </div>
              </div>
              <Callout tone="warn">
                Anyone who can guess the passphrase can read the room, and the relay stores the salt and a verifier - so it could try guesses offline. Use a
                generated passphrase and share it out-of-band.
              </Callout>
            </>
          )}
          {mode === 'pk' && (
            <Callout tone="accent" icon="shieldCheck">
              Your invite carries your signed prekey. Your contact opens it and sends the first message (X3DH); from then on every message gets its own key.
              Compare safety numbers to rule out a man-in-the-middle.
            </Callout>
          )}
          {mode === 'keyfile' && (
            <Callout icon="qr">After creating the room you can download a key file or show a QR code - both generated on this device, never uploaded.</Callout>
          )}
        </>
      )}

      {step === 2 && (
        <div className="choice-grid three" role="radiogroup" aria-label="Cipher suite">
          {SUITES.map((s) => (
            <button key={s} className="choice" role="radio" aria-checked={suite === s} onClick={() => setSuite(s)}>
              <span className="ctitle">{SUITE_INFO[s].label}</span>
              <span className="cdesc">{SUITE_INFO[s].blurb}</span>
              <span className="cbest">
                {SUITE_INFO[s].nonceBytes * 8}-bit nonce · {SUITE_INFO[s].impl}
              </span>
            </button>
          ))}
        </div>
      )}

      {step === 3 && (
        <>
          <div className="seg" role="group" aria-label="Disappearing message timer">
            {TTLS.map((t) => (
              <button key={t} aria-pressed={ttl === t} onClick={() => setTtl(t)}>
                {ttlLabel(t)}
              </button>
            ))}
          </div>
          <dl className="summary">
            <dt>Room</dt>
            <dd>{name}</dd>
            <dt>Key mode</dt>
            <dd>
              {MODE_INFO[mode].label}
              {mode === 'passphrase' ? ` · ${kdf === 'argon2id' ? 'Argon2id' : 'PBKDF2-SHA-256'}` : ''}
            </dd>
            <dt>Cipher</dt>
            <dd>{SUITE_INFO[suite].label}</dd>
            <dt>Messages</dt>
            <dd>{ttl ? `disappear after ${ttlLabel(ttl)}` : 'kept until you delete the room'}</dd>
            <dt>Signatures</dt>
            <dd>Ed25519 on every message</dd>
          </dl>
          {err && <Callout tone="danger">{err}</Callout>}
        </>
      )}
    </Modal>
  );
}
