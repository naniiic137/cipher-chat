import { useId, useState } from 'react';
import { passphraseStrength } from '@cipher-chat/shared';
import { Callout } from './Modal.tsx';
import { Icon, Logo } from './Icon.tsx';
import { MODE_INFO } from './labels.ts';
import { StrengthMeter } from './RoomWizard.tsx';

export function Onboarding({ demo, onDone }: { demo: boolean; onDone: (name: string, passphrase?: string) => Promise<void> }) {
  const [step, setStep] = useState(0);
  const [name, setName] = useState('');
  const [lock, setLock] = useState(false);
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const ids = { name: useId(), pass: useId(), title: useId() };

  const finish = async () => {
    setBusy(true);
    await onDone(name.trim(), lock ? pass : undefined);
  };

  return (
    <div className="onboard">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={ids.title} style={{ width: 'min(640px, 100%)' }}>
        <div className="stepper" aria-label={`Step ${step + 1} of 3`}>
          {[0, 1, 2].map((i) => (
            <div key={i} className={`s${i <= step ? ' on' : ''}`} />
          ))}
        </div>
        {step === 0 && (
          <>
            <div className="modal-head">
              <Logo size={48} />
              <div className="grow">
                <h2 id={ids.title}>Welcome to CipherChat</h2>
                <p>End-to-end encrypted rooms with a server that can’t read them.</p>
              </div>
            </div>
            <div className="modal-body">
              <div className="mode-list">
                <div className="mode-item">
                  <span className="mi">
                    <Icon name="lock" />
                  </span>
                  <div>
                    <b>Encrypted before it leaves your device</b>
                    <span>Messages, room names and files are encrypted in this browser. The relay forwards ciphertext it has no key for.</span>
                  </div>
                </div>
                <div className="mode-item">
                  <span className="mi">
                    <Icon name="shieldCheck" />
                  </span>
                  <div>
                    <b>Signed, so nobody can pretend to be you</b>
                    <span>This device gets its own Ed25519 identity. Every message is signed; forged or tampered ones are rejected and flagged.</span>
                  </div>
                </div>
                <div className="mode-item">
                  <span className="mi">
                    <Icon name="eye" />
                  </span>
                  <div>
                    <b>See for yourself</b>
                    <span>Open “Server view” in any room to watch the exact frames the server receives.</span>
                  </div>
                </div>
              </div>
              {demo && (
                <Callout tone="accent" icon="zap">
                  No server is configured, so this is the <b>offline demo</b>: tabs in this browser relay through BroadcastChannel. Open a second tab to chat with yourself.
                </Callout>
              )}
            </div>
            <div className="modal-foot">
              <button className="btn primary" onClick={() => setStep(1)}>
                How do keys work? <Icon name="back" size={14} className="flip" />
              </button>
            </div>
          </>
        )}
        {step === 1 && (
          <>
            <div className="modal-head">
              <div className="grow">
                <h2 id={ids.title}>Four ways to share a room key</h2>
                <p>You pick one per room. The server never gets the key in any of them.</p>
              </div>
            </div>
            <div className="modal-body">
              <div className="mode-list">
                {(['link', 'passphrase', 'pk', 'keyfile'] as const).map((m) => (
                  <div className="mode-item" key={m}>
                    <span className="mi">
                      <Icon name={MODE_INFO[m].icon} />
                    </span>
                    <div>
                      <b>{MODE_INFO[m].label}</b>
                      <span>{MODE_INFO[m].desc}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="modal-foot">
              <button className="btn ghost" onClick={() => setStep(0)}>
                Back
              </button>
              <button className="btn primary" onClick={() => setStep(2)}>
                Set up this device
              </button>
            </div>
          </>
        )}
        {step === 2 && (
          <>
            <div className="modal-head">
              <div className="grow">
                <h2 id={ids.title}>Create your device identity</h2>
                <p>Generates an Ed25519 signing key and an X25519 key-agreement key, stored only in this browser.</p>
              </div>
            </div>
            <div className="modal-body">
              <div className="field">
                <label htmlFor={ids.name}>Display name</label>
                <input id={ids.name} className="input" value={name} maxLength={40} placeholder="e.g. Hamza" onChange={(e) => setName(e.target.value)} autoFocus />
                <span className="hint">Shown to people in your rooms. It only ever travels inside encrypted messages.</span>
              </div>
              <label className="row" style={{ cursor: 'pointer' }}>
                <input type="checkbox" checked={lock} onChange={(e) => setLock(e.target.checked)} />
                <span>Protect this device’s keys with a passphrase (Argon2id + AES-256-GCM)</span>
              </label>
              {lock && (
                <div className="field">
                  <label htmlFor={ids.pass}>Device passphrase</label>
                  <input id={ids.pass} className="input mono" type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" />
                  <StrengthMeter value={pass} />
                  <span className="hint">There is no recovery. Forget it and the only option is wiping this device.</span>
                </div>
              )}
            </div>
            <div className="modal-foot">
              <button className="btn ghost" onClick={() => setStep(1)} disabled={busy}>
                Back
              </button>
              <button
                className="btn primary"
                onClick={() => void finish()}
                disabled={busy || !name.trim() || (lock && passphraseStrength(pass).score < 2)}
              >
                {busy ? 'Generating keys…' : 'Generate my keys'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export function UnlockScreen({ onUnlock, onWipe }: { onUnlock: (pw: string) => Promise<void>; onWipe: () => Promise<void> }) {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const id = useId();
  const unlock = async () => {
    setBusy(true);
    setErr('');
    try {
      await onUnlock(pw);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };
  return (
    <div className="onboard">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={id + 't'} style={{ width: 'min(440px, 100%)' }}>
        <div className="modal-head">
          <Logo size={44} />
          <div className="grow">
            <h2 id={id + 't'}>CipherChat is locked</h2>
            <p>Your keys are encrypted on this device.</p>
          </div>
        </div>
        <div className="modal-body">
          <div className="field">
            <label htmlFor={id}>Device passphrase</label>
            <input id={id} className="input mono" type="password" value={pw} autoFocus onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void unlock()} />
          </div>
          {err && <Callout tone="danger">{err}</Callout>}
        </div>
        <div className="modal-foot">
          <button
            className="btn ghost"
            onClick={() => {
              if (confirm('Forgot it? Wiping deletes every key and message on this device.')) void onWipe();
            }}
          >
            Forgot? Wipe device
          </button>
          <button className="btn primary" onClick={() => void unlock()} disabled={busy || !pw}>
            {busy ? 'Unlocking…' : 'Unlock'}
          </button>
        </div>
      </div>
    </div>
  );
}
