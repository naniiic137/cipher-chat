import { useId, useState } from 'react';
import { fingerprintDigits, formatSafetyNumber, passphraseStrength, type CipherClient } from '@cipher-chat/shared';
import { Vault } from '../lib/vault.ts';
import { Callout } from './Modal.tsx';
import { Icon } from './Icon.tsx';
import { StrengthMeter } from './RoomWizard.tsx';
import { defaultRelay, isDemo } from '../lib/util.ts';

export function DevicePage({ client, vault, toast, onLock }: { client: CipherClient; vault: Vault; toast: (t: string) => void; onLock: () => void }) {
  const data = vault.data!;
  const [name, setName] = useState(client.displayName);
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const [relay, setRelay] = useState(isDemo(data.settings.relay) ? '' : data.settings.relay);
  const [useDemo, setUseDemo] = useState(isDemo(data.settings.relay));
  const [confirmWipe, setConfirmWipe] = useState('');
  const ids = { name: useId(), pass: useId(), relay: useId(), wipe: useId() };
  const rooms = [...client.rooms.values()];
  const msgCount = rooms.reduce((n, r) => n + r.messages.length, 0);
  const keyCount = rooms.reduce((n, r) => n + Object.keys(r.keys).length, 0);

  const saveName = async () => {
    client.displayName = name.trim().slice(0, 40) || client.displayName;
    data.name = client.displayName;
    await vault.save();
    toast('Display name updated (it only travels inside encrypted messages)');
  };

  const setDevicePass = async (value: string | null) => {
    setBusy(true);
    try {
      data.snapshot = client.snapshot();
      await vault.setPassphrase(value);
      setPass('');
      toast(value ? 'Device storage is now encrypted with Argon2id + AES-256-GCM' : 'Device passphrase removed');
    } finally {
      setBusy(false);
    }
  };

  const saveRelay = async () => {
    const next = useDemo ? 'demo' : relay.trim();
    if (!useDemo && !/^wss?:\/\/.+/.test(next)) return toast('Relay URL must start with ws:// or wss://');
    data.settings.relay = next;
    data.snapshot = client.snapshot();
    await vault.save();
    location.reload();
  };

  return (
    <div className="page">
      <div className="page-inner">
        <div>
          <h2>This device</h2>
          <p className="lead">Your identity keys and every room key live only here, in IndexedDB.</p>
        </div>

        <div className="grid-2">
          <section className="card section" aria-labelledby="id-h">
            <h3 id="id-h">
              <Icon name="key" size={16} /> Identity
            </h3>
            <div className="field">
              <label htmlFor={ids.name}>Display name</label>
              <div className="copybox">
                <input id={ids.name} className="input" value={name} maxLength={40} onChange={(e) => setName(e.target.value)} />
                <button className="btn" onClick={() => void saveName()} disabled={!name.trim() || name === client.displayName}>
                  Save
                </button>
              </div>
            </div>
            <div className="field">
              <span className="label">Your fingerprint</span>
              <div className="mono" style={{ fontSize: 15, letterSpacing: '.05em' }}>
                {formatSafetyNumber(fingerprintDigits(client.me)).join(' ')}
              </div>
              <span className="hint">Derived from your Ed25519 signing key and X25519 key-agreement key.</span>
            </div>
            <dl className="summary small">
              <dt>Ed25519</dt>
              <dd className="mono ellipsis">{client.me.ed}</dd>
              <dt>X25519</dt>
              <dd className="mono ellipsis">{client.me.x}</dd>
            </dl>
          </section>

          <section className="card section" aria-labelledby="lock-h">
            <h3 id="lock-h">
              <Icon name="lock" size={16} /> Device passphrase
            </h3>
            <p className="small muted" style={{ margin: 0 }}>
              {vault.protectedByPassphrase
                ? 'Local storage is encrypted (Argon2id → AES-256-GCM). You will be asked for the passphrase when the app opens.'
                : 'Optional. Encrypts the keys and history stored on this device, so a stolen laptop or a copied browser profile does not expose them.'}
            </p>
            <div className="field">
              <label htmlFor={ids.pass}>{vault.protectedByPassphrase ? 'Change passphrase' : 'Set a passphrase'}</label>
              <input id={ids.pass} className="input mono" type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" />
              <StrengthMeter value={pass} />
            </div>
            <div className="row" style={{ flexWrap: 'wrap' }}>
              <button className="btn primary" disabled={busy || passphraseStrength(pass).score < 2} onClick={() => void setDevicePass(pass)}>
                {busy ? 'Deriving key…' : vault.protectedByPassphrase ? 'Change' : 'Encrypt storage'}
              </button>
              {vault.protectedByPassphrase && (
                <>
                  <button className="btn" onClick={onLock}>
                    <Icon name="lock" size={15} /> Lock now
                  </button>
                  <button className="btn ghost" disabled={busy} onClick={() => void setDevicePass(null)}>
                    Remove
                  </button>
                </>
              )}
            </div>
          </section>

          <section className="card section" aria-labelledby="relay-h">
            <h3 id="relay-h">
              <Icon name="server" size={16} /> Relay
            </h3>
            <div className="seg" role="group" aria-label="Relay mode">
              <button aria-pressed={useDemo} onClick={() => setUseDemo(true)}>
                Offline demo
              </button>
              <button aria-pressed={!useDemo} onClick={() => setUseDemo(false)}>
                Relay server
              </button>
            </div>
            {!useDemo && (
              <div className="field">
                <label htmlFor={ids.relay}>WebSocket URL</label>
                <input
                  id={ids.relay}
                  className="input mono"
                  value={relay}
                  placeholder={isDemo(defaultRelay()) ? 'wss://your-relay.example/ws' : defaultRelay()}
                  onChange={(e) => setRelay(e.target.value)}
                />
              </div>
            )}
            <p className="small muted" style={{ margin: 0 }}>
              The relay only stores ciphertext. It still sees metadata: your IP, timing, and which random room ids you use.
            </p>
            <button className="btn" onClick={() => void saveRelay()}>
              Save &amp; reconnect
            </button>
          </section>

          <section className="card section" aria-labelledby="store-h">
            <h3 id="store-h">
              <Icon name="device" size={16} /> Stored on this device
            </h3>
            <div className="stat-row">
              <div className="stat">
                <div className="v">{rooms.length}</div>
                <div className="l">rooms</div>
              </div>
              <div className="stat">
                <div className="v">{keyCount}</div>
                <div className="l">room keys</div>
              </div>
              <div className="stat">
                <div className="v">{msgCount}</div>
                <div className="l">messages</div>
              </div>
            </div>
            <Callout tone="danger" icon="trash">
              <b>Wipe this device</b> deletes your identity, every room key, ratchet session and message from this browser. It cannot be undone - rooms remain readable only
              on other members’ devices.
            </Callout>
            <div className="field">
              <label htmlFor={ids.wipe}>Type WIPE to confirm</label>
              <div className="copybox">
                <input id={ids.wipe} className="input" value={confirmWipe} onChange={(e) => setConfirmWipe(e.target.value)} autoComplete="off" />
                <button
                  className="btn danger"
                  disabled={confirmWipe !== 'WIPE'}
                  onClick={async () => {
                    for (const r of client.rooms.keys()) client.leaveRoom(r);
                    client.disconnect();
                    await vault.wipe();
                    location.replace(location.pathname);
                  }}
                >
                  <Icon name="trash" size={15} /> Wipe device
                </button>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
