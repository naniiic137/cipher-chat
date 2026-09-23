import { useId, useMemo, useState } from 'react';
import { parseInvite, type CipherClient, type RoomInvite } from '@cipher-chat/shared';
import { Callout, Modal } from './Modal.tsx';
import { Icon } from './Icon.tsx';
import { MODE_INFO } from './labels.ts';
import { decodeQrFile } from '../lib/util.ts';

export function JoinDialog({
  client,
  initialText,
  onClose,
  onJoined,
}: {
  client: CipherClient;
  initialText?: string;
  onClose: () => void;
  onJoined: (rid: string) => void;
}) {
  const [tab, setTab] = useState<'paste' | 'file' | 'qr'>('paste');
  const [text, setText] = useState(initialText ?? '');
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const ids = { text: useId(), pass: useId(), file: useId(), qr: useId() };

  const parsed = useMemo((): { inv?: RoomInvite; error?: string } => {
    if (!text.trim()) return {};
    try {
      return { inv: parseInvite(text) };
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) };
    }
  }, [text]);
  const inv = parsed.inv;
  const needsPass = inv && !inv.key;

  const join = async () => {
    if (!inv) return;
    setBusy(true);
    setErr('');
    try {
      const rid = await client.joinRoom(inv, needsPass ? pass : undefined);
      onJoined(rid);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };

  const readFile = async (f: File | undefined, qr: boolean) => {
    if (!f) return;
    setErr('');
    try {
      setText(qr ? await decodeQrFile(f) : (await f.text()).slice(0, 10_000));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Modal
      title="Join a room"
      subtitle="Paste an invite link, import a key file, or read a QR image. Everything is parsed locally."
      onClose={busy ? undefined : onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => void join()} disabled={!inv || busy || (needsPass && pass.length < 1)}>
            {busy ? (needsPass ? 'Deriving key & proving membership…' : 'Proving membership…') : 'Join room'}
          </button>
        </>
      }
    >
      <div className="tabs" role="tablist" aria-label="Import method">
        <button role="tab" aria-selected={tab === 'paste'} onClick={() => setTab('paste')}>
          <Icon name="link" size={14} /> Paste
        </button>
        <button role="tab" aria-selected={tab === 'file'} onClick={() => setTab('file')}>
          <Icon name="file" size={14} /> Key file
        </button>
        <button role="tab" aria-selected={tab === 'qr'} onClick={() => setTab('qr')}>
          <Icon name="qr" size={14} /> QR image
        </button>
      </div>
      {tab === 'paste' && (
        <div className="field">
          <label htmlFor={ids.text}>Invite link, key file contents or QR text</label>
          <textarea id={ids.text} className="textarea" value={text} onChange={(e) => setText(e.target.value)} placeholder="https://…#r=…&k=…" spellCheck={false} />
        </div>
      )}
      {tab === 'file' && (
        <div className="field">
          <label htmlFor={ids.file}>Choose a .key.json file</label>
          <input id={ids.file} className="input" type="file" accept=".json,application/json,text/plain" onChange={(e) => void readFile(e.target.files?.[0], false)} />
        </div>
      )}
      {tab === 'qr' && (
        <div className="field">
          <label htmlFor={ids.qr}>Choose a photo or screenshot of the QR code</label>
          <input id={ids.qr} className="input" type="file" accept="image/*" onChange={(e) => void readFile(e.target.files?.[0], true)} />
          <span className="hint">Decoded in your browser with jsQR - the image is never uploaded.</span>
        </div>
      )}

      {inv && (
        <dl className="summary">
          <dt>Room id</dt>
          <dd className="mono">{inv.rid.slice(0, 11)}…</dd>
          <dt>Key mode</dt>
          <dd>{MODE_INFO[inv.mode].label}</dd>
          <dt>Key</dt>
          <dd>{inv.key ? 'included (256-bit)' : 'passphrase required'}</dd>
          <dt>Epoch</dt>
          <dd>{inv.epoch}</dd>
        </dl>
      )}
      {needsPass && (
        <div className="field">
          <label htmlFor={ids.pass}>Room passphrase</label>
          <input
            id={ids.pass}
            className="input mono"
            type="password"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void join()}
            autoComplete="off"
          />
          <span className="hint">Stretched with the room’s Argon2id/PBKDF2 parameters. Weak parameters from the relay are refused.</span>
        </div>
      )}
      {parsed.error && <Callout tone="warn">{parsed.error}</Callout>}
      {err && <Callout tone="danger">{err}</Callout>}
    </Modal>
  );
}
