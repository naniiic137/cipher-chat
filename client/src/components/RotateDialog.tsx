import { useId, useState } from 'react';
import { generatePassphrase, passphraseStrength, type CipherClient, type RoomState } from '@cipher-chat/shared';
import { Callout, Modal } from './Modal.tsx';
import { Icon } from './Icon.tsx';
import { StrengthMeter } from './RoomWizard.tsx';

export function RotateDialog({
  client,
  room,
  onClose,
  onRotated,
}: {
  client: CipherClient;
  room: RoomState;
  onClose: () => void;
  onRotated: (distributed: boolean) => void;
}) {
  const [distribute, setDistribute] = useState(true);
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const passId = useId();
  const needPass = room.mode === 'passphrase';

  const rotate = async () => {
    setBusy(true);
    setErr('');
    try {
      await client.rotateKey(room.rid, { distribute, ...(needPass ? { passphrase: pass } : {}) });
      onRotated(distribute);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Rotate the room key"
      subtitle={`Epoch ${room.epoch} → ${room.epoch + 1}. Old keys stay on this device so history remains readable.`}
      onClose={busy ? undefined : onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => void rotate()} disabled={busy || (needPass && passphraseStrength(pass).score < 2)}>
            <Icon name="rotate" size={15} /> {busy ? 'Rotating…' : 'Rotate key'}
          </button>
        </>
      }
    >
      <div className="choice-grid" role="radiogroup" aria-label="How to distribute the new key">
        <button className="choice" role="radio" aria-checked={distribute} onClick={() => setDistribute(true)}>
          <span className="ctitle">
            <Icon name="users" className="ci" /> Share in-band
          </span>
          <span className="cdesc">The new key is sent to current members, encrypted and signed under the old key. Seamless.</span>
          <span className="cbest">Limits exposure if a key leaks later.</span>
        </button>
        <button className="choice" role="radio" aria-checked={!distribute} onClick={() => setDistribute(false)}>
          <span className="ctitle">
            <Icon name="logout" className="ci" /> Evict (out-of-band)
          </span>
          <span className="cdesc">Nobody receives the key automatically. The relay forces every member to re-prove membership.</span>
          <span className="cbest">Use to remove someone: share the new invite privately.</span>
        </button>
      </div>
      {needPass && (
        <div className="field">
          <label htmlFor={passId}>New passphrase (new random salt)</label>
          <div className="row">
            <input id={passId} className="input mono" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" spellCheck={false} />
            <button className="btn" onClick={() => setPass(generatePassphrase())}>
              <Icon name="sparkle" size={15} /> Generate
            </button>
          </div>
          <StrengthMeter value={pass} />
        </div>
      )}
      {distribute ? (
        <Callout>Someone who already holds the old key and still sees relay traffic could read the in-band key message. To evict a member, choose out-of-band.</Callout>
      ) : (
        <Callout tone="warn">Everyone except you loses access until they import the new invite or key file (shown next).</Callout>
      )}
      {err && <Callout tone="danger">{err}</Callout>}
    </Modal>
  );
}
