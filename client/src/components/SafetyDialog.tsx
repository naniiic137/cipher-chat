import { useEffect, useState } from 'react';
import {
  checkVerificationPayload,
  fingerprintDigits,
  formatSafetyNumber,
  safetyNumber,
  verificationPayload,
  type CipherClient,
  type RoomState,
} from '@cipher-chat/shared';
import { Callout, Modal } from './Modal.tsx';
import { Icon } from './Icon.tsx';
import { decodeQrFile, qrSvg } from '../lib/util.ts';

export function SafetyDialog({ client, room, initialEd, onClose }: { client: CipherClient; room: RoomState; initialEd?: string; onClose: () => void }) {
  const others = Object.values(room.members).filter((m) => m.ed !== client.me.ed);
  if (room.pk?.peer && !others.some((m) => m.ed === room.pk!.peer!.ed)) {
    others.push({ ...room.pk.peer, firstSeen: 0, lastSeen: 0 });
  }
  const [sel, setSel] = useState(initialEd ?? others[0]?.ed ?? '');
  const them = others.find((m) => m.ed === sel);
  const [svg, setSvg] = useState('');
  const [scan, setScan] = useState('');
  const [result, setResult] = useState<'match' | 'mismatch' | null>(null);
  const contact = them ? client.contacts[them.ed] : undefined;
  const [, force] = useState(0);

  useEffect(() => {
    if (!them) return;
    let live = true;
    void qrSvg(verificationPayload(client.me, them)).then((s) => live && setSvg(s));
    setResult(null);
    return () => {
      live = false;
    };
  }, [them, client.me]);

  const check = (payload: string) => {
    if (!them) return;
    const ok = checkVerificationPayload(payload, client.me, them);
    setResult(ok ? 'match' : 'mismatch');
    if (ok) {
      client.setVerified(them.ed, true);
      force((x) => x + 1);
    }
  };

  return (
    <Modal
      title="Safety numbers"
      subtitle="If both devices show the same 60 digits, nobody is intercepting your conversation."
      onClose={onClose}
      wide
      footer={
        <button className="btn primary" onClick={onClose}>
          Done
        </button>
      }
    >
      {others.length === 0 ? (
        <Callout>No one else has spoken in this room yet. Safety numbers appear once a member sends a signed message.</Callout>
      ) : (
        <>
          {others.length > 1 && (
            <div className="field">
              <label htmlFor="member">Member</label>
              <select id="member" className="select" value={sel} onChange={(e) => setSel(e.target.value)}>
                {others.map((m) => (
                  <option key={m.ed} value={m.ed}>
                    {m.name} {client.contacts[m.ed]?.verified ? '(verified)' : ''}
                  </option>
                ))}
              </select>
            </div>
          )}
          {them && (
            <>
              <div className="row" style={{ gap: 18, alignItems: 'flex-start', flexWrap: 'wrap' }}>
                <div className="qr" role="img" aria-label="Verification QR code" dangerouslySetInnerHTML={{ __html: svg }} />
                <div className="col grow" style={{ minWidth: 240 }}>
                  <div className="row">
                    <b className="grow">You ↔ {them.name}</b>
                    {contact?.verified ? (
                      <span className="chip accent">
                        <Icon name="shieldCheck" size={12} /> Verified
                      </span>
                    ) : (
                      <span className="chip warn">
                        <Icon name="shieldAlert" size={12} /> Not verified
                      </span>
                    )}
                  </div>
                  <div className="safety" aria-label="Safety number">
                    {formatSafetyNumber(safetyNumber(client.me, them)).map((g, i) => (
                      <span key={i}>{g}</span>
                    ))}
                  </div>
                </div>
              </div>
              <dl className="summary small">
                <dt>Your fingerprint</dt>
                <dd className="mono">{formatSafetyNumber(fingerprintDigits(client.me)).join(' ')}</dd>
                <dt>{them.name}</dt>
                <dd className="mono">{formatSafetyNumber(fingerprintDigits(them)).join(' ')}</dd>
              </dl>
              <div className="grid-2">
                <div className="field">
                  <label htmlFor="scan-file">Scan their code (image)</label>
                  <input
                    id="scan-file"
                    className="input"
                    type="file"
                    accept="image/*"
                    onChange={async (e) => {
                      const f = e.target.files?.[0];
                      if (!f) return;
                      try {
                        check(await decodeQrFile(f));
                      } catch {
                        setResult('mismatch');
                      }
                    }}
                  />
                </div>
                <div className="field">
                  <label htmlFor="scan-text">…or paste their verification text</label>
                  <div className="copybox">
                    <input id="scan-text" className="input" value={scan} onChange={(e) => setScan(e.target.value)} placeholder="cipherchat-verify:v1:…" />
                    <button className="btn" onClick={() => check(scan)} disabled={!scan}>
                      Check
                    </button>
                  </div>
                </div>
              </div>
              {result === 'match' && (
                <Callout tone="accent" icon="shieldCheck">
                  Keys match. {them.name} is marked as verified - you will get a loud warning if their key ever changes.
                </Callout>
              )}
              {result === 'mismatch' && (
                <Callout tone="danger">That code does not match {them.name}’s current keys. Do not trust this conversation until you find out why.</Callout>
              )}
              <div className="row">
                {contact?.verified ? (
                  <button className="btn danger sm" onClick={() => { client.setVerified(them.ed, false); force((x) => x + 1); }}>
                    Clear verification
                  </button>
                ) : (
                  <button className="btn sm" onClick={() => { client.setVerified(them.ed, true); force((x) => x + 1); }}>
                    <Icon name="check" size={14} /> I compared the numbers in person - mark verified
                  </button>
                )}
              </div>
            </>
          )}
        </>
      )}
    </Modal>
  );
}
