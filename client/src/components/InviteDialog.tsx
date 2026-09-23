import { useEffect, useState } from 'react';
import { inviteLink, toKeyFile, toQrString, type CipherClient } from '@cipher-chat/shared';
import { Callout, Modal } from './Modal.tsx';
import { Icon } from './Icon.tsx';
import { copy, defaultRelay, download, isDemo, qrSvg } from '../lib/util.ts';

function Qr({ text, label }: { text: string; label: string }) {
  const [svg, setSvg] = useState('');
  useEffect(() => {
    let live = true;
    void qrSvg(text).then((s) => live && setSvg(s));
    return () => {
      live = false;
    };
  }, [text]);
  return <div className="qr" role="img" aria-label={label} dangerouslySetInnerHTML={{ __html: svg }} />;
}

export function InviteDialog({
  client,
  rid,
  relay,
  fresh,
  onClose,
  toast,
}: {
  client: CipherClient;
  rid: string;
  relay: string;
  fresh: boolean;
  onClose: () => void;
  toast: (t: string) => void;
}) {
  const room = client.rooms.get(rid)!;
  const [tab, setTab] = useState<'link' | 'key'>(room.mode === 'keyfile' ? 'key' : 'link');
  // Include a relay hint only when this deployment's default relay differs.
  const hint = !isDemo(relay) && relay !== defaultRelay() ? relay : undefined;
  const base = location.origin + location.pathname;
  const link = inviteLink(base, client.inviteFor(rid, hint));
  const keyInv = client.keyInvite(rid, hint);
  const qrText = toQrString(keyInv);

  const doCopy = async (text: string, what: string) => toast((await copy(text)) ? `${what} copied` : 'Copy failed - select and copy manually');

  return (
    <Modal
      title={fresh ? 'Room created - invite people' : 'Invite & export key'}
      subtitle={<>Anything below that contains the key lets its holder read <b>{room.name}</b>. Share it over a channel you trust.</>}
      onClose={onClose}
      wide
      footer={
        <button className="btn primary" onClick={onClose}>
          Done
        </button>
      }
    >
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === 'link'} onClick={() => setTab('link')}>
          Invite link
        </button>
        <button role="tab" aria-selected={tab === 'key'} onClick={() => setTab('key')}>
          Key file &amp; QR
        </button>
      </div>

      {tab === 'link' && (
        <>
          <div className="field">
            <label htmlFor="invite-link">{room.mode === 'passphrase' ? 'Invite link (no key inside)' : 'Invite link'}</label>
            <div className="copybox">
              <input id="invite-link" className="input" readOnly value={link} onFocus={(e) => e.currentTarget.select()} />
              <button className="btn" onClick={() => void doCopy(link, 'Invite link')}>
                <Icon name="copy" size={15} /> Copy
              </button>
            </div>
          </div>
          <div className="row" style={{ alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
            <Qr text={link} label="QR code of the invite link" />
            <div className="col grow" style={{ minWidth: 220 }}>
              {room.mode === 'passphrase' && (
                <Callout tone="accent" icon="key">
                  This link only identifies the room. Tell people the <b>passphrase</b> separately - in person or by voice.
                </Callout>
              )}
              {room.mode === 'pk' && (
                <Callout tone="accent" icon="shieldCheck">
                  Send this to <b>one</b> person. They open it and say hello first (X3DH). Then compare safety numbers.
                </Callout>
              )}
              {(room.mode === 'link' || room.mode === 'keyfile') && (
                <Callout icon="link">
                  The key is after the <span className="mono">#</span>. Browsers never send the fragment to servers, and CipherChat removes it from the address bar
                  once read.
                </Callout>
              )}
              {isDemo(relay) && (
                <Callout tone="warn" icon="zap">
                  Demo mode: this link works in other tabs of <b>this browser</b> only. Open it in a new tab to join as a second person.
                </Callout>
              )}
            </div>
          </div>
        </>
      )}

      {tab === 'key' && (
        <>
          <div className="row" style={{ alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
            <Qr text={qrText} label="QR code containing the room key" />
            <div className="col grow" style={{ minWidth: 220 }}>
              <p className="small muted" style={{ margin: 0 }}>
                Generated on this device - no QR service, no network. Scan it with another device, or save a screenshot and import the image.
              </p>
              <div className="field">
                <label htmlFor="qr-text">QR payload</label>
                <div className="copybox">
                  <input id="qr-text" className="input" readOnly value={qrText} onFocus={(e) => e.currentTarget.select()} />
                  <button className="btn" onClick={() => void doCopy(qrText, 'Key text')}>
                    <Icon name="copy" size={15} />
                  </button>
                </div>
              </div>
              <button
                className="btn"
                onClick={() => {
                  download(`cipherchat-${room.name.replace(/[^a-z0-9]+/gi, '-').toLowerCase() || 'room'}.key.json`, JSON.stringify(toKeyFile(keyInv), null, 2), 'application/json');
                  toast('Key file downloaded - store it like a password');
                }}
              >
                <Icon name="download" size={15} /> Download key file (.json)
              </button>
            </div>
          </div>
          {room.mode === 'passphrase' && (
            <Callout tone="warn">This exports the raw room key derived from the passphrase: whoever has it can skip the passphrase entirely.</Callout>
          )}
          {room.mode === 'pk' && (
            <Callout tone="warn">
              In 1:1 rooms the room key only gates the relay and wraps metadata. Message contents are protected by the Double Ratchet session on each device.
            </Callout>
          )}
        </>
      )}
    </Modal>
  );
}
