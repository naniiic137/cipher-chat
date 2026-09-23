import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { LIMITS, shortId, type ChatMessage, type CipherClient, type RoomState } from '@cipher-chat/shared';
import { Icon, Logo } from './Icon.tsx';
import { modeLabel, suiteLabel } from './labels.ts';
import { bytes, countdown, download, initials, time, ttlLabel } from '../lib/util.ts';

interface Props {
  client: CipherClient;
  room: RoomState;
  inspectorOpen: boolean;
  onToggleInspector: () => void;
  onInvite: () => void;
  onVerify: (ed?: string) => void;
  onRotate: () => void;
  onImportKey: () => void;
  onBack: () => void;
  onLeave: () => void;
  toast: (t: string) => void;
}

export function ChatView(p: Props) {
  const { client, room } = p;
  const listRef = useRef<HTMLDivElement>(null);
  const [menu, setMenu] = useState(false);
  const count = room.messages.length;

  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
    // The list may be hidden (mobile room list) when it mounts: scroll again once it gets a size.
    const ro = new ResizeObserver(() => {
      if (el.scrollHeight - el.scrollTop - el.clientHeight > 40 && el.dataset.pinned !== 'no') el.scrollTop = el.scrollHeight;
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [count, room.rid]);

  const members = client.presence.get(room.rid);
  const typing = [...(client.typing.get(room.rid)?.keys() ?? [])].map((ed) => room.members[ed]?.name ?? 'Someone');
  const peer = room.pk?.peer;
  const peerVerified = peer ? client.contacts[peer.ed]?.verified : false;
  const can = client.canSend(room.rid);

  return (
    <>
      <header className="chat-head">
        <button className="btn ghost icon back-btn" onClick={p.onBack} aria-label="Back to rooms">
          <Icon name="back" />
        </button>
        <div className="grow" style={{ minWidth: 0 }}>
          <h2 className="ellipsis">{room.name}</h2>
          <div className="chips">
            <span className="chip accent" title="End-to-end encrypted">
              <Icon name="lock" size={11} /> {suiteLabel(room)}
            </span>
            <span className="chip">{modeLabel(room)}</span>
            <span className="chip hide-sm" title="Key epoch - increases on every rotation">
              <Icon name="key" size={11} /> epoch {room.epoch}
            </span>
            {room.ttl > 0 && (
              <span className="chip" title="Disappearing messages">
                <Icon name="timer" size={11} /> {ttlLabel(room.ttl)}
              </span>
            )}
            {peer && (
              <span className={`chip ${peerVerified ? 'accent' : 'warn'}`}>
                <Icon name={peerVerified ? 'shieldCheck' : 'shieldAlert'} size={11} /> {peerVerified ? 'Verified' : 'Not verified'}
              </span>
            )}
            {members !== undefined && (
              <span className="chip hide-sm" title="Connected members (visible to the relay)">
                <Icon name="users" size={11} /> {members} online
              </span>
            )}
          </div>
        </div>
        <button className="btn sm hide-sm" onClick={p.onInvite}>
          <Icon name="link" size={15} /> Invite
        </button>
        <button className="btn sm icon hide-sm" onClick={() => p.onVerify()} aria-label="Safety numbers" title="Safety numbers">
          <Icon name="shieldCheck" size={16} />
        </button>
        <button
          className={`btn sm${p.inspectorOpen ? ' primary' : ''}`}
          onClick={p.onToggleInspector}
          aria-pressed={p.inspectorOpen}
          title="What the server sees"
        >
          <Icon name="eye" size={15} /> <span className="hide-sm">Server view</span>
        </button>
        <div style={{ position: 'relative' }}>
          <button className="btn sm icon" aria-label="Room menu" aria-expanded={menu} onClick={() => setMenu((m) => !m)}>
            <Icon name="menu" size={16} />
          </button>
          {menu && (
            <div className="menu card" role="menu" onMouseLeave={() => setMenu(false)}>
              <button role="menuitem" onClick={() => { setMenu(false); p.onInvite(); }}>
                <Icon name="link" size={15} /> Invite / export key
              </button>
              <button role="menuitem" onClick={() => { setMenu(false); p.onRotate(); }}>
                <Icon name="rotate" size={15} /> Rotate room key
              </button>
              <button role="menuitem" onClick={() => { setMenu(false); p.onVerify(); }}>
                <Icon name="shieldCheck" size={15} /> Safety numbers
              </button>
              <button role="menuitem" className="danger" onClick={() => { setMenu(false); if (confirm('Leave this room and delete its keys and history from this device?')) p.onLeave(); }}>
                <Icon name="logout" size={15} /> Leave &amp; forget room
              </button>
            </div>
          )}
        </div>
      </header>

      <div
        className="messages"
        ref={listRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          el.dataset.pinned = el.scrollHeight - el.scrollTop - el.clientHeight < 60 ? 'yes' : 'no';
        }}
        role="log" aria-live="polite" aria-label={`Messages in ${room.name}`}>
        {renderMessages(room, client, p)}
      </div>

      <div className="typing" aria-live="polite">
        {typing.length > 0 && (
          <>
            <span className="dots" aria-hidden>
              <span />
              <span />
              <span />
            </span>
            {typing.join(', ')} {typing.length > 1 ? 'are' : 'is'} typing <span className="faint">(encrypted indicator)</span>
          </>
        )}
      </div>

      {room.needsKey ? (
        <div className="composer">
          <div className="callout warn grow">
            <Icon name="key" size={16} />
            <div className="grow">The room key was rotated out-of-band. Import the new invite or key file to keep reading.</div>
            <button className="btn sm" onClick={p.onImportKey}>
              Import key
            </button>
          </div>
        </div>
      ) : (
        <Composer client={client} room={room} can={can} toast={p.toast} />
      )}
    </>
  );
}

function renderMessages(room: RoomState, client: CipherClient, p: Props) {
  const out: JSX.Element[] = [];
  let group: ChatMessage[] = [];
  const flush = () => {
    if (!group.length) return;
    const first = group[0]!;
    const verified = !first.mine && client.contacts[first.sender.ed]?.verified;
    out.push(
      <div key={first.id} className={`msg-group${first.mine ? ' mine' : ''}`}>
        {!first.mine && (
          <button
            className={`avatar${verified ? ' verified' : ''}`}
            title={`Verify ${first.sender.name}`}
            aria-label={`Safety number for ${first.sender.name}`}
            onClick={() => p.onVerify(first.sender.ed)}
          >
            {initials(first.sender.name)}
          </button>
        )}
        <div className="msg-col">
          <div className="msg-meta">
            <span className="name">{first.mine ? 'You' : first.sender.name}</span>
            {!first.mine && (
              <span className={`chip ${verified ? 'accent' : ''}`} style={{ height: 18, fontSize: 10.5 }} title="Short fingerprint of this sender's identity key">
                <Icon name={verified ? 'shieldCheck' : 'key'} size={10} /> {verified ? 'Verified' : shortId(first.sender)}
              </span>
            )}
          </div>
          {group.map((m) => (
            <Bubble key={m.id} m={m} client={client} room={room} />
          ))}
        </div>
      </div>,
    );
    group = [];
  };
  for (const m of room.messages) {
    if (m.kind === 'system') {
      flush();
      out.push(
        <div key={m.id} className={`notice${m.severity === 'warn' ? ' warn' : m.severity === 'danger' ? ' danger' : ''}`}>
          {m.text}
        </div>,
      );
    } else if (m.kind === 'rejected') {
      flush();
      out.push(
        <div key={m.id} className="rejected" role="alert">
          <Icon name="shieldAlert" size={18} />
          <div>
            <strong>Message rejected</strong>
            {m.reason}
          </div>
        </div>,
      );
    } else if (m.kind === 'locked') {
      flush();
      out.push(
        <div key={m.id} className="locked">
          <Icon name="lock" size={13} /> {m.reason}
        </div>,
      );
    } else {
      const prev = group[group.length - 1];
      if (prev && (prev.sender.ed !== m.sender.ed || prev.mine !== m.mine || m.serverTs - prev.serverTs > 5 * 60_000)) flush();
      group.push(m);
    }
  }
  flush();
  if (!out.length) {
    out.push(
      <div key="empty" className="notice">
        No messages yet. Everything you send is encrypted on this device before it leaves.
      </div>,
    );
  }
  return out;
}

function Bubble({ m, client, room }: { m: ChatMessage; client: CipherClient; room: RoomState }) {
  const readers = (m.readBy ?? []).map((ed) => room.members[ed]?.name ?? 'someone');
  return (
    <>
      <div className="bubble">{m.kind === 'file' && m.file ? <FileBody m={m} client={client} room={room} /> : m.text}</div>
      <div className="bubble-foot">
        {m.ratchet && (
          <span className="sig" title="Delivered through the Double Ratchet: a fresh key for this message only">
            <Icon name="rotate" size={11} /> ratchet
          </span>
        )}
        <span className="sig" title={m.mine ? 'Signed with your device key' : 'Ed25519 signature verified'}>
          <Icon name="shieldCheck" size={11} /> signed
        </span>
        {m.exp && (
          <span className="sig" title="Disappearing message">
            <Icon name="timer" size={11} /> {countdown(m.exp - Date.now())}
          </span>
        )}
        <span>{time(m.serverTs)}</span>
        {m.mine &&
          (readers.length ? (
            <span className="read sig" title={`Read by ${readers.join(', ')} (encrypted receipt)`}>
              <Icon name="checks" size={13} /> Read
            </span>
          ) : m.status === 'sending' ? (
            <span className="sig" title="Sending">
              <Icon name="timer" size={11} />
            </span>
          ) : (
            <span className="sig" title="Delivered to the relay">
              <Icon name="check" size={13} />
            </span>
          ))}
      </div>
    </>
  );
}

const previewCache = new Map<string, string>();

function FileBody({ m, client, room }: { m: ChatMessage; client: CipherClient; room: RoomState }) {
  const f = m.file!;
  const isImage = f.mime.startsWith('image/') && f.size <= 3 * 1024 * 1024;
  const [url, setUrl] = useState<string | null>(previewCache.get(f.fid) ?? null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const fetchIt = async (save: boolean) => {
    setBusy(true);
    setErr('');
    try {
      const data = await client.fetchFile(room.rid, f);
      if (save) download(f.name, data as BlobPart, f.mime);
      if (isImage) {
        const u = URL.createObjectURL(new Blob([data as BlobPart], { type: f.mime }));
        previewCache.set(f.fid, u);
        setUrl(u);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (isImage && !url) void fetchIt(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <div className="file-card">
        <span className="ficon">
          <Icon name={isImage ? 'image' : 'file'} />
        </span>
        <span className="grow" style={{ minWidth: 0 }}>
          <span className="ellipsis" style={{ display: 'block', fontWeight: 600 }}>
            {f.name}
          </span>
          <span className="small muted">
            {bytes(f.size)} · {f.chunks} encrypted chunk{f.chunks > 1 ? 's' : ''}
          </span>
        </span>
        <button className="btn sm icon" onClick={() => void fetchIt(true)} disabled={busy} aria-label={`Decrypt and download ${f.name}`}>
          <Icon name="download" size={15} />
        </button>
      </div>
      {url && <img className="file-img" src={url} alt={f.name} />}
      {busy && !url && <div className="small muted" style={{ marginTop: 6 }}>Decrypting…</div>}
      {err && <div className="small" style={{ color: 'var(--danger)', marginTop: 6 }}>{err}</div>}
    </div>
  );
}

function Composer({ client, room, can, toast }: { client: CipherClient; room: RoomState; can: { ok: boolean; why?: string }; toast: (t: string) => void }) {
  const [text, setText] = useState('');
  const lastTyping = useRef(0);
  const fileRef = useRef<HTMLInputElement>(null);

  const send = async () => {
    const t = text.trim();
    if (!t || !can.ok) return;
    setText('');
    lastTyping.current = 0;
    try {
      await client.sendText(room.rid, t);
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e));
      setText(t);
    }
  };

  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void send();
    }
  };

  const onChange = (v: string) => {
    setText(v);
    const now = Date.now();
    if (v && now - lastTyping.current > 3000 && can.ok) {
      lastTyping.current = now;
      void client.sendTyping(room.rid, true);
    }
  };

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > LIMITS.maxFileBytes) return toast(`Files are limited to ${bytes(LIMITS.maxFileBytes)}.`);
    try {
      const data = new Uint8Array(await file.arrayBuffer());
      await client.sendFile(room.rid, data, file.name, file.type || 'application/octet-stream');
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e));
    } finally {
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  return (
    <>
      <div className="composer">
        <div className="composer-box">
          <input ref={fileRef} type="file" hidden onChange={(e) => void onFile(e.target.files?.[0])} aria-hidden tabIndex={-1} />
          <button className="btn ghost icon" onClick={() => fileRef.current?.click()} disabled={!can.ok} aria-label="Attach an encrypted file" title={`Attach a file (encrypted, max ${bytes(LIMITS.maxFileBytes)})`}>
            <Icon name="paperclip" />
          </button>
          <label htmlFor="composer" className="sr-only">
            Message
          </label>
          <textarea
            id="composer"
            rows={1}
            value={text}
            placeholder={can.ok ? 'Write an encrypted message…' : can.why}
            disabled={!can.ok}
            maxLength={LIMITS.maxMessageChars}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={onKey}
            onBlur={() => lastTyping.current && void client.sendTyping(room.rid, false)}
          />
          <button className="btn primary icon" onClick={() => void send()} disabled={!can.ok || !text.trim()} aria-label="Send">
            <Icon name="send" />
          </button>
        </div>
      </div>
      <div className="composer-note">
        <Icon name="lock" size={12} /> Signed with your device key, padded, and encrypted with {suiteLabel(room)} before it leaves this device.
      </div>
    </>
  );
}

export function EmptyState({ onNew, onJoin, demo }: { onNew: () => void; onJoin: () => void; demo: boolean }) {
  return (
    <div className="empty">
      <div className="hero">
        <Logo size={64} />
        <h2>Private rooms. A server that can’t read them.</h2>
        <p>
          Every message, room name and file is encrypted in your browser. The relay only moves ciphertext - open the <b>Server view</b> in any room to see exactly what it receives.
          {demo && ' In demo mode, open a second tab to play the other person.'}
        </p>
        <div className="row" style={{ justifyContent: 'center' }}>
          <button className="btn primary" onClick={onNew}>
            <Icon name="plus" size={16} /> Create a room
          </button>
          <button className="btn" onClick={onJoin}>
            Join with an invite
          </button>
        </div>
        <div className="hero-grid">
          <div className="card">
            <Icon name="lock" />
            <b>End-to-end encrypted</b>AES-256-GCM, ChaCha20 or XChaCha20-Poly1305, per room.
          </div>
          <div className="card">
            <Icon name="shieldCheck" />
            <b>Signed & verified</b>Every message is Ed25519-signed. Compare safety numbers.
          </div>
          <div className="card">
            <Icon name="server" />
            <b>Blind relay</b>Proves membership without ever learning the key.
          </div>
        </div>
      </div>
    </div>
  );
}
