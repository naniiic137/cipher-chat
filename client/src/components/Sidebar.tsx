import type { CipherClient } from '@cipher-chat/shared';
import { Icon } from './Icon.tsx';
import { MODE_INFO, modeLabel } from './labels.ts';
import { time } from '../lib/util.ts';

export function Sidebar({
  client,
  active,
  demo,
  onOpen,
  onNew,
  onJoin,
}: {
  client: CipherClient;
  active: string | null;
  demo: boolean;
  onOpen: (rid: string) => void;
  onNew: () => void;
  onJoin: () => void;
}) {
  const rooms = [...client.rooms.values()].sort((a, b) => {
    const la = a.messages[a.messages.length - 1]?.serverTs ?? a.joinedAt;
    const lb = b.messages[b.messages.length - 1]?.serverTs ?? b.joinedAt;
    return lb - la;
  });
  return (
    <aside className="sidebar" aria-label="Rooms">
      <div className="sidebar-head">
        <div className="row">
          <h1 className="grow">Rooms</h1>
          <span className="chip accent" title="All content is end-to-end encrypted">
            <Icon name="lock" size={12} /> E2EE
          </span>
        </div>
        <div className="row">
          <button className="btn primary grow" onClick={onNew}>
            <Icon name="plus" size={16} /> New room
          </button>
          <button className="btn" onClick={onJoin}>
            Join
          </button>
        </div>
      </div>
      <nav className="room-list" aria-label="Your rooms">
        {rooms.length === 0 && <p className="muted small" style={{ padding: '8px 10px' }}>No rooms yet. Create one or open an invite link.</p>}
        {rooms.map((r) => {
          const last = [...r.messages].reverse().find((m) => m.kind === 'text' || m.kind === 'file');
          const preview = r.needsKey
            ? 'Key rotated - import the new key'
            : last
              ? `${last.mine ? 'You' : last.sender.name}: ${last.kind === 'file' ? `File: ${last.file?.name ?? 'attachment'}` : last.text}`
              : modeLabel(r);
          return (
            <button key={r.rid} className="room-item" aria-current={r.rid === active ? 'true' : undefined} onClick={() => onOpen(r.rid)}>
              <span className="room-icon">
                <Icon name={MODE_INFO[r.mode].icon} size={18} />
              </span>
              <span className="grow">
                <span className="row">
                  <span className="title ellipsis grow">{r.name}</span>
                  {last && <span className="small faint">{time(last.serverTs)}</span>}
                </span>
                <span className="row">
                  <span className={`sub ellipsis grow${r.needsKey ? ' warn' : ''}`}>{preview}</span>
                  {r.unread > 0 && r.rid !== active && <span className="badge">{r.unread}</span>}
                </span>
              </span>
            </button>
          );
        })}
      </nav>
      <div className="sidebar-foot">
        <span className={`status-dot ${client.status}`} aria-hidden />
        <span className="small grow ellipsis">
          <span className="sr-only">Connection: </span>
          {client.status === 'online' ? (demo ? 'Demo relay · this browser' : 'Connected to relay') : client.status === 'connecting' ? 'Connecting…' : 'Offline'}
        </span>
        <span className="small muted ellipsis" title="Your display name (only sent inside encrypted messages)">
          {client.displayName}
        </span>
      </div>
    </aside>
  );
}
