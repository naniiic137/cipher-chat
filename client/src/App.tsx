import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import {
  CipherClient,
  parseInvite,
  WsTransport,
  type FrameEvent,
  type RoomInvite,
} from '@cipher-chat/shared';
import { Vault } from './lib/vault.ts';
import { BroadcastTransport } from './lib/demoRelay.ts';
import { defaultRelay, isDemo } from './lib/util.ts';
import { Icon, Logo } from './components/Icon.tsx';
import { Onboarding, UnlockScreen } from './components/Onboarding.tsx';
import { Sidebar } from './components/Sidebar.tsx';
import { ChatView, EmptyState } from './components/ChatView.tsx';
import { Inspector } from './components/Inspector.tsx';
import { RoomWizard } from './components/RoomWizard.tsx';
import { InviteDialog } from './components/InviteDialog.tsx';
import { JoinDialog } from './components/JoinDialog.tsx';
import { SafetyDialog } from './components/SafetyDialog.tsx';
import { RotateDialog } from './components/RotateDialog.tsx';
import { DevicePage } from './components/DevicePage.tsx';
import { Playground } from './components/Playground.tsx';

type Phase = 'loading' | 'new' | 'locked' | 'ready' | 'error' | 'elsewhere' | 'moved';

/**
 * Storage profile. In demo mode every browser TAB is its own person (its own
 * identity), so two tabs can chat. With a real relay there is one profile per
 * browser and only one tab may use it at a time (shared message counters).
 */
function profileDb(): string {
  if (!isDemo(defaultRelay())) return 'cipherchat';
  try {
    let p = sessionStorage.getItem('cipherchat-demo-profile');
    if (!p) {
      p = crypto.randomUUID().slice(0, 8);
      sessionStorage.setItem('cipherchat-demo-profile', p);
    }
    return `cipherchat-demo-${p}`;
  } catch {
    return 'cipherchat-demo';
  }
}

/** Hold an exclusive Web Lock for this profile while the tab is open. */
function acquireTabLock(db: string, steal: boolean, onLost: () => void): Promise<boolean> {
  if (!navigator.locks) return Promise.resolve(true);
  return new Promise((resolve) => {
    navigator.locks
      .request(`cipherchat-active:${db}`, steal ? { steal: true } : { ifAvailable: true }, (lock) => {
        if (!lock) {
          resolve(false);
          return undefined;
        }
        resolve(true);
        return new Promise<never>(() => {});
      })
      .catch(() => onLost()); // another tab stole the lock
  });
}

export function Root() {
  const db = useMemo(profileDb, []);
  const vault = useMemo(() => new Vault(db), [db]);
  const [phase, setPhase] = useState<Phase>('loading');
  const [error, setError] = useState('');

  const start = useCallback(
    async (steal: boolean) => {
      try {
        const ok = await acquireTabLock(db, steal, () => {
          vault.lock();
          setPhase('moved');
        });
        if (!ok) return setPhase('elsewhere');
        setPhase(await vault.load());
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        setPhase('error');
      }
    },
    [db, vault],
  );

  const once = useRef(false);
  useEffect(() => {
    if (once.current) return; // StrictMode double-invokes effects in dev
    once.current = true;
    void start(false);
  }, [start]);

  if (phase === 'loading') return <div className="onboard" aria-busy="true" />;
  if (phase === 'elsewhere' || phase === 'moved')
    return (
      <div className="onboard">
        <div className="modal" role="dialog" aria-labelledby="tab-t" style={{ width: 'min(460px, 100%)' }}>
          <div className="modal-head">
            <Logo size={44} />
            <div className="grow">
              <h2 id="tab-t">{phase === 'moved' ? 'CipherChat moved to another tab' : 'CipherChat is open in another tab'}</h2>
              <p>One tab at a time keeps message counters (replay protection) consistent.</p>
            </div>
          </div>
          <div className="modal-foot">
            <button className="btn primary" onClick={() => (phase === 'moved' ? location.reload() : void start(true))}>
              Use here
            </button>
          </div>
        </div>
      </div>
    );
  if (phase === 'error')
    return (
      <div className="onboard">
        <div className="card section" role="alert">
          <h3>Storage unavailable</h3>
          <p className="muted">CipherChat keeps keys in IndexedDB, which this browser blocked: {error}</p>
        </div>
      </div>
    );
  if (phase === 'new')
    return (
      <Onboarding
        demo={isDemo(defaultRelay())}
        onDone={async (name, passphrase) => {
          vault.create(name, { relay: defaultRelay() });
          if (passphrase) await vault.setPassphrase(passphrase);
          else await vault.save();
          setPhase('ready');
        }}
      />
    );
  if (phase === 'locked')
    return (
      <UnlockScreen
        onUnlock={async (pw) => {
          await vault.unlock(pw);
          setPhase('ready');
        }}
        onWipe={async () => {
          await vault.wipe();
          location.reload();
        }}
      />
    );
  return <Shell vault={vault} onLock={() => { vault.lock(); setPhase('locked'); }} />;
}

export type View = 'chats' | 'playground' | 'device';
type Dialog =
  | { kind: 'wizard' }
  | { kind: 'join'; invite?: RoomInvite; text?: string }
  | { kind: 'invite'; rid: string; fresh?: boolean }
  | { kind: 'safety'; rid: string; ed?: string }
  | { kind: 'rotate'; rid: string }
  | null;

function Shell({ vault, onLock }: { vault: Vault; onLock: () => void }) {
  const data = vault.data!;
  const relay = data.settings.relay;
  const demo = isDemo(relay);
  const client = useMemo(() => {
    const transport = demo ? new BroadcastTransport() : new WsTransport(relay);
    return new CipherClient(transport, vault.identity(), data.name, { snapshot: data.snapshot });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [, force] = useReducer((x: number) => x + 1, 0);
  const frames = useRef<FrameEvent[]>([]);
  const [frameTick, bumpFrames] = useReducer((x: number) => x + 1, 0);
  const [view, setView] = useState<View>('chats');
  const [active, setActive] = useState<string | null>(() => client.rooms.keys().next().value ?? null);
  const [showList, setShowList] = useState(true);
  const [inspector, setInspector] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [toasts, setToasts] = useState<{ id: number; text: string }[]>([]);

  const toast = useCallback((text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3500);
  }, []);

  // Connect once; persist (debounced) on every state change.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const offs = [
      client.on('change', () => force()),
      client.on('status', () => force()),
      client.on('notice', (n) => toast(n.text)),
      client.on('frame', (f) => {
        frames.current = [f, ...frames.current].slice(0, 250);
        bumpFrames();
      }),
      client.on('persist', () => {
        if (timer) return;
        timer = setTimeout(() => {
          timer = null;
          data.snapshot = client.snapshot();
          data.name = client.displayName;
          void vault.save();
        }, 400);
      }),
    ];
    client.connect();
    const sweep = setInterval(() => {
      client.sweepExpired();
      if ([...client.rooms.values()].some((r) => r.ttl > 0) || client.typing.size) force();
    }, 1000);
    return () => {
      offs.forEach((off) => off());
      clearInterval(sweep);
      client.disconnect();
    };
  }, [client, data, vault, toast]);

  // Invite links: the key is in the #fragment (never sent to a server). Consume and scrub it.
  useEffect(() => {
    const check = () => {
      const h = location.hash;
      if (!h.includes('r=')) return;
      history.replaceState(null, '', location.pathname + location.search);
      try {
        const inv = parseInvite(h);
        if (client.rooms.has(inv.rid) && !client.rooms.get(inv.rid)!.needsKey && !inv.key) {
          setActive(inv.rid);
          return;
        }
        setDialog({ kind: 'join', invite: inv, text: h });
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Invalid invite link');
      }
    };
    check();
    window.addEventListener('hashchange', check);
    return () => window.removeEventListener('hashchange', check);
  }, [client, toast]);

  const room = active ? client.rooms.get(active) : undefined;
  useEffect(() => {
    if (room && view === 'chats' && document.visibilityState === 'visible') void client.markRead(room.rid);
  }, [room, room?.messages.length, view, client]);

  const openRoom = (rid: string) => {
    setActive(rid);
    setView('chats');
    setShowList(false);
  };

  const classes = ['app'];
  if (view !== 'chats') classes.push('full-main');
  else if (inspector) classes.push('with-inspector');
  if (view === 'chats' && showList) classes.push('show-list');

  const unread = [...client.rooms.values()].reduce((n, r) => n + (r.rid === active ? 0 : r.unread), 0);

  return (
    <>
      <div className={classes.join(' ')}>
        <nav className="rail" aria-label="Primary">
          <div className="logo">
            <Logo />
          </div>
          <RailButton icon="chat" label="Chats" current={view === 'chats'} onClick={() => setView('chats')} badge={unread} />
          <RailButton icon="flask" label="Classic ciphers playground" current={view === 'playground'} onClick={() => setView('playground')} />
          <RailButton icon="device" label="This device" current={view === 'device'} onClick={() => setView('device')} />
          <div className="spacer" />
          {vault.protectedByPassphrase && <RailButton icon="lock" label="Lock now" current={false} onClick={onLock} />}
        </nav>

        {view === 'chats' && (
          <Sidebar
            client={client}
            active={active}
            demo={demo}
            onOpen={openRoom}
            onNew={() => setDialog({ kind: 'wizard' })}
            onJoin={() => setDialog({ kind: 'join' })}
          />
        )}

        <main className="main" id="main">
          {demo && (
            <div className="demo-banner" role="note">
              <Icon name="zap" size={15} />
              <span>
                <strong>Offline demo mode</strong>
                <span className="hide-sm"> - no server. Each tab of this browser is a separate person, relayed over BroadcastChannel.</span>
                <span className="show-sm"> - each browser tab is a separate person.</span>
              </span>
            </div>
          )}
          {view === 'playground' && <Playground />}
          {view === 'device' && <DevicePage client={client} vault={vault} toast={toast} onLock={onLock} />}
          {view === 'chats' &&
            (room ? (
              <ChatView
                key={room.rid}
                client={client}
                room={room}
                inspectorOpen={inspector}
                onToggleInspector={() => setInspector((v) => !v)}
                onInvite={() => setDialog({ kind: 'invite', rid: room.rid })}
                onVerify={(ed) => setDialog({ kind: 'safety', rid: room.rid, ...(ed ? { ed } : {}) })}
                onRotate={() => setDialog({ kind: 'rotate', rid: room.rid })}
                onImportKey={() => setDialog({ kind: 'join' })}
                onBack={() => setShowList(true)}
                onLeave={() => {
                  client.leaveRoom(room.rid);
                  setActive(client.rooms.keys().next().value ?? null);
                  setShowList(true);
                }}
                toast={toast}
              />
            ) : (
              <EmptyState onNew={() => setDialog({ kind: 'wizard' })} onJoin={() => setDialog({ kind: 'join' })} demo={demo} />
            ))}
        </main>

        {view === 'chats' && inspector && (
          <Inspector client={client} frames={frames.current} tick={frameTick} onClose={() => setInspector(false)} demo={demo} />
        )}

        <nav className="tabbar" aria-label="Primary">
          <button aria-current={view === 'chats' ? 'page' : undefined} onClick={() => { setView('chats'); setShowList(true); }}>
            <Icon name="chat" />
            Chats
          </button>
          <button aria-current={view === 'playground' ? 'page' : undefined} onClick={() => setView('playground')}>
            <Icon name="flask" />
            Playground
          </button>
          <button aria-current={view === 'device' ? 'page' : undefined} onClick={() => setView('device')}>
            <Icon name="device" />
            Device
          </button>
        </nav>
      </div>

      {dialog?.kind === 'wizard' && (
        <RoomWizard
          client={client}
          onClose={() => setDialog(null)}
          onCreated={(rid) => {
            openRoom(rid);
            setDialog({ kind: 'invite', rid, fresh: true });
          }}
        />
      )}
      {dialog?.kind === 'join' && (
        <JoinDialog
          client={client}
          {...(dialog.text ? { initialText: dialog.text } : {})}
          onClose={() => setDialog(null)}
          onJoined={(rid) => {
            setDialog(null);
            openRoom(rid);
            toast('Joined - membership proven without revealing the key.');
          }}
        />
      )}
      {dialog?.kind === 'invite' && (
        <InviteDialog client={client} rid={dialog.rid} relay={relay} fresh={!!dialog.fresh} onClose={() => setDialog(null)} toast={toast} />
      )}
      {dialog?.kind === 'safety' && client.rooms.get(dialog.rid) && (
        <SafetyDialog client={client} room={client.rooms.get(dialog.rid)!} {...(dialog.ed ? { initialEd: dialog.ed } : {})} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === 'rotate' && client.rooms.get(dialog.rid) && (
        <RotateDialog
          client={client}
          room={client.rooms.get(dialog.rid)!}
          onClose={() => setDialog(null)}
          onRotated={(distributed) => {
            if (distributed) {
              setDialog(null);
              toast('Key rotated and shared in-band with current members.');
            } else setDialog({ kind: 'invite', rid: dialog.rid });
          }}
        />
      )}
      <div className="toast-wrap" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className="toast">
            {t.text}
          </div>
        ))}
      </div>
    </>
  );
}

function RailButton({
  icon,
  label,
  current,
  onClick,
  badge,
}: {
  icon: Parameters<typeof Icon>[0]['name'];
  label: string;
  current: boolean;
  onClick: () => void;
  badge?: number;
}) {
  return (
    <button className="rail-btn" aria-label={label} title={label} aria-current={current ? 'page' : undefined} onClick={onClick}>
      <Icon name={icon} size={21} />
      {!!badge && <span className="badge">{badge > 99 ? '99+' : badge}</span>}
    </button>
  );
}
