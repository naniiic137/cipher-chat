/**
 * Offline demo mode. With no relay server configured (e.g. on GitHub Pages),
 * one browser tab becomes the relay - elected with the Web Locks API - and all
 * tabs of this origin talk to it over BroadcastChannel. It runs the SAME
 * RelayCore as the Node server, so the inspector shows exactly the frames a
 * real server would get. Nothing leaves this browser.
 */
import { MemoryStore, RelayCore, type Transport, type TransportHandlers } from '@cipher-chat/shared';

const CHANNEL = 'cipherchat-demo-v1';
const LOCK = 'cipherchat-demo-relay';
const SNAPSHOT = 'cipherchat-demo-relay-state';

type Msg =
  | { type: 'connect'; cid: string }
  | { type: 'frame'; cid: string; raw: string }
  | { type: 'close'; cid: string }
  | { type: 'server'; cid: string; raw: string }
  | { type: 'leader'; id: string };

class PersistentMemoryStore extends MemoryStore {
  private timer: ReturnType<typeof setTimeout> | null = null;
  schedule(): void {
    if (this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      try {
        // File chunks can be large; the demo keeps rooms + messages across relay hand-overs.
        const snap = this.snapshot() as { rooms: unknown; msgs: unknown };
        localStorage.setItem(SNAPSHOT, JSON.stringify({ rooms: snap.rooms, msgs: snap.msgs }));
      } catch {
        /* quota exceeded or storage disabled: demo continues in memory */
      }
    }, 300);
  }
}

let hostStarted = false;

/** Try to become the relay for this browser. Safe to call from every tab. */
export function startDemoRelayHost(): void {
  if (hostStarted) return;
  hostStarted = true;
  const run = () => {
    const store = new PersistentMemoryStore();
    try {
      const saved = localStorage.getItem(SNAPSHOT);
      if (saved) store.restore(JSON.parse(saved));
    } catch {
      /* ignore */
    }
    const relay = new RelayCore(store, { roomTtlMs: 7 * 24 * 3600_000, demo: true });
    const ch = new BroadcastChannel(CHANNEL);
    const conns = new Map<string, string>(); // client cid -> relay conn id
    ch.onmessage = (ev: MessageEvent<Msg>) => {
      const m = ev.data;
      if (m.type === 'connect') {
        // Retries can arrive after we already answered; replacing the connection
        // would drop an in-flight join challenge, so duplicates are ignored.
        if (conns.has(m.cid)) return;
        conns.set(
          m.cid,
          relay.connect((f) => ch.postMessage({ type: 'server', cid: m.cid, raw: JSON.stringify(f) } satisfies Msg)),
        );
      } else if (m.type === 'frame') {
        const conn = conns.get(m.cid);
        if (conn) {
          relay.receive(conn, m.raw);
          store.schedule();
        }
      } else if (m.type === 'close') {
        const conn = conns.get(m.cid);
        if (conn) relay.disconnect(conn);
        conns.delete(m.cid);
      }
    };
    setInterval(() => relay.sweep(), 5000);
    ch.postMessage({ type: 'leader', id: Math.random().toString(36).slice(2) } satisfies Msg);
  };
  if (navigator.locks) {
    // Held for the lifetime of this tab; the next tab takes over when it closes.
    void navigator.locks.request(LOCK, () => {
      run();
      return new Promise<never>(() => {});
    });
  } else {
    run();
  }
}

export class BroadcastTransport implements Transport {
  readonly kind = 'broadcast' as const;
  readonly label = 'Demo relay (this browser, via BroadcastChannel)';
  private ch: BroadcastChannel | null = null;
  private cid = crypto.randomUUID();
  private h: TransportHandlers | null = null;
  private retry: ReturnType<typeof setInterval> | null = null;
  private gotWelcome = false;

  connect(h: TransportHandlers): void {
    this.h = h;
    this.ch = new BroadcastChannel(CHANNEL);
    this.ch.onmessage = (ev: MessageEvent<Msg>) => {
      const m = ev.data;
      if (m.type === 'server' && m.cid === this.cid) {
        if (!this.gotWelcome) {
          this.gotWelcome = true;
          if (this.retry) clearInterval(this.retry);
          this.h?.onOpen();
        }
        this.h?.onMessage(m.raw);
      } else if (m.type === 'leader') {
        // A new relay tab took over: reconnect (the client re-joins its rooms on "welcome").
        this.gotWelcome = false;
        this.hello();
      }
    };
    this.hello();
    startDemoRelayHost();
  }

  private hello(): void {
    if (this.retry) clearInterval(this.retry);
    const send = () => this.ch?.postMessage({ type: 'connect', cid: this.cid } satisfies Msg);
    send();
    this.retry = setInterval(() => (this.gotWelcome ? this.retry && clearInterval(this.retry) : send()), 400);
  }

  send(raw: string): void {
    this.ch?.postMessage({ type: 'frame', cid: this.cid, raw } satisfies Msg);
  }

  close(): void {
    this.ch?.postMessage({ type: 'close', cid: this.cid } satisfies Msg);
    if (this.retry) clearInterval(this.retry);
    this.ch?.close();
    this.ch = null;
    this.h?.onClose('closed');
  }
}
