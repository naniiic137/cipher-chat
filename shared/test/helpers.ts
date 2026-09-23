import {
  CipherClient,
  generateIdentity,
  MemoryStore,
  RelayCore,
  type ServerFrame,
  type Transport,
  type TransportHandlers,
} from '../src/index.ts';

/** In-memory transport to a RelayCore, asynchronous like a real network. */
export class LoopTransport implements Transport {
  readonly kind = 'memory' as const;
  readonly label = 'memory';
  private conn: string | null = null;
  private h: TransportHandlers | null = null;
  /** Everything the relay sent to this client (raw), for assertions. */
  readonly inbound: string[] = [];
  /** Optional hook to mutate/drop frames the relay sends (malicious relay). */
  intercept: ((f: ServerFrame) => ServerFrame | null) | null = null;

  constructor(private readonly relay: RelayCore) {}

  connect(h: TransportHandlers): void {
    this.h = h;
    this.conn = this.relay.connect((f) => {
      const g = this.intercept ? this.intercept(f) : f;
      if (!g) return;
      const raw = JSON.stringify(g);
      this.inbound.push(raw);
      setTimeout(() => this.h?.onMessage(raw), 0);
    });
    setTimeout(() => h.onOpen(), 0);
  }

  send(raw: string): void {
    const c = this.conn;
    if (c) setTimeout(() => this.relay.receive(c, raw), 0);
  }

  close(): void {
    if (this.conn) this.relay.disconnect(this.conn);
    this.conn = null;
    this.h?.onClose('closed');
  }
}

export function makeRelay(opts: { now?: () => number } = {}) {
  const store = new MemoryStore();
  const inbound: string[] = [];
  const relay = new RelayCore(store, {
    roomTtlMs: 60_000,
    ...(opts.now ? { now: opts.now } : {}),
    onInbound: (_c, raw) => inbound.push(raw),
  });
  return { relay, store, inbound };
}

export function makeClient(relay: RelayCore, name: string, opts: { now?: () => number } = {}) {
  const transport = new LoopTransport(relay);
  const client = new CipherClient(transport, generateIdentity(), name, opts.now ? { now: opts.now } : {});
  client.connect();
  return { client, transport };
}

export async function waitFor(cond: () => boolean, timeout = 5000, what = 'condition'): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeout) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

export async function online(...clients: CipherClient[]): Promise<void> {
  await waitFor(() => clients.every((c) => c.status === 'online'), 5000, 'clients online');
}

export function texts(c: CipherClient, rid: string): string[] {
  return (c.rooms.get(rid)?.messages ?? []).filter((m) => m.kind === 'text').map((m) => m.text ?? '');
}
