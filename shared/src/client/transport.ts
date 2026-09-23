/**
 * Transports carry opaque JSON text frames between a client and a relay.
 * The browser app uses WebSockets (or BroadcastChannel in demo mode); tests
 * use the same WebSocket transport against the real Node server.
 */

export interface TransportHandlers {
  onOpen: () => void;
  onMessage: (raw: string) => void;
  onClose: (reason: string) => void;
}

export interface Transport {
  readonly kind: 'websocket' | 'broadcast' | 'memory';
  readonly label: string;
  connect(h: TransportHandlers): void;
  send(raw: string): void;
  close(): void;
}

/** WebSocket transport with capped exponential back-off reconnects. */
export class WsTransport implements Transport {
  readonly kind = 'websocket' as const;
  private ws: WebSocket | null = null;
  private h: TransportHandlers | null = null;
  private closed = false;
  private attempt = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    public readonly url: string,
    private readonly opts: { reconnect?: boolean } = {},
  ) {}

  get label(): string {
    return this.url;
  }

  connect(h: TransportHandlers): void {
    this.h = h;
    this.closed = false;
    this.open();
  }

  private open(): void {
    const ws = new WebSocket(this.url);
    this.ws = ws;
    ws.onopen = () => {
      this.attempt = 0;
      this.h?.onOpen();
    };
    ws.onmessage = (ev: MessageEvent) => {
      if (typeof ev.data === 'string') this.h?.onMessage(ev.data);
    };
    ws.onclose = (ev: CloseEvent) => {
      this.ws = null;
      this.h?.onClose(ev.reason || `closed (${ev.code})`);
      if (!this.closed && this.opts.reconnect !== false) {
        const delay = Math.min(15_000, 500 * 2 ** this.attempt++);
        this.timer = setTimeout(() => this.open(), delay);
      }
    };
    ws.onerror = () => {
      /* onclose follows */
    };
  }

  send(raw: string): void {
    if (this.ws?.readyState === 1) this.ws.send(raw);
  }

  close(): void {
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    this.ws?.close();
    this.ws = null;
  }
}
