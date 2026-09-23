/**
 * Token-bucket rate limiting per connection and per client IP, plus a cap on
 * concurrent connections per IP. Buckets refill continuously.
 */
import type { RateConfig } from './config.ts';

export class TokenBucket {
  private tokens: number;
  private last: number;

  constructor(
    private readonly ratePerSec: number,
    private readonly burst: number,
    private readonly now: () => number = Date.now,
  ) {
    this.tokens = burst;
    this.last = now();
  }

  take(n = 1): boolean {
    const t = this.now();
    this.tokens = Math.min(this.burst, this.tokens + ((t - this.last) / 1000) * this.ratePerSec);
    this.last = t;
    if (this.tokens < n) return false;
    this.tokens -= n;
    return true;
  }
}

interface IpState {
  conns: number;
  frames: TokenBucket;
  bytes: TokenBucket;
  /** when the last connection closed (IP buckets survive reconnects for a while) */
  idleSince: number;
}

const IP_STATE_IDLE_MS = 60_000;

export interface ConnLimiter {
  /** Returns false if this frame exceeds a limit. */
  allow(bytes: number): boolean;
  /** Number of limit violations so far. */
  readonly violations: number;
  release(): void;
}

export class RateLimiter {
  private ips = new Map<string, IpState>();

  constructor(
    private readonly cfg: RateConfig,
    private readonly now: () => number = Date.now,
  ) {}

  /** Registers a new connection. Returns null if the IP has too many connections. */
  open(ip: string): ConnLimiter | null {
    this.prune();
    let st = this.ips.get(ip);
    if (!st) {
      st = {
        conns: 0,
        frames: new TokenBucket(this.cfg.ipFramesPerSec, this.cfg.ipFrameBurst, this.now),
        bytes: new TokenBucket(this.cfg.ipBytesPerSec, this.cfg.ipByteBurst, this.now),
        idleSince: 0,
      };
      this.ips.set(ip, st);
    }
    if (st.conns >= this.cfg.maxConnsPerIp) return null;
    st.conns++;
    const ipState = st;
    const frames = new TokenBucket(this.cfg.connFramesPerSec, this.cfg.connFrameBurst, this.now);
    const bytes = new TokenBucket(this.cfg.connBytesPerSec, this.cfg.connByteBurst, this.now);
    let violations = 0;
    let released = false;
    return {
      allow: (n: number) => {
        const ok = frames.take(1) && bytes.take(n) && ipState.frames.take(1) && ipState.bytes.take(n);
        if (!ok) violations++;
        return ok;
      },
      get violations() {
        return violations;
      },
      release: () => {
        if (released) return;
        released = true;
        ipState.conns--;
        // Keep the IP's buckets for a while so reconnecting does not reset them.
        if (ipState.conns <= 0) ipState.idleSince = this.now();
      },
    };
  }

  private prune(): void {
    const t = this.now();
    for (const [ip, st] of this.ips) {
      if (st.conns <= 0 && t - st.idleSince > IP_STATE_IDLE_MS) this.ips.delete(ip);
    }
  }

  get trackedIps(): number {
    return this.ips.size;
  }
}
