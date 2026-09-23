import { describe, expect, it } from 'vitest';
import { MemoryStore, type RelayStore, type RoomHeaderWire } from '@cipher-chat/shared';
import { loadConfig } from '../src/config.ts';
import { createLogger } from '../src/logger.ts';
import { RateLimiter, TokenBucket } from '../src/rateLimit.ts';
import { openSqliteStore } from '../src/sqliteStore.ts';

describe('config', () => {
  it('has safe defaults', () => {
    const c = loadConfig({});
    expect(c.port).toBe(3401);
    expect(c.allowedOrigins).toEqual([]);
    expect(c.roomTtlMs).toBe(168 * 3_600_000);
    expect(c.sqlitePath).toBeUndefined();
    expect(c.trustProxy).toBe(false);
  });

  it('parses env values and rejects garbage', () => {
    const c = loadConfig({ PORT: '8080', ALLOWED_ORIGINS: 'https://a.example/, https://b.example', ROOM_TTL_HOURS: '2', TRUST_PROXY: 'true' });
    expect(c.port).toBe(8080);
    expect(c.allowedOrigins).toEqual(['https://a.example', 'https://b.example']);
    expect(c.roomTtlMs).toBe(7_200_000);
    expect(c.trustProxy).toBe(true);
    expect(() => loadConfig({ PORT: 'abc' })).toThrow(/PORT/);
    expect(() => loadConfig({ ROOM_TTL_HOURS: '0' })).toThrow();
  });
});

describe('logger', () => {
  it('writes one JSON line per event and drops forbidden fields', () => {
    const lines: string[] = [];
    const log = createLogger((l) => lines.push(l));
    log.info('room.join', { room: 'abc123', blob: 'SECRET', rid: 'SECRET', count: 2 });
    expect(lines).toHaveLength(1);
    const o = JSON.parse(lines[0]!);
    expect(o).toMatchObject({ level: 'info', evt: 'room.join', room: 'abc123', count: 2 });
    expect(lines[0]).not.toContain('SECRET');
  });
});

describe('rate limiting', () => {
  it('token bucket allows a burst then refills over time', () => {
    let t = 0;
    const b = new TokenBucket(10, 5, () => t);
    for (let i = 0; i < 5; i++) expect(b.take()).toBe(true);
    expect(b.take()).toBe(false);
    t += 100; // 10/s -> one token
    expect(b.take()).toBe(true);
    expect(b.take()).toBe(false);
  });

  it('limits per connection, per IP and concurrent connections', () => {
    let t = 0;
    const rl = new RateLimiter(
      {
        connFramesPerSec: 1, connFrameBurst: 3, connBytesPerSec: 1000, connByteBurst: 1000,
        ipFramesPerSec: 1, ipFrameBurst: 4, ipBytesPerSec: 1e6, ipByteBurst: 1e6,
        maxConnsPerIp: 2, maxViolations: 5,
      },
      () => t,
    );
    const a = rl.open('1.1.1.1')!;
    const b = rl.open('1.1.1.1')!;
    expect(rl.open('1.1.1.1')).toBeNull();
    expect(rl.open('2.2.2.2')).not.toBeNull();
    expect([a.allow(10), a.allow(10), a.allow(10), a.allow(10)]).toEqual([true, true, true, false]);
    expect(b.allow(10)).toBe(true); // 4th frame for the IP
    expect(b.allow(10)).toBe(false); // IP bucket empty although b has tokens
    expect(a.violations).toBe(1);
    expect(a.allow(5000)).toBe(false); // byte budget
    a.release();
    b.release();
    // Reconnecting does not reset the IP bucket.
    const c = rl.open('1.1.1.1')!;
    expect(c.allow(1)).toBe(false);
    t += 5000;
    expect(c.allow(1)).toBe(true);
  });
});

const header: RoomHeaderWire = { pub: { v: 1, suite: 'aes-256-gcm', epoch: 0 }, box: 'AAAA' };

async function storeContract(name: string, make: () => Promise<RelayStore>) {
  describe(`${name} store`, () => {
    it('stores rooms, caps messages per room and filters expired ones', async () => {
      const s = await make();
      s.putRoom({ rid: 'r1', verifier: 'v', header, createdAt: 1, lastActive: 1 });
      expect(s.getRoom('r1')?.header).toEqual(header);
      for (let i = 0; i < 5; i++) s.addMsg('r1', { id: `m${i}`, blob: `b${i}`, ts: i, ...(i === 4 ? { exp: 100 } : {}) }, 3);
      expect(s.listMsgs('r1', 0).map((m) => m.id)).toEqual(['m2', 'm3', 'm4']);
      expect(s.listMsgs('r1', 200).map((m) => m.id)).toEqual(['m2', 'm3']);
      expect(s.purgeExpired(200)).toBe(1);
      s.putRoom({ rid: 'r1', verifier: 'v2', header, createdAt: 1, lastActive: 9 });
      expect(s.getRoom('r1')).toMatchObject({ verifier: 'v2', lastActive: 9, createdAt: 1 });
    });

    it('returns files only when complete and not expired; deleteRoom cascades', async () => {
      const s = await make();
      s.putRoom({ rid: 'r2', verifier: 'v', header, createdAt: 1, lastActive: 1 });
      s.putChunk('r2', 'f1', 1, 2, 'c1', undefined);
      expect(s.getChunks('r2', 'f1', 0)).toBeNull();
      s.putChunk('r2', 'f1', 0, 2, 'c0', undefined);
      expect(s.getChunks('r2', 'f1', 0)).toEqual(['c0', 'c1']);
      s.putChunk('r2', 'f2', 0, 1, 'x', 50);
      expect(s.countFiles('r2')).toBe(2);
      expect(s.getChunks('r2', 'f2', 60)).toBeNull();
      expect(s.purgeExpired(60)).toBe(1);
      expect(s.countFiles('r2')).toBe(1);
      s.addMsg('r2', { id: 'm', blob: 'b', ts: 1 }, 10);
      s.deleteRoom('r2');
      expect(s.getRoom('r2')).toBeUndefined();
      expect(s.listMsgs('r2', 0)).toEqual([]);
      expect(s.getChunks('r2', 'f1', 0)).toBeNull();
    });
  });
}

await storeContract('memory', async () => new MemoryStore());
await storeContract('sqlite', async () => {
  const s = await openSqliteStore(':memory:');
  if (!s) throw new Error('node:sqlite unavailable');
  return s;
});
