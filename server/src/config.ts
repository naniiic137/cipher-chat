/**
 * Server configuration from environment variables. `loadConfig` is pure so it
 * can be unit-tested and reused by the integration tests.
 */

export interface RateConfig {
  /** sustained frames per second per connection */
  connFramesPerSec: number;
  connFrameBurst: number;
  /** sustained bytes per second per connection */
  connBytesPerSec: number;
  connByteBurst: number;
  /** aggregate limits per client IP (all its connections) */
  ipFramesPerSec: number;
  ipFrameBurst: number;
  ipBytesPerSec: number;
  ipByteBurst: number;
  maxConnsPerIp: number;
  /** violations tolerated before the socket is closed */
  maxViolations: number;
}

export interface ServerConfig {
  port: number;
  host: string;
  /** Empty list = any origin allowed (development only; a warning is logged). */
  allowedOrigins: string[];
  roomTtlMs: number;
  sqlitePath: string | undefined;
  trustProxy: boolean;
  sweepIntervalMs: number;
  keepaliveMs: number;
  rate: RateConfig;
}

function int(env: Record<string, string | undefined>, key: string, def: number, min = 0): number {
  const raw = env[key];
  if (raw === undefined || raw.trim() === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < min) throw new Error(`invalid ${key}: ${raw}`);
  return Math.floor(n);
}

function bool(env: Record<string, string | undefined>, key: string, def: boolean): boolean {
  const raw = env[key]?.trim().toLowerCase();
  if (!raw) return def;
  return raw === '1' || raw === 'true' || raw === 'yes';
}

export function loadConfig(env: Record<string, string | undefined> = {}): ServerConfig {
  const allowedOrigins = (env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((s) => s.trim().replace(/\/+$/, ''))
    .filter(Boolean);
  return {
    port: int(env, 'PORT', 3401),
    host: env.HOST?.trim() || '0.0.0.0',
    allowedOrigins,
    roomTtlMs: int(env, 'ROOM_TTL_HOURS', 168, 1) * 3_600_000,
    sqlitePath: env.SQLITE_PATH?.trim() || undefined,
    trustProxy: bool(env, 'TRUST_PROXY', false),
    sweepIntervalMs: int(env, 'SWEEP_INTERVAL_MS', 30_000, 100),
    keepaliveMs: int(env, 'KEEPALIVE_MS', 30_000, 100),
    rate: {
      connFramesPerSec: int(env, 'RATE_CONN_FPS', 20, 1),
      connFrameBurst: int(env, 'RATE_CONN_BURST', 120, 1),
      connBytesPerSec: int(env, 'RATE_CONN_BPS', 1_000_000, 1),
      connByteBurst: int(env, 'RATE_CONN_BYTE_BURST', 8_000_000, 1),
      ipFramesPerSec: int(env, 'RATE_IP_FPS', 60, 1),
      ipFrameBurst: int(env, 'RATE_IP_BURST', 300, 1),
      ipBytesPerSec: int(env, 'RATE_IP_BPS', 3_000_000, 1),
      ipByteBurst: int(env, 'RATE_IP_BYTE_BURST', 20_000_000, 1),
      maxConnsPerIp: int(env, 'RATE_MAX_CONNS_PER_IP', 20, 1),
      maxViolations: int(env, 'RATE_MAX_VIOLATIONS', 20, 1),
    },
  };
}
