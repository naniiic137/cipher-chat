/**
 * HTTP + WebSocket front-end for the blind relay. All protocol logic lives in
 * RelayCore (@cipher-chat/shared); this layer adds transport hardening:
 * origin checks, per-IP/per-connection rate limits, frame size limits,
 * keep-alive, optional SQLite persistence and privacy-preserving logs.
 */
import http from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer, type RawData, type WebSocket } from 'ws';
import { LIMITS, MemoryStore, RelayCore, type RelayStore, type ServerFrame } from '@cipher-chat/shared';
import type { ServerConfig } from './config.ts';
import { createLogger, type LogSink, type Logger } from './logger.ts';
import { RateLimiter } from './rateLimit.ts';
import { openSqliteStore, SqliteStore } from './sqliteStore.ts';

export const VERSION = '1.0.0';

export interface RelayServerOptions {
  /** Where log lines go (default: stdout). */
  logSink?: LogSink;
  /** Custom store (default: SQLite if config.sqlitePath, else memory). */
  store?: RelayStore;
  /** Observe raw frames received from clients (tests assert on these). */
  onInbound?: (connId: string, raw: string) => void;
  /** Observe raw frames sent to clients. */
  onOutbound?: (connId: string, raw: string) => void;
}

export interface RelayServer {
  listen(): Promise<{ port: number }>;
  close(): Promise<void>;
  relay: RelayCore;
  store: RelayStore;
  logger: Logger;
  persistence: 'sqlite' | 'memory';
}

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
};

const DEV_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/;

function clientIp(req: http.IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    const first = (Array.isArray(xff) ? xff[0] : xff)?.split(',')[0]?.trim();
    if (first) return first;
  }
  return req.socket.remoteAddress ?? 'unknown';
}

function rejectUpgrade(socket: Duplex, status: number, text: string): void {
  socket.write(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  socket.destroy();
}

export async function createRelayServer(config: ServerConfig, opts: RelayServerOptions = {}): Promise<RelayServer> {
  const logger = createLogger(opts.logSink);
  let store: RelayStore;
  let persistence: 'sqlite' | 'memory' = 'memory';
  let ownedSqlite: SqliteStore | null = null;
  if (opts.store) {
    store = opts.store;
    persistence = opts.store instanceof SqliteStore ? 'sqlite' : 'memory';
  } else if (config.sqlitePath) {
    ownedSqlite = await openSqliteStore(config.sqlitePath);
    if (ownedSqlite) {
      store = ownedSqlite;
      persistence = 'sqlite';
    } else {
      logger.warn('persistence.unavailable', { hint: 'node:sqlite missing; use Node >= 22.13' });
      store = new MemoryStore();
    }
  } else {
    store = new MemoryStore();
  }

  const relay = new RelayCore(store, {
    roomTtlMs: config.roomTtlMs,
    log: (evt, fields) => logger.info(evt, fields),
    ...(opts.onInbound ? { onInbound: opts.onInbound } : {}),
  });
  const limiter = new RateLimiter(config.rate);
  const startedAt = Date.now();
  let closing = false;
  const originAllowed = (origin: string | undefined): boolean =>
    config.allowedOrigins.length === 0 || (origin !== undefined && config.allowedOrigins.includes(origin.replace(/\/+$/, '')));

  // ------------------------------------------------------------------ HTTP
  const server = http.createServer((req, res) => {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    const url = new URL(req.url ?? '/', 'http://relay.local');
    if (url.pathname === '/health') {
      const origin = req.headers.origin;
      const corsOk =
        origin !== undefined &&
        (config.allowedOrigins.length ? config.allowedOrigins.includes(origin) : DEV_ORIGIN.test(origin));
      if (corsOk) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
      }
      if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Methods', 'GET');
        res.writeHead(204).end();
        return;
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { Allow: 'GET' }).end();
        return;
      }
      const s = relay.stats();
      const body = JSON.stringify({
        ok: true,
        version: VERSION,
        uptime: Math.round((Date.now() - startedAt) / 1000),
        connections: s.connections,
        rooms: s.rooms,
        persistence,
      });
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }).end(req.method === 'HEAD' ? undefined : body);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('not found');
  });

  // ------------------------------------------------------------- WebSocket
  const wss = new WebSocketServer({ noServer: true, maxPayload: LIMITS.maxFrameBytes, perMessageDeflate: false });
  const alive = new WeakMap<WebSocket, boolean>();

  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url ?? '/', 'http://relay.local');
    if (url.pathname !== '/ws') return rejectUpgrade(socket, 404, 'Not Found');
    if (!originAllowed(req.headers.origin)) {
      logger.warn('conn.origin_rejected', {});
      return rejectUpgrade(socket, 403, 'Forbidden');
    }
    const ip = clientIp(req, config.trustProxy);
    const lim = limiter.open(ip);
    if (!lim) {
      logger.warn('conn.too_many_per_ip', {});
      return rejectUpgrade(socket, 429, 'Too Many Requests');
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      alive.set(ws, true);
      let connId = '';
      const send = (f: ServerFrame): void => {
        if (ws.readyState !== ws.OPEN) return;
        const raw = JSON.stringify(f);
        opts.onOutbound?.(connId || 'pending', raw);
        ws.send(raw);
      };
      connId = relay.connect(send);
      logger.info('conn.open', { conns: wss.clients.size });

      ws.on('pong', () => alive.set(ws, true));
      ws.on('message', (data: RawData, isBinary: boolean) => {
        const buf = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as ArrayBuffer);
        if (!lim.allow(buf.length)) {
          send({ t: 'error', code: 'rate-limited', msg: 'slow down' });
          if (lim.violations === 1 || lim.violations % 10 === 0) logger.warn('conn.rate_limited', { violations: lim.violations });
          if (lim.violations > config.rate.maxViolations) ws.close(1008, 'rate limited');
          return;
        }
        if (closing) return;
        if (isBinary) {
          send({ t: 'error', code: 'bad-frame', msg: 'text frames only' });
          return;
        }
        try {
          relay.receive(connId, buf.toString('utf8'));
        } catch (e) {
          // Never let one bad frame (or a storage error) take the process down.
          logger.error('relay.error', { kind: e instanceof Error ? e.name : 'unknown' });
          send({ t: 'error', code: 'bad-frame', msg: 'internal error' });
        }
      });
      ws.on('error', () => {
        /* 'close' follows (e.g. maxPayload exceeded -> 1009) */
      });
      ws.on('close', (code: number) => {
        if (!closing) relay.disconnect(connId);
        lim.release();
        logger.info('conn.close', { code, conns: wss.clients.size });
      });
    });
  });

  // ------------------------------------------------------------ timers
  const sweepTimer = setInterval(() => relay.sweep(), config.sweepIntervalMs);
  sweepTimer.unref();
  const keepalive = setInterval(() => {
    for (const ws of wss.clients) {
      if (alive.get(ws) === false) {
        ws.terminate();
        continue;
      }
      alive.set(ws, false);
      ws.ping();
    }
  }, config.keepaliveMs);
  keepalive.unref();

  return {
    relay,
    store,
    logger,
    persistence,
    listen: () =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.port, config.host, () => {
          const addr = server.address();
          const port = typeof addr === 'object' && addr ? addr.port : config.port;
          logger.info('server.listen', { port, persistence, origins: config.allowedOrigins.length });
          if (!config.allowedOrigins.length) {
            logger.warn('config.any_origin', { hint: 'set ALLOWED_ORIGINS in production' });
          }
          resolve({ port });
        });
      }),
    close: () =>
      new Promise<void>((resolve) => {
        closing = true;
        clearInterval(sweepTimer);
        clearInterval(keepalive);
        for (const ws of wss.clients) ws.terminate();
        wss.close();
        server.closeAllConnections?.();
        server.close(() => {
          ownedSqlite?.close();
          resolve();
        });
      }),
  };
}
