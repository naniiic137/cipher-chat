/**
 * Integration: the real Node relay (HTTP + WebSocket + SQLite) with real
 * CipherClients over WebSockets. The headline assertion: no plaintext, room
 * name, file name/content, passphrase, display name or room key ever appears
 * in any frame the server receives or sends, in its storage (including the raw
 * SQLite file on disk) or in its logs.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import WsClient from 'ws';
import {
  CipherClient,
  WsTransport,
  fromB64u,
  generateIdentity,
  newRoomId,
  parseInvite,
  toKeyFile,
  type KeyMode,
  type SuiteId,
} from '@cipher-chat/shared';
import { createRelayServer, type RelayServer } from '../src/app.ts';
import { loadConfig, type ServerConfig } from '../src/config.ts';

// ------------------------------------------------------------------ helpers

const tmp = mkdtempSync(join(tmpdir(), 'cipherchat-it-'));
const opened: { close(): Promise<void> }[] = [];
const clients: CipherClient[] = [];
const rawSockets: WsClient[] = [];

interface Harness {
  server: RelayServer;
  port: number;
  url: string;
  inbound: string[];
  outbound: string[];
  logs: string[];
}

async function start(env: Record<string, string> = {}, tweak: (c: ServerConfig) => void = () => {}): Promise<Harness> {
  const config = loadConfig({ PORT: '0', HOST: '127.0.0.1', SWEEP_INTERVAL_MS: '60000', ...env });
  tweak(config);
  const inbound: string[] = [];
  const outbound: string[] = [];
  const logs: string[] = [];
  const server = await createRelayServer(config, {
    logSink: (l) => logs.push(l),
    onInbound: (_c, raw) => inbound.push(raw),
    onOutbound: (_c, raw) => outbound.push(raw),
  });
  const { port } = await server.listen();
  opened.push(server);
  return { server, port, url: `ws://127.0.0.1:${port}/ws`, inbound, outbound, logs };
}

async function waitFor(cond: () => boolean, what = 'condition', timeout = 10_000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > timeout) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

async function client(h: Harness, name: string): Promise<CipherClient> {
  const c = new CipherClient(new WsTransport(h.url, { reconnect: false }), generateIdentity(), name);
  clients.push(c);
  c.connect();
  await waitFor(() => c.status === 'online', `${name} online`);
  return c;
}

const texts = (c: CipherClient, rid: string): string[] =>
  (c.rooms.get(rid)?.messages ?? []).filter((m) => m.kind === 'text').map((m) => m.text ?? '');

async function exchange(a: CipherClient, b: CipherClient, rid: string, first: CipherClient, t1: string, t2: string) {
  const second = first === a ? b : a;
  await first.sendText(rid, t1);
  await waitFor(() => texts(second, rid).includes(t1), `"${t1}" delivered`);
  await second.sendText(rid, t2);
  await waitFor(() => texts(first, rid).includes(t2), `"${t2}" delivered`);
}

/** Every encoding under which a secret could leak. */
function encodings(secret: string, isB64uKey = false): string[] {
  const bytes = isB64uKey ? Buffer.from(fromB64u(secret)) : Buffer.from(secret, 'utf8');
  const std = bytes.toString('base64').replace(/=+$/, '');
  const url = bytes.toString('base64url');
  return [...new Set([secret, std, url, bytes.toString('hex'), bytes.toString('hex').toUpperCase()])];
}

function openRaw(url: string, origin?: string): WsClient {
  const ws = new WsClient(url, origin ? { origin } : {});
  rawSockets.push(ws);
  return ws;
}

function framesOf(ws: WsClient): { frames: { t: string; code?: string }[]; closed: { code: number } | null } {
  const state = { frames: [] as { t: string; code?: string }[], closed: null as { code: number } | null };
  ws.on('message', (d) => state.frames.push(JSON.parse(String(d))));
  ws.on('close', (code) => (state.closed = { code }));
  ws.on('error', () => {});
  return state;
}

const whenOpen = (ws: WsClient) =>
  new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

afterAll(async () => {
  for (const c of clients) c.disconnect();
  for (const s of rawSockets) s.terminate();
  for (const s of opened) await s.close();
  rmSync(tmp, { recursive: true, force: true });
});

// ------------------------------------------------ the blind-relay guarantee

describe('blind relay: nothing readable ever reaches the server', () => {
  const dbPath = join(tmp, 'relay.sqlite');
  let h: Harness;
  const secrets: string[] = [];
  const keySecrets: string[] = [];
  const fileMarker = 'FILE-MARKER-7f3a9c-CONFIDENTIAL';
  const fileName = 'quarterly-secret-report.pdf';
  let alice: CipherClient;
  let bob: CipherClient;

  const rooms: { name: string; mode: KeyMode; suite: SuiteId; pass?: string; kdf?: 'argon2id' | 'pbkdf2-sha256'; via?: 'keyfile' }[] = [
    { name: 'Operation Nightingale', mode: 'link', suite: 'aes-256-gcm' },
    { name: 'Pbkdf2 Garden Room', mode: 'passphrase', suite: 'aes-256-gcm', pass: 'pbkdf2-passphrase-orbit-velvet', kdf: 'pbkdf2-sha256' },
    { name: 'Argon Vault Room', mode: 'passphrase', suite: 'xchacha20-poly1305', pass: 'argon2-passphrase-lantern-cactus', kdf: 'argon2id' },
    { name: 'Keyfile Lighthouse', mode: 'keyfile', suite: 'xchacha20-poly1305', via: 'keyfile' },
    { name: 'Direct Line Room', mode: 'pk', suite: 'chacha20-poly1305' },
  ];

  beforeAll(async () => {
    h = await start({ SQLITE_PATH: dbPath });
    expect(h.server.persistence).toBe('sqlite');
    alice = await client(h, 'Alice Quasar');
    bob = await client(h, 'Bob Nebula');
    secrets.push('Alice Quasar', 'Bob Nebula', fileName, fileMarker);

    let linkRid = '';
    for (const [i, r] of rooms.entries()) {
      const room = await alice.createRoom({
        name: r.name,
        mode: r.mode,
        suite: r.suite,
        ttl: 0,
        ...(r.pass ? { passphrase: r.pass, kdf: r.kdf! } : {}),
      });
      secrets.push(r.name);
      if (r.pass) secrets.push(r.pass);
      if (r.via === 'keyfile') {
        await bob.joinRoom(parseInvite(JSON.stringify(toKeyFile(alice.keyInvite(room.rid)))));
      } else if (r.pass) {
        await bob.joinRoom({ rid: room.rid, epoch: 0, mode: 'passphrase' }, r.pass);
      } else {
        await bob.joinRoom(alice.inviteFor(room.rid));
      }
      expect(bob.rooms.get(room.rid)!.name).toBe(r.name);
      const t1 = `secret message one in room ${i} about the harbour`;
      const t2 = `secret reply two in room ${i} about the lighthouse`;
      secrets.push(t1, t2);
      // In 1:1 rooms the joiner (X3DH initiator) must speak first.
      await exchange(alice, bob, room.rid, r.mode === 'pk' ? bob : alice, t1, t2);
      if (r.mode === 'link') linkRid = room.rid;
    }

    // Multi-chunk encrypted file with a marker inside.
    const data = new Uint8Array(200_000);
    for (let off = 0; off < data.length; off += 65_536) globalThis.crypto.getRandomValues(data.subarray(off, off + 65_536));
    data.set(new TextEncoder().encode(fileMarker), 70_000); // lands in chunk #2
    await alice.sendFile(linkRid, data, fileName, 'application/pdf');
    await waitFor(() => bob.rooms.get(linkRid)!.messages.some((m) => m.kind === 'file'), 'file manifest');
    const fm = bob.rooms.get(linkRid)!.messages.find((m) => m.kind === 'file')!;
    expect(fm.file!.chunks).toBe(4);
    const got = await bob.fetchFile(linkRid, fm.file!);
    expect(Buffer.from(got).equals(Buffer.from(data))).toBe(true);

    // Typing indicator + read receipt.
    await alice.sendTyping(linkRid, true);
    await waitFor(() => (bob.typing.get(linkRid)?.size ?? 0) > 0, 'typing indicator');
    const id = await alice.sendText(linkRid, 'please confirm you read this');
    secrets.push('please confirm you read this');
    await waitFor(() => texts(bob, linkRid).includes('please confirm you read this'), 'receipt target');
    await bob.markRead(linkRid);
    await waitFor(
      () => alice.rooms.get(linkRid)!.messages.find((m) => m.id === id)?.readBy?.includes(bob.me.ed) === true,
      'read receipt',
    );

    // Key rotation (in-band) and traffic under the new key.
    await alice.rotateKey(linkRid, { distribute: true });
    await waitFor(() => bob.rooms.get(linkRid)!.epoch === 1 && bob.canSend(linkRid).ok, 'rotation');
    await exchange(alice, bob, linkRid, alice, 'post-rotation message alpha', 'post-rotation message beta');
    secrets.push('post-rotation message alpha', 'post-rotation message beta');

    for (const c of [alice, bob]) for (const r of c.rooms.values()) keySecrets.push(...Object.values(r.keys));
  });

  function assertClean(label: string, haystack: string) {
    expect(haystack.length, `${label} should not be empty`).toBeGreaterThan(0);
    for (const s of secrets) for (const e of encodings(s)) expect(haystack.includes(e), `${label} leaked "${s}" as ${e}`).toBe(false);
    for (const k of new Set(keySecrets)) {
      for (const e of encodings(k, true)) expect(haystack.includes(e), `${label} leaked a room key`).toBe(false);
    }
  }

  it('exercised every key mode and all three suites', () => {
    expect(secrets.length).toBeGreaterThan(15);
    expect(new Set(keySecrets).size).toBeGreaterThanOrEqual(6); // 5 rooms + rotated epoch
  });

  it('inbound frames (everything clients sent) contain no plaintext or keys', () => {
    expect(h.inbound.length).toBeGreaterThan(20);
    assertClean('inbound frames', h.inbound.join('\n'));
  });

  it('outbound frames (everything the relay sent) contain no plaintext or keys', () => {
    expect(h.outbound.length).toBeGreaterThan(20);
    assertClean('outbound frames', h.outbound.join('\n'));
  });

  it('the store contents contain no plaintext or keys', () => {
    const dump = (h.server.store as unknown as { dump(): string }).dump();
    expect(dump).toContain('"blob"');
    assertClean('store dump', dump);
  });

  it('logs contain no payloads, room ids, verifiers or secrets', () => {
    const logText = h.logs.join('\n');
    assertClean('logs', logText);
    for (const line of h.logs) {
      const obj = JSON.parse(line) as Record<string, unknown>;
      for (const k of ['blob', 'header', 'verifier', 'rid', 'sig', 'nonce', 'key', 'payload']) expect(obj).not.toHaveProperty(k);
    }
    for (const r of alice.rooms.keys()) expect(logText).not.toContain(r);
    expect(h.logs.some((l) => l.includes('"evt":"room.create"'))).toBe(true);
  });

  it('/health reports status without leaking anything', async () => {
    const res = await fetch(`http://127.0.0.1:${h.port}/health`);
    expect(res.status).toBe(200);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['connections', 'ok', 'persistence', 'rooms', 'uptime', 'version']);
    expect(body).toMatchObject({ ok: true, rooms: 5, persistence: 'sqlite' });
    expect((await fetch(`http://127.0.0.1:${h.port}/anything`)).status).toBe(404);
  });

  it('the raw SQLite file on disk contains no plaintext or keys', async () => {
    for (const c of [alice, bob]) c.disconnect();
    const idx = opened.indexOf(h.server);
    await h.server.close();
    opened.splice(idx, 1);
    expect(existsSync(dbPath)).toBe(true);
    const raw = readFileSync(dbPath).toString('latin1');
    expect(raw.length).toBeGreaterThan(100_000); // chunks really are persisted
    assertClean('sqlite file', raw);
  });
});

// ------------------------------------------------------------- persistence

describe('persistence', () => {
  it('rooms and ciphertext history survive a server restart (SQLite)', async () => {
    const dbPath = join(tmp, 'restart.sqlite');
    const h1 = await start({ SQLITE_PATH: dbPath });
    const alice = await client(h1, 'Alice Restart');
    const room = await alice.createRoom({ name: 'Durable Room', mode: 'link', suite: 'aes-256-gcm', ttl: 0 });
    await alice.sendText(room.rid, 'survives restarts');
    await waitFor(() => alice.rooms.get(room.rid)!.messages.some((m) => m.status === 'sent'), 'ack');
    const invite = alice.inviteFor(room.rid);
    alice.disconnect();
    await h1.server.close();
    opened.splice(opened.indexOf(h1.server), 1);

    const h2 = await start({ SQLITE_PATH: dbPath });
    const bob = await client(h2, 'Bob Restart');
    await bob.joinRoom(invite);
    expect(bob.rooms.get(room.rid)!.name).toBe('Durable Room');
    expect(texts(bob, room.rid)).toContain('survives restarts');
  });
});

// ------------------------------------------------------------ hardening

describe('transport hardening', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await start({ ALLOWED_ORIGINS: 'https://good.example' }, (c) => {
      c.rate.connFramesPerSec = 5;
      c.rate.connFrameBurst = 30;
      c.rate.maxViolations = 1000;
    });
  });

  it('rejects WebSocket upgrades from a disallowed Origin (403)', async () => {
    const ws = openRaw(h.url, 'https://evil.example');
    const status = await new Promise<number>((resolve) => {
      ws.on('unexpected-response', (_req, res) => resolve(res.statusCode ?? 0));
      ws.on('error', () => {});
    });
    expect(status).toBe(403);
    const ok = openRaw(h.url, 'https://good.example');
    await whenOpen(ok);
    ok.close();
  });

  it('answers malformed JSON with bad-frame', async () => {
    const ws = openRaw(h.url, 'https://good.example');
    const st = framesOf(ws);
    await whenOpen(ws);
    ws.send('{not json');
    ws.send(JSON.stringify({ t: 'send', rid: 'short', id: 'x', blob: '!!', persist: true }));
    await waitFor(() => st.frames.filter((f) => f.t === 'error').length >= 2, 'bad-frame errors');
    expect(st.frames.filter((f) => f.t === 'error').every((f) => f.code === 'bad-frame')).toBe(true);
    ws.close();
  });

  it('refuses to relay for connections that have not proved membership', async () => {
    const ws = openRaw(h.url, 'https://good.example');
    const st = framesOf(ws);
    await whenOpen(ws);
    ws.send(JSON.stringify({ t: 'send', rid: newRoomId(), id: newRoomId(), blob: 'AAAA', persist: true }));
    ws.send(JSON.stringify({ t: 'join', rid: newRoomId() }));
    await waitFor(() => st.frames.filter((f) => f.t === 'error').length >= 2, 'errors');
    const codes = st.frames.filter((f) => f.t === 'error').map((f) => f.code);
    expect(codes).toEqual(['not-member', 'no-room']);
    ws.close();
  });

  it('closes the socket on frames larger than the limit', async () => {
    const ws = openRaw(h.url, 'https://good.example');
    const st = framesOf(ws);
    await whenOpen(ws);
    ws.send('x'.repeat(300_000));
    await waitFor(() => st.closed !== null || st.frames.some((f) => f.code === 'too-large'), 'oversize rejection');
    if (st.closed) expect(st.closed.code).toBe(1009);
  });

  it('rate-limits a flood of frames', async () => {
    const ws = openRaw(h.url, 'https://good.example');
    const st = framesOf(ws);
    await whenOpen(ws);
    for (let i = 0; i < 300; i++) ws.send('{"t":"ping"}');
    await waitFor(() => st.frames.some((f) => f.code === 'rate-limited'), 'rate-limited error');
    const pongs = st.frames.filter((f) => f.t === 'pong').length;
    expect(pongs).toBeLessThan(300);
    expect(pongs).toBeGreaterThanOrEqual(30);
    ws.close();
  });

  it('closes abusive connections after repeated violations', async () => {
    const h2 = await start({}, (c) => {
      c.rate.connFramesPerSec = 1;
      c.rate.connFrameBurst = 5;
      c.rate.maxViolations = 10;
    });
    const ws = openRaw(h2.url);
    const st = framesOf(ws);
    await whenOpen(ws);
    for (let i = 0; i < 100; i++) if (ws.readyState === ws.OPEN) ws.send('{"t":"ping"}');
    await waitFor(() => st.closed !== null, 'socket closed');
    expect(st.closed!.code).toBe(1008);
  });

  it('caps concurrent connections per IP', async () => {
    const h3 = await start({}, (c) => {
      c.rate.maxConnsPerIp = 2;
    });
    const a = openRaw(h3.url);
    const b = openRaw(h3.url);
    await Promise.all([whenOpen(a), whenOpen(b)]);
    const c = openRaw(h3.url);
    const status = await new Promise<number>((resolve) => {
      c.on('unexpected-response', (_req, res) => resolve(res.statusCode ?? 0));
      c.on('error', () => {});
    });
    expect(status).toBe(429);
  });
});
