/**
 * The blind relay's protocol logic, transport-agnostic. The Node server wraps
 * it with WebSockets (+ rate limits, origin checks, persistence); the offline
 * demo runs the very same class inside a browser tab over BroadcastChannel.
 *
 * What it knows: random room ids, public headers (suite/epoch/KDF salt),
 * Ed25519 verifiers, opaque ciphertext and timing. What it never gets: keys,
 * plaintext, room names, file names or contents, or even which member sent
 * a given message (the signature is inside the ciphertext).
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { b64u, randomBytes, toHex, utf8, type Bytes } from '../encoding.ts';
import { checkMembership, checkRekey } from '../membership.ts';
import {
  LIMITS,
  PROTOCOL_VERSION,
  parseClientFrame,
  type ClientFrame,
  type ErrorCode,
  type ServerFrame,
} from '../protocol.ts';
import type { RelayStore } from './store.ts';

export type RelayLogger = (event: string, fields: Record<string, string | number | boolean>) => void;

export interface RelayOptions {
  /** Idle rooms are deleted after this long (ms). */
  roomTtlMs: number;
  now?: () => number;
  log?: RelayLogger;
  demo?: boolean;
  /** Observe every raw inbound frame (tests assert on these). */
  onInbound?: (connId: string, raw: string) => void;
}

interface Membership {
  authed: boolean;
  /** pending single-use challenge nonce (before auth) */
  challenge: Bytes | null;
  /** session nonce issued on join (binds rekey requests to this connection) */
  session: Bytes | null;
}

interface Conn {
  id: string;
  send: (f: ServerFrame) => void;
  rooms: Map<string, Membership>;
}

/** Log-safe room tag: a short hash, so logs cannot be joined back to invite links. */
export function roomTag(rid: string): string {
  return toHex(sha256(utf8('log:' + rid))).slice(0, 10);
}

export class RelayCore {
  private conns = new Map<string, Conn>();
  private readonly now: () => number;
  private readonly log: RelayLogger;

  constructor(
    public readonly store: RelayStore,
    private readonly opts: RelayOptions,
  ) {
    this.now = opts.now ?? Date.now;
    this.log = opts.log ?? (() => {});
  }

  connect(send: (f: ServerFrame) => void): string {
    const id = b64u(randomBytes(9));
    this.conns.set(id, { id, send, rooms: new Map() });
    send({ t: 'welcome', v: PROTOCOL_VERSION, conn: id, limits: LIMITS, ...(this.opts.demo ? { demo: true } : {}) });
    return id;
  }

  disconnect(connId: string): void {
    const c = this.conns.get(connId);
    if (!c) return;
    this.conns.delete(connId);
    for (const rid of c.rooms.keys()) this.broadcastPresence(rid);
  }

  /** Entry point for raw text frames from an untrusted client. */
  receive(connId: string, raw: string): void {
    this.opts.onInbound?.(connId, raw);
    const c = this.conns.get(connId);
    if (!c) return;
    if (raw.length > LIMITS.maxFrameBytes) return this.err(c, 'too-large', 'frame too large');
    const f = parseClientFrame(raw);
    if (!f) return this.err(c, 'bad-frame', 'malformed frame');
    this.handle(c, f);
  }

  memberCount(rid: string): number {
    let n = 0;
    for (const c of this.conns.values()) if (c.rooms.get(rid)?.authed) n++;
    return n;
  }

  stats(): { connections: number; rooms: number } {
    return { connections: this.conns.size, rooms: this.store.listRooms().length };
  }

  /** Purge expired ciphertext and idle rooms. Call periodically. */
  sweep(): void {
    const now = this.now();
    const purged = this.store.purgeExpired(now);
    let rooms = 0;
    for (const r of this.store.listRooms()) {
      if (now - r.lastActive > this.opts.roomTtlMs && this.memberCount(r.rid) === 0) {
        this.store.deleteRoom(r.rid);
        rooms++;
      }
    }
    if (purged || rooms) this.log('sweep', { purged, rooms });
  }

  private err(c: Conn, code: ErrorCode, msg: string, rid?: string): void {
    c.send({ t: 'error', code, msg, ...(rid ? { rid } : {}) });
  }

  private authed(c: Conn, rid: string): boolean {
    return c.rooms.get(rid)?.authed === true;
  }

  private broadcast(rid: string, f: ServerFrame): void {
    for (const c of this.conns.values()) if (this.authed(c, rid)) c.send(f);
  }

  private broadcastPresence(rid: string): void {
    this.broadcast(rid, { t: 'presence', rid, members: this.memberCount(rid) });
  }

  private sendJoined(c: Conn, rid: string, m: Membership): void {
    const room = this.store.getRoom(rid)!;
    m.authed = true;
    m.challenge = null;
    m.session = randomBytes(32);
    c.send({
      t: 'joined',
      rid,
      header: room.header,
      history: this.store.listMsgs(rid, this.now()),
      members: this.memberCount(rid),
      nonce: b64u(m.session),
    });
    this.broadcastPresence(rid);
  }

  private handle(c: Conn, f: ClientFrame): void {
    const now = this.now();
    switch (f.t) {
      case 'ping':
        c.send({ t: 'pong' });
        return;

      case 'create': {
        if (this.store.getRoom(f.rid)) return this.err(c, 'exists', 'room id already taken', f.rid);
        if (f.header.pub.epoch !== 0) return this.err(c, 'bad-frame', 'new rooms start at epoch 0', f.rid);
        if (c.rooms.size >= LIMITS.maxRoomsPerConnection) return this.err(c, 'quota', 'too many rooms', f.rid);
        this.store.putRoom({ rid: f.rid, verifier: f.verifier, header: f.header, createdAt: now, lastActive: now });
        const m: Membership = { authed: false, challenge: null, session: null };
        c.rooms.set(f.rid, m);
        this.log('room.create', { room: roomTag(f.rid), suite: f.header.pub.suite, kdf: f.header.pub.kdf?.alg ?? 'none' });
        this.sendJoined(c, f.rid, m);
        return;
      }

      case 'join': {
        const room = this.store.getRoom(f.rid);
        if (!room) return this.err(c, 'no-room', 'room not found (expired or never existed)', f.rid);
        if (!c.rooms.has(f.rid) && c.rooms.size >= LIMITS.maxRoomsPerConnection) {
          return this.err(c, 'quota', 'too many rooms', f.rid);
        }
        const nonce = randomBytes(32);
        c.rooms.set(f.rid, { authed: false, challenge: nonce, session: null });
        c.send({ t: 'challenge', rid: f.rid, nonce: b64u(nonce), pub: room.header.pub });
        return;
      }

      case 'auth': {
        const room = this.store.getRoom(f.rid);
        const m = c.rooms.get(f.rid);
        if (!room || !m || !m.challenge) return this.err(c, 'auth-failed', 'no pending challenge', f.rid);
        const nonce = m.challenge;
        m.challenge = null; // single use
        if (!checkMembership(room.verifier, f.rid, nonce, room.header.pub.epoch, f.sig)) {
          c.rooms.delete(f.rid);
          this.log('room.auth_fail', { room: roomTag(f.rid) });
          return this.err(c, 'auth-failed', 'membership proof rejected (wrong key?)', f.rid);
        }
        if (this.memberCount(f.rid) >= LIMITS.maxMembersPerRoom) {
          c.rooms.delete(f.rid);
          return this.err(c, 'room-full', 'room is full', f.rid);
        }
        room.lastActive = now;
        this.store.putRoom(room);
        this.log('room.join', { room: roomTag(f.rid) });
        this.sendJoined(c, f.rid, m);
        return;
      }

      case 'send': {
        if (!this.authed(c, f.rid)) return this.err(c, 'not-member', 'join the room first', f.rid);
        const room = this.store.getRoom(f.rid);
        if (!room) return this.err(c, 'no-room', 'room not found', f.rid);
        const msg = { id: f.id, blob: f.blob, ts: now, ...(f.exp !== undefined ? { exp: f.exp } : {}) };
        if (f.persist) this.store.addMsg(f.rid, msg, LIMITS.maxStoredPerRoom);
        room.lastActive = now;
        this.store.putRoom(room);
        this.broadcast(f.rid, { t: 'msg', rid: f.rid, ...msg, persist: f.persist });
        return;
      }

      case 'chunk': {
        if (!this.authed(c, f.rid)) return this.err(c, 'not-member', 'join the room first', f.rid);
        if (f.idx === 0 && this.store.countFiles(f.rid) >= LIMITS.maxFilesPerRoom) {
          return this.err(c, 'quota', 'room file quota reached', f.rid);
        }
        this.store.putChunk(f.rid, f.fid, f.idx, f.total, f.blob, f.exp);
        return;
      }

      case 'getFile': {
        if (!this.authed(c, f.rid)) return this.err(c, 'not-member', 'join the room first', f.rid);
        c.send({ t: 'file', rid: f.rid, fid: f.fid, chunks: this.store.getChunks(f.rid, f.fid, now) });
        return;
      }

      case 'rekey': {
        const room = this.store.getRoom(f.rid);
        const m = c.rooms.get(f.rid);
        if (!room || !m?.authed || !m.session) return this.err(c, 'not-member', 'join the room first', f.rid);
        if (f.epoch !== room.header.pub.epoch + 1 || f.header.pub.epoch !== f.epoch) {
          return this.err(c, 'stale-epoch', 'rekey must advance the epoch by exactly one', f.rid);
        }
        if (!checkRekey(room.verifier, f.rid, f.epoch, f.verifier, f.header, m.session, f.sig)) {
          return this.err(c, 'auth-failed', 'rekey not authorised by the current room key', f.rid);
        }
        room.verifier = f.verifier;
        room.header = f.header;
        room.lastActive = now;
        this.store.putRoom(room);
        this.log('room.rekey', { room: roomTag(f.rid), epoch: f.epoch });
        // Everyone else must prove possession of the NEW key to stay in the room.
        for (const other of this.conns.values()) {
          const om = other.rooms.get(f.rid);
          if (!om?.authed) continue;
          if (other !== c) {
            om.authed = false;
            om.session = null;
          }
          other.send({ t: 'rekeyed', rid: f.rid, epoch: f.epoch, header: f.header });
        }
        this.broadcastPresence(f.rid);
        return;
      }

      case 'leave': {
        if (c.rooms.delete(f.rid)) {
          c.send({ t: 'left', rid: f.rid });
          this.broadcastPresence(f.rid);
        }
        return;
      }
    }
  }
}

