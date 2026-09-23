/**
 * CipherClient - the end-to-end encryption engine behind the UI.
 *
 * It owns the device identity, per-room key material and state, speaks the
 * relay protocol over any Transport, and exposes a small async API
 * (createRoom / joinRoom / sendText / sendFile / rotateKey ...). The React app
 * and the integration tests drive exactly this class.
 */
import { b64u, fromB64u, fromUtf8, randomBytes, utf8, type Bytes } from '../encoding.ts';
import { openEnvelope, sealEnvelope, type Body, type BodyContent, type BodyMeta } from '../envelope.ts';
import { decryptFile, encryptFile, type FileManifest } from '../files.ts';
import { openHeader, sealHeader, type SecretHeader } from '../header.ts';
import { publicIdentity, type Identity, type PublicIdentity } from '../identity.ts';
import {
  checkKdfParams,
  deriveRoomKeys,
  newKdfParams,
  passphraseToRoomSecret,
  type KdfParams,
  type RoomKeys,
} from '../kdf.ts';
import { newRoomId, newRoomSecret, type RoomInvite } from '../keyfile.ts';
import { proveMembership, signRekey } from '../membership.ts';
import {
  LIMITS,
  type ClientFrame,
  type KeyMode,
  type PublicHeader,
  type RoomHeaderWire,
  type ServerFrame,
  type WireMsg,
} from '../protocol.ts';
import { initInitiator, initResponder, ratchetDecrypt, ratchetEncrypt, type RatchetState } from '../ratchet.ts';
import { checkReplay, recordCounter, type ReplayState } from '../replay.ts';
import { CryptoError, SUITE_INFO, type SuiteId } from '../suites.ts';
import { createPrekeyBundle, x3dhInitiate, x3dhRespond, type PrekeyBundle, type X3dhInit } from '../x3dh.ts';
import type { Transport } from './transport.ts';

// ------------------------------------------------------------------ types

export interface Sender {
  ed: string;
  x: string;
  name: string;
}

export type MessageKind = 'text' | 'file' | 'system' | 'rejected' | 'locked';

export interface ChatMessage {
  id: string;
  ts: number;
  serverTs: number;
  epoch: number;
  mine: boolean;
  sender: Sender;
  kind: MessageKind;
  text?: string;
  file?: FileManifest;
  exp?: number;
  status?: 'sending' | 'sent';
  readBy?: string[];
  /** why a frame was rejected / system notice severity */
  reason?: string;
  severity?: 'info' | 'warn' | 'danger';
  /** delivered through the Double Ratchet (1:1 rooms) */
  ratchet?: boolean;
}

export interface MemberInfo {
  ed: string;
  x: string;
  name: string;
  firstSeen: number;
  lastSeen: number;
}

export interface PkState {
  role: 'responder' | 'initiator';
  spkPriv?: string;
  bundle: PrekeyBundle;
  peer?: { ed: string; x: string; name: string };
  session?: RatchetState;
  ad?: string;
  init?: X3dhInit;
}

export interface RoomState {
  rid: string;
  mode: KeyMode;
  suite: SuiteId;
  epoch: number;
  /** epoch -> room secret (base64url). Old epochs kept for history. */
  keys: Record<string, string>;
  pub: PublicHeader;
  name: string;
  ttl: number;
  createdAt: number;
  createdBy: string;
  sendCtr: number;
  replay: ReplayState;
  messages: ChatMessage[];
  members: Record<string, MemberInfo>;
  pk?: PkState;
  pendingKey?: { epoch: number; key: string };
  needsKey?: boolean;
  receipted: string[];
  unread: number;
  joinedAt: number;
}

export interface Contact {
  ed: string;
  x: string;
  name: string;
  verified: boolean;
  verifiedAt?: number;
  firstSeen: number;
}

export interface ClientSnapshot {
  rooms: RoomState[];
  contacts: Record<string, Contact>;
}

export type FrameDir = 'in' | 'out';
export interface FrameEvent {
  dir: FrameDir;
  raw: string;
  at: number;
  tampered?: boolean;
}

export interface CreateRoomOptions {
  name: string;
  mode: KeyMode;
  suite: SuiteId;
  ttl: number;
  passphrase?: string;
  kdf?: KdfParams['alg'];
}

type Listener<T> = (v: T) => void;

interface ClientEvents {
  change: string | null;
  frame: FrameEvent;
  status: ConnStatus;
  notice: { rid?: string; text: string; level: 'info' | 'warn' | 'danger' };
  persist: null;
}

export type ConnStatus = 'connecting' | 'online' | 'offline';

interface PendingJoin {
  resolve: (rid: string) => void;
  reject: (e: Error) => void;
  key?: Bytes;
  passphrase?: string;
  invite?: RoomInvite;
  creating?: { state: RoomState };
}

const MAX_LOCAL_MESSAGES = 1000;
const TYPING_MS = 6000;

function isDr(c: BodyContent): c is Extract<BodyContent, { k: 'dr' }> {
  return c.k === 'dr';
}

// ------------------------------------------------------------------ client

export class CipherClient {
  readonly me: PublicIdentity;
  status: ConnStatus = 'offline';
  readonly rooms = new Map<string, RoomState>();
  contacts: Record<string, Contact> = {};
  /** rid -> (signer ed -> typing-until timestamp) */
  readonly typing = new Map<string, Map<string, number>>();
  /** Demo feature: corrupt the next incoming ciphertext, like a malicious relay would. */
  tamperNext = false;

  private listeners = new Map<keyof ClientEvents, Set<Listener<unknown>>>();
  private keyCache = new Map<string, RoomKeys>();
  private sessionNonce = new Map<string, Bytes>();
  private pendingJoins = new Map<string, PendingJoin>();
  private pendingFiles = new Map<string, (chunks: string[] | null) => void>();
  private rotating = new Set<string>();
  /** Rooms the relay currently admits this connection to (membership proven). */
  private admitted = new Set<string>();
  private queue: Promise<void> = Promise.resolve();
  private readonly now: () => number;

  constructor(
    private readonly transport: Transport,
    private readonly identity: Identity,
    public displayName: string,
    opts: { snapshot?: ClientSnapshot; now?: () => number } = {},
  ) {
    this.me = publicIdentity(identity);
    this.now = opts.now ?? Date.now;
    for (const r of opts.snapshot?.rooms ?? []) this.rooms.set(r.rid, r);
    this.contacts = opts.snapshot?.contacts ?? {};
  }

  // ------------------------------------------------------------- events

  on<K extends keyof ClientEvents>(ev: K, fn: Listener<ClientEvents[K]>): () => void {
    let set = this.listeners.get(ev);
    if (!set) this.listeners.set(ev, (set = new Set()));
    const f = fn as Listener<unknown>;
    set.add(f);
    return () => {
      set.delete(f);
    };
  }

  private emit<K extends keyof ClientEvents>(ev: K, v: ClientEvents[K]): void {
    this.listeners.get(ev)?.forEach((fn) => fn(v));
  }

  private changed(rid: string | null): void {
    this.emit('change', rid);
    this.emit('persist', null);
  }

  // ---------------------------------------------------------- connection

  connect(): void {
    this.setStatus('connecting');
    this.transport.connect({
      onOpen: () => {},
      onMessage: (raw) => {
        this.queue = this.queue.then(() => this.onRaw(raw)).catch((e) => console.error('[cipherchat]', e));
      },
      onClose: () => {
        this.admitted.clear();
        this.setStatus('offline');
      },
    });
  }

  disconnect(): void {
    this.transport.close();
    this.setStatus('offline');
  }

  private setStatus(s: ConnStatus): void {
    this.status = s;
    this.emit('status', s);
  }

  private send(f: ClientFrame): void {
    const raw = JSON.stringify(f);
    this.emit('frame', { dir: 'out', raw, at: this.now() });
    this.transport.send(raw);
  }

  snapshot(): ClientSnapshot {
    return { rooms: [...this.rooms.values()], contacts: this.contacts };
  }

  // ---------------------------------------------------------- key helpers

  private keysFor(room: RoomState, epoch: number): RoomKeys | undefined {
    const cacheKey = `${room.rid}:${epoch}`;
    let k = this.keyCache.get(cacheKey);
    if (!k) {
      const rk = room.keys[String(epoch)];
      if (!rk) return undefined;
      k = deriveRoomKeys(fromB64u(rk), room.rid, epoch);
      this.keyCache.set(cacheKey, k);
    }
    return k;
  }

  private currentKeys(room: RoomState): RoomKeys {
    const k = this.keysFor(room, room.epoch);
    if (!k) throw new Error('no key for the current epoch');
    return k;
  }

  // ------------------------------------------------------------- rooms

  async createRoom(o: CreateRoomOptions): Promise<RoomState> {
    const rid = newRoomId();
    let rk: Bytes;
    let kdf: KdfParams | undefined;
    if (o.mode === 'passphrase') {
      if (!o.passphrase) throw new Error('passphrase required');
      kdf = newKdfParams(o.kdf ?? 'argon2id');
      rk = await passphraseToRoomSecret(o.passphrase, kdf);
    } else {
      rk = newRoomSecret();
    }
    const now = this.now();
    const pub: PublicHeader = { v: 1, suite: o.suite, epoch: 0, ...(kdf ? { kdf } : {}) };
    const secret: SecretHeader = {
      name: o.name.trim().slice(0, 80) || 'Untitled room',
      mode: o.mode,
      ttl: o.ttl,
      createdAt: now,
      createdBy: this.displayName,
    };
    const state: RoomState = {
      rid,
      mode: o.mode,
      suite: o.suite,
      epoch: 0,
      keys: { '0': b64u(rk) },
      pub,
      name: secret.name,
      ttl: o.ttl,
      createdAt: now,
      createdBy: this.displayName,
      sendCtr: 0,
      replay: {},
      messages: [],
      members: {},
      receipted: [],
      unread: 0,
      joinedAt: now,
    };
    if (o.mode === 'pk') {
      const { bundle, spkPriv } = createPrekeyBundle(this.identity);
      secret.bundle = bundle;
      state.pk = { role: 'responder', bundle, spkPriv: b64u(spkPriv) };
    }
    const keys = this.keysFor(state, 0)!;
    const header = await sealHeader(rid, pub, secret, keys);
    return new Promise<RoomState>((resolve, reject) => {
      this.pendingJoins.set(rid, {
        resolve: () => resolve(this.rooms.get(rid)!),
        reject,
        creating: { state },
      });
      this.send({ t: 'create', rid, verifier: b64u(keys.authPub), header });
    });
  }

  /** Join with a key (link / key file / QR) or a passphrase. Resolves once the relay admits us. */
  joinRoom(invite: RoomInvite, passphrase?: string): Promise<string> {
    const existing = this.rooms.get(invite.rid);
    if (existing && !existing.needsKey && !invite.key) return Promise.resolve(invite.rid);
    return new Promise<string>((resolve, reject) => {
      this.pendingJoins.set(invite.rid, {
        resolve,
        reject,
        invite,
        ...(invite.key ? { key: invite.key } : {}),
        ...(passphrase ? { passphrase } : {}),
      });
      this.send({ t: 'join', rid: invite.rid });
    });
  }

  /** Re-join all known rooms after (re)connecting. */
  private rejoinAll(): void {
    for (const r of this.rooms.values()) {
      if (r.needsKey || this.pendingJoins.has(r.rid)) continue;
      this.pendingJoins.set(r.rid, { resolve: () => {}, reject: () => {} });
      this.send({ t: 'join', rid: r.rid });
    }
  }

  inviteFor(rid: string, relay?: string): RoomInvite {
    const r = this.mustRoom(rid);
    const key = r.keys[String(r.epoch)];
    return {
      rid,
      epoch: r.epoch,
      mode: r.mode,
      ...(r.mode !== 'passphrase' && key ? { key: fromB64u(key) } : {}),
      ...(relay ? { relay } : {}),
    };
  }

  /** Export the raw room secret (key file / QR) - also for passphrase rooms. */
  keyInvite(rid: string, relay?: string): RoomInvite {
    const r = this.mustRoom(rid);
    return {
      rid,
      epoch: r.epoch,
      mode: r.mode === 'passphrase' ? 'keyfile' : r.mode,
      key: fromB64u(r.keys[String(r.epoch)]!),
      ...(relay ? { relay } : {}),
    };
  }

  leaveRoom(rid: string, forget = true): void {
    this.send({ t: 'leave', rid });
    if (forget) {
      this.rooms.delete(rid);
      for (const k of this.keyCache.keys()) if (k.startsWith(rid + ':')) this.keyCache.delete(k);
    }
    this.changed(null);
  }

  private mustRoom(rid: string): RoomState {
    const r = this.rooms.get(rid);
    if (!r) throw new Error('unknown room');
    return r;
  }

  // ------------------------------------------------------------ sending

  private nextBodyMeta(room: RoomState): BodyMeta {
    room.sendCtr += 1;
    const ts = this.now();
    return {
      c: room.sendCtr,
      ts,
      n: this.displayName,
      x: this.me.x,
      ...(room.ttl > 0 ? { exp: ts + room.ttl * 1000 } : {}),
    };
  }

  private async sendBody(room: RoomState, content: BodyContent, persist: boolean): Promise<{ id: string; body: Body }> {
    const meta = this.nextBodyMeta(room);
    const body = { ...content, ...meta } as Body;
    if (!persist) delete body.exp;
    const id = b64u(randomBytes(16));
    const blob = await sealEnvelope({
      rid: room.rid,
      id,
      persist,
      suite: room.suite,
      keys: this.currentKeys(room),
      identity: this.identity,
      body,
    });
    recordCounter(room.replay, this.me.ed, meta.c);
    this.send({ t: 'send', rid: room.rid, id, blob, persist, ...(body.exp ? { exp: body.exp } : {}) });
    return { id, body };
  }

  private selfSender(): Sender {
    return { ed: this.me.ed, x: this.me.x, name: this.displayName };
  }

  private pushMessage(room: RoomState, m: ChatMessage): void {
    room.messages.push(m);
    room.messages.sort((a, b) => a.serverTs - b.serverTs || a.ts - b.ts);
    if (room.messages.length > MAX_LOCAL_MESSAGES) room.messages.splice(0, room.messages.length - MAX_LOCAL_MESSAGES);
  }

  /** Wraps content for 1:1 rooms in the Double Ratchet. */
  private async wrapPk(room: RoomState, inner: BodyContent): Promise<BodyContent> {
    const pk = room.pk!;
    if (!pk.session) {
      if (pk.role === 'responder') throw new Error('Waiting for your contact to open the invite - they must send first.');
      const { sk, ad, init } = x3dhInitiate(this.identity, pk.bundle);
      pk.session = initInitiator(sk, pk.bundle.spk);
      pk.ad = b64u(ad);
      pk.init = init;
      pk.peer = { ed: pk.bundle.ed, x: pk.bundle.x, name: room.createdBy };
      sk.fill(0);
    }
    const { state, msg } = await ratchetEncrypt(pk.session, utf8(JSON.stringify(inner)), fromB64u(pk.ad!), room.suite);
    pk.session = state;
    return { k: 'dr', dr: msg, ...(pk.init ? { init: pk.init } : {}) };
  }

  canSend(rid: string): { ok: boolean; why?: string } {
    const r = this.rooms.get(rid);
    if (!r) return { ok: false, why: 'Unknown room' };
    if (r.needsKey) return { ok: false, why: 'The room key was rotated - import the new key to continue.' };
    if (!this.admitted.has(rid)) {
      return { ok: false, why: this.status === 'online' ? 'Proving membership to the relay…' : 'Offline - reconnecting…' };
    }
    if (r.mode === 'pk' && r.pk?.role === 'responder' && !r.pk.session) {
      return { ok: false, why: 'Waiting for your contact to open the invite and say hello.' };
    }
    return { ok: true };
  }

  async sendText(rid: string, text: string): Promise<string> {
    const room = this.mustRoom(rid);
    const t = text.slice(0, LIMITS.maxMessageChars);
    if (!t.trim()) throw new Error('empty message');
    const content: BodyContent = room.mode === 'pk' ? await this.wrapPk(room, { k: 'text', text: t }) : { k: 'text', text: t };
    const { id, body } = await this.sendBody(room, content, true);
    this.pushMessage(room, {
      id,
      ts: body.ts,
      serverTs: body.ts,
      epoch: room.epoch,
      mine: true,
      sender: this.selfSender(),
      kind: 'text',
      text: t,
      status: 'sending',
      ...(body.exp ? { exp: body.exp } : {}),
      ...(room.mode === 'pk' ? { ratchet: true } : {}),
    });
    this.changed(rid);
    return id;
  }

  async sendFile(rid: string, data: Bytes, name: string, mime: string): Promise<string> {
    const room = this.mustRoom(rid);
    const keys = this.currentKeys(room);
    const { manifest, chunks } = await encryptFile(data, { name, mime }, {
      rid,
      suite: room.suite,
      roomFileKey: keys.file,
      epoch: room.epoch,
    });
    const exp = room.ttl > 0 ? this.now() + room.ttl * 1000 : undefined;
    chunks.forEach((blob, idx) =>
      this.send({ t: 'chunk', rid, fid: manifest.fid, idx, total: chunks.length, blob, ...(exp ? { exp } : {}) }),
    );
    const content: BodyContent =
      room.mode === 'pk' ? await this.wrapPk(room, { k: 'file', file: manifest }) : { k: 'file', file: manifest };
    const { id, body } = await this.sendBody(room, content, true);
    this.pushMessage(room, {
      id,
      ts: body.ts,
      serverTs: body.ts,
      epoch: room.epoch,
      mine: true,
      sender: this.selfSender(),
      kind: 'file',
      file: manifest,
      status: 'sending',
      ...(body.exp ? { exp: body.exp } : {}),
      ...(room.mode === 'pk' ? { ratchet: true } : {}),
    });
    this.changed(rid);
    return id;
  }

  async fetchFile(rid: string, manifest: FileManifest): Promise<Bytes> {
    const room = this.mustRoom(rid);
    const keys = this.keysFor(room, manifest.epoch);
    if (!keys) throw new CryptoError('unknown-epoch', 'this file was encrypted with a key this device does not have');
    const chunks = await new Promise<string[] | null>((resolve) => {
      this.pendingFiles.set(`${rid}:${manifest.fid}`, resolve);
      this.send({ t: 'getFile', rid, fid: manifest.fid });
    });
    if (!chunks) throw new Error('file is no longer available on the relay (expired or incomplete)');
    return decryptFile(chunks, manifest, { rid, suite: room.suite, roomFileKey: keys.file });
  }

  async sendTyping(rid: string, on: boolean): Promise<void> {
    const room = this.rooms.get(rid);
    if (!room || !this.canSend(rid).ok) return;
    await this.sendBody(room, { k: 'typing', on }, false);
  }

  /** Sends an encrypted read receipt for messages not yet acknowledged. */
  async markRead(rid: string): Promise<void> {
    const room = this.rooms.get(rid);
    if (!room) return;
    room.unread = 0;
    const ids = room.messages
      .filter((m) => !m.mine && (m.kind === 'text' || m.kind === 'file') && !room.receipted.includes(m.id))
      .map((m) => m.id)
      .slice(-50);
    if (!ids.length || !this.canSend(rid).ok) return this.changed(rid);
    room.receipted.push(...ids);
    if (room.receipted.length > 500) room.receipted.splice(0, room.receipted.length - 500);
    await this.sendBody(room, { k: 'read', ids }, false);
    this.changed(rid);
  }

  /**
   * Key rotation. A new random secret (or a new passphrase) becomes epoch+1.
   * With `distribute`, the new key is sent in-band, encrypted under the old
   * one (convenient). Without it, members must receive it out-of-band - the
   * way to evict someone, since the relay makes every connection re-prove
   * membership with the new key.
   */
  async rotateKey(rid: string, opts: { distribute: boolean; passphrase?: string; kdf?: KdfParams['alg'] }): Promise<void> {
    const room = this.mustRoom(rid);
    const nonce = this.sessionNonce.get(rid);
    if (!nonce) throw new Error('not connected to this room');
    const oldKeys = this.currentKeys(room);
    const epoch = room.epoch + 1;
    let rk: Bytes;
    let kdf: KdfParams | undefined;
    if (room.mode === 'passphrase') {
      if (!opts.passphrase) throw new Error('enter the new passphrase');
      kdf = newKdfParams(opts.kdf ?? room.pub.kdf?.alg ?? 'argon2id');
      rk = await passphraseToRoomSecret(opts.passphrase, kdf);
    } else {
      rk = newRoomSecret();
    }
    const newKeys = deriveRoomKeys(rk, rid, epoch);
    const pub: PublicHeader = { v: 1, suite: room.suite, epoch, ...(kdf ? { kdf } : {}) };
    const secret: SecretHeader = {
      name: room.name,
      mode: room.mode,
      ttl: room.ttl,
      createdAt: room.createdAt,
      createdBy: room.createdBy,
      ...(room.pk?.role === 'responder' ? { bundle: room.pk.bundle } : {}),
      ...(room.pk?.role === 'initiator' ? { bundle: room.pk.bundle } : {}),
    };
    const header = await sealHeader(rid, pub, secret, newKeys);
    room.pendingKey = { epoch, key: b64u(rk) };
    this.rotating.add(rid);
    if (opts.distribute) await this.sendBody(room, { k: 'rekey', epoch, key: b64u(rk) }, true);
    const verifier = b64u(newKeys.authPub);
    this.send({ t: 'rekey', rid, epoch, verifier, header, sig: signRekey(oldKeys.authPriv, rid, epoch, verifier, header, nonce) });
  }

  setTtl(rid: string, ttl: number): void {
    // TTL lives in the encrypted header; changing it would need a header update - kept per-epoch.
    const r = this.mustRoom(rid);
    r.ttl = ttl;
    this.changed(rid);
  }

  /** Removes expired disappearing messages locally. Returns how many were removed. */
  sweepExpired(): number {
    const now = this.now();
    let n = 0;
    for (const r of this.rooms.values()) {
      const before = r.messages.length;
      r.messages = r.messages.filter((m) => m.exp === undefined || m.exp > now);
      if (r.messages.length !== before) {
        n += before - r.messages.length;
        this.changed(r.rid);
      }
    }
    for (const [rid, m] of this.typing) {
      for (const [ed, until] of m) if (until <= now) m.delete(ed);
      if (!m.size) this.typing.delete(rid);
    }
    return n;
  }

  setVerified(ed: string, verified: boolean): void {
    const c = this.contacts[ed];
    if (!c) return;
    c.verified = verified;
    if (verified) c.verifiedAt = this.now();
    else delete c.verifiedAt;
    this.changed(null);
  }

  // ------------------------------------------------------------ inbound

  private async onRaw(raw: string): Promise<void> {
    let f: ServerFrame;
    let tampered = false;
    try {
      f = JSON.parse(raw) as ServerFrame;
    } catch {
      return;
    }
    if (this.tamperNext && f.t === 'msg' && f.persist) {
      // Flip one bit in the middle of the ciphertext, as a malicious relay could.
      const bytes = fromB64u(f.blob);
      const i = Math.min(bytes.length - 1, 6 + Math.floor((bytes.length - 6) / 2));
      bytes[i]! ^= 0x01;
      f = { ...f, blob: b64u(bytes) };
      raw = JSON.stringify(f);
      this.tamperNext = false;
      tampered = true;
    }
    this.emit('frame', { dir: 'in', raw, at: this.now(), ...(tampered ? { tampered } : {}) });
    switch (f.t) {
      case 'welcome':
        this.admitted.clear();
        this.setStatus('online');
        this.rejoinAll();
        return;
      case 'challenge':
        return this.onChallenge(f.rid, f.nonce, f.pub);
      case 'joined':
        return this.onJoined(f.rid, f.header, f.history, f.nonce);
      case 'msg':
        return this.onMessage(f.rid, { id: f.id, blob: f.blob, ts: f.ts, ...(f.exp ? { exp: f.exp } : {}) }, f.persist, true);
      case 'file': {
        const k = `${f.rid}:${f.fid}`;
        this.pendingFiles.get(k)?.(f.chunks);
        this.pendingFiles.delete(k);
        return;
      }
      case 'rekeyed':
        return this.onRekeyed(f.rid, f.epoch, f.header);
      case 'presence': {
        const r = this.rooms.get(f.rid);
        if (r) {
          this.presence.set(f.rid, f.members);
          this.emit('change', f.rid);
        }
        return;
      }
      case 'error': {
        const p = f.rid ? this.pendingJoins.get(f.rid) : undefined;
        if (p && f.rid) {
          this.pendingJoins.delete(f.rid);
          const room = this.rooms.get(f.rid);
          if (room && f.code === 'auth-failed') {
            room.needsKey = true;
            this.changed(f.rid);
          }
          p.reject(new Error(f.msg));
        }
        this.emit('notice', { ...(f.rid ? { rid: f.rid } : {}), text: f.msg, level: 'warn' });
        return;
      }
      default:
        return;
    }
  }

  readonly presence = new Map<string, number>();

  private async onChallenge(rid: string, nonceB64: string, pub: PublicHeader): Promise<void> {
    const p = this.pendingJoins.get(rid);
    const room = this.rooms.get(rid);
    let rk: Bytes | undefined;
    try {
      if (p?.key) {
        rk = p.key;
      } else if (p?.passphrase) {
        if (!pub.kdf) throw new Error('this room is not passphrase-protected - use the invite link');
        checkKdfParams(pub.kdf); // refuse relay-supplied downgrades
        rk = await passphraseToRoomSecret(p.passphrase, pub.kdf);
      } else if (room?.keys[String(pub.epoch)]) {
        rk = fromB64u(room.keys[String(pub.epoch)]!);
      } else if (room?.pendingKey?.epoch === pub.epoch) {
        rk = fromB64u(room.pendingKey.key);
      }
      if (!rk) {
        if (pub.kdf) throw new Error('passphrase required');
        throw new Error('this device has no key for the current room epoch - ask for a new invite');
      }
      const keys = deriveRoomKeys(rk, rid, pub.epoch);
      if (p) p.key = rk;
      this.send({ t: 'auth', rid, sig: proveMembership(keys.authPriv, rid, fromB64u(nonceB64), pub.epoch) });
    } catch (e) {
      this.pendingJoins.delete(rid);
      if (room && !rk) {
        room.needsKey = true;
        this.changed(rid);
      }
      this.send({ t: 'leave', rid });
      p?.reject(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private async onJoined(rid: string, header: RoomHeaderWire, history: WireMsg[], nonce: string): Promise<void> {
    const p = this.pendingJoins.get(rid);
    this.pendingJoins.delete(rid);
    this.sessionNonce.set(rid, fromB64u(nonce));
    const epoch = header.pub.epoch;
    try {
      let room = this.rooms.get(rid) ?? p?.creating?.state;
      const rk = p?.key ?? (room?.keys[String(epoch)] ? fromB64u(room.keys[String(epoch)]!) : undefined);
      if (!rk) throw new Error('no key for this room');
      const keys = deriveRoomKeys(rk, rid, epoch);
      const secret = await openHeader(rid, header, keys);
      if (!room) {
        room = {
          rid,
          mode: secret.mode,
          suite: header.pub.suite,
          epoch,
          keys: {},
          pub: header.pub,
          name: secret.name,
          ttl: secret.ttl,
          createdAt: secret.createdAt,
          createdBy: secret.createdBy,
          sendCtr: 0,
          replay: {},
          messages: [],
          members: {},
          receipted: [],
          unread: 0,
          joinedAt: this.now(),
        };
        if (secret.mode === 'pk') {
          if (!secret.bundle) throw new Error('1:1 room header has no prekey bundle');
          if (secret.bundle.ed === this.me.ed) throw new Error('this is your own 1:1 invite - send it to your contact');
          room.pk = { role: 'initiator', bundle: secret.bundle };
        }
        this.addSystem(room, `You joined "${secret.name}". Messages are end-to-end encrypted with ${SUITE_INFO[header.pub.suite].label}.`, 'info');
      } else if (p?.creating) {
        this.addSystem(room, `Room created. Only people holding the key can read it - the relay stores ciphertext only.`, 'info');
      }
      room.keys[String(epoch)] = b64u(rk);
      room.epoch = epoch;
      room.pub = header.pub;
      room.suite = header.pub.suite;
      room.name = secret.name;
      room.ttl = secret.ttl;
      delete room.needsKey;
      if (room.pendingKey && room.pendingKey.epoch <= epoch) delete room.pendingKey;
      this.keyCache.set(`${rid}:${epoch}`, keys);
      this.rooms.set(rid, room);
      this.admitted.add(rid);
      for (const m of history) await this.onMessage(rid, m, true, false);
      this.changed(rid);
      p?.resolve(rid);
    } catch (e) {
      this.send({ t: 'leave', rid });
      p?.reject(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private async onRekeyed(rid: string, epoch: number, header: RoomHeaderWire): Promise<void> {
    const room = this.rooms.get(rid);
    if (!room || epoch <= room.epoch) return;
    const pending = room.pendingKey;
    if (pending && pending.epoch === epoch) {
      try {
        const keys = deriveRoomKeys(fromB64u(pending.key), rid, epoch);
        await openHeader(rid, header, keys);
        room.keys[String(epoch)] = pending.key;
        room.epoch = epoch;
        room.pub = header.pub;
        delete room.pendingKey;
        this.keyCache.set(`${rid}:${epoch}`, keys);
        this.addSystem(room, `Room key rotated (epoch ${epoch}). Earlier keys are kept on this device for history only.`, 'info');
        this.changed(rid);
        // The relay keeps the rotating connection authorised; everyone else was
        // de-authorised and must re-prove membership with the new key.
        if (!this.rotating.delete(rid)) {
          this.admitted.delete(rid);
          this.pendingJoins.set(rid, { resolve: () => {}, reject: () => {} });
          this.send({ t: 'join', rid });
        }
        return;
      } catch {
        /* fall through: key did not match the new header */
      }
    }
    room.needsKey = true;
    this.addSystem(room, 'The room key was rotated out-of-band. Import the new invite link or key file to keep reading.', 'warn');
    this.changed(rid);
  }

  private addSystem(room: RoomState, text: string, severity: 'info' | 'warn' | 'danger', ts = this.now()): void {
    this.pushMessage(room, {
      id: 'sys-' + b64u(randomBytes(8)),
      ts,
      serverTs: ts,
      epoch: room.epoch,
      mine: false,
      sender: { ed: '', x: '', name: 'CipherChat' },
      kind: 'system',
      text,
      severity,
    });
  }

  private reject(room: RoomState, msg: WireMsg, kind: 'rejected' | 'locked', reason: string): void {
    this.pushMessage(room, {
      id: msg.id,
      ts: msg.ts,
      serverTs: msg.ts,
      epoch: -1,
      mine: false,
      sender: { ed: '', x: '', name: 'Unknown' },
      kind,
      reason,
      severity: kind === 'locked' ? 'info' : 'danger',
    });
  }

  /** Track who is in the room and warn when a known name shows up with a new key. */
  private trackMember(room: RoomState, signer: string, body: Body): void {
    const now = this.now();
    const known = room.members[signer];
    if (!known && signer !== this.me.ed) {
      const sameName = Object.values(room.members).find((m) => m.name === body.n && m.ed !== signer);
      if (sameName) {
        const wasVerified = this.contacts[sameName.ed]?.verified;
        this.addSystem(
          room,
          `${body.n}'s safety number changed - this is a different key than before.${
            wasVerified ? ' You had VERIFIED the old key: confirm in person before trusting it.' : ''
          }`,
          wasVerified ? 'danger' : 'warn',
          body.ts,
        );
      }
    }
    room.members[signer] = { ed: signer, x: body.x, name: body.n.slice(0, 60), firstSeen: known?.firstSeen ?? now, lastSeen: now };
    if (signer !== this.me.ed) {
      const c = this.contacts[signer];
      if (!c) this.contacts[signer] = { ed: signer, x: body.x, name: body.n.slice(0, 60), verified: false, firstSeen: now };
      else c.name = body.n.slice(0, 60);
    }
  }

  private async onMessage(rid: string, msg: WireMsg, persist: boolean, live: boolean): Promise<void> {
    const room = this.rooms.get(rid);
    if (!room) return;
    const existing = room.messages.find((m) => m.id === msg.id);
    if (existing) {
      if (existing.mine && existing.status === 'sending') {
        existing.status = 'sent';
        existing.serverTs = msg.ts;
        this.changed(rid);
      }
      return;
    }
    let opened;
    try {
      opened = await openEnvelope(rid, msg.id, persist, msg.blob, (epoch) => {
        const keys = this.keysFor(room, epoch);
        return keys ? { keys, suite: room.suite } : undefined;
      });
    } catch (e) {
      if (!persist) return; // ephemeral junk: drop silently
      const code = e instanceof CryptoError ? e.code : 'bad-format';
      if (code === 'unknown-epoch') {
        this.reject(room, msg, 'locked', 'Encrypted with an earlier room key that this device never had.');
      } else if (code === 'bad-signature') {
        this.reject(room, msg, 'rejected', 'Forged: the Ed25519 signature does not match the claimed sender. Message discarded.');
      } else {
        this.reject(room, msg, 'rejected', 'Tampered or corrupted ciphertext: AEAD authentication failed. Message discarded.');
      }
      this.changed(rid);
      return;
    }
    const { signer, body } = opened;
    const verdict = checkReplay(room.replay, signer, body.c);
    if (verdict !== 'ok') {
      if (persist) {
        this.addSystem(room, `Blocked a replayed message (${verdict} counter ${body.c}).`, 'warn', msg.ts);
        this.changed(rid);
      }
      return;
    }
    recordCounter(room.replay, signer, body.c);
    if (body.exp !== undefined && body.exp <= this.now()) return; // already expired
    if (signer === this.me.ed && body.k !== 'rekey') return; // our own message from another session
    this.trackMember(room, signer, body);
    const sender: Sender = { ed: signer, x: body.x, name: body.n.slice(0, 60) };
    const base = {
      id: msg.id,
      ts: body.ts,
      serverTs: msg.ts,
      epoch: opened.epoch,
      mine: false,
      sender,
      ...(body.exp !== undefined ? { exp: body.exp } : {}),
    };
    switch (body.k) {
      case 'text':
        if (typeof body.text !== 'string') return;
        this.pushMessage(room, { ...base, kind: 'text', text: body.text.slice(0, LIMITS.maxMessageChars) });
        this.typing.get(rid)?.delete(signer);
        if (live) room.unread++;
        break;
      case 'file':
        this.pushMessage(room, { ...base, kind: 'file', file: body.file });
        this.typing.get(rid)?.delete(signer);
        if (live) room.unread++;
        break;
      case 'typing': {
        let m = this.typing.get(rid);
        if (!m) this.typing.set(rid, (m = new Map()));
        if (body.on) m.set(signer, this.now() + TYPING_MS);
        else m.delete(signer);
        this.emit('change', rid);
        return;
      }
      case 'read':
        if (!Array.isArray(body.ids)) return;
        for (const m of room.messages) {
          if (m.mine && body.ids.includes(m.id)) {
            m.readBy = [...new Set([...(m.readBy ?? []), signer])];
          }
        }
        break;
      case 'rekey':
        if (body.epoch === room.epoch + 1 && typeof body.key === 'string') {
          room.pendingKey = { epoch: body.epoch, key: body.key };
        }
        if (signer === this.me.ed) return;
        break;
      case 'dr':
        await this.onRatchet(room, base, signer, body);
        this.typing.get(rid)?.delete(signer);
        break;
      default:
        return;
    }
    this.changed(rid);
  }

  private async onRatchet(
    room: RoomState,
    base: Omit<ChatMessage, 'kind'>,
    signer: string,
    body: Body,
  ): Promise<void> {
    const pk = room.pk;
    if (!pk || !isDr(body)) return;
    try {
      if (pk.role === 'responder' && !pk.session) {
        if (!body.init) throw new CryptoError('ratchet', 'first message is missing the X3DH handshake');
        if (body.init.ed !== signer || body.init.x !== body.x) {
          throw new CryptoError('bad-signature', 'handshake identity does not match the message signer');
        }
        if (pk.peer && pk.peer.ed !== signer) throw new CryptoError('ratchet', 'second device tried to start a session');
        const { sk, ad } = x3dhRespond(this.identity, fromB64u(pk.spkPriv!), pk.bundle, body.init);
        const fresh = initResponder(sk, fromB64u(pk.spkPriv!), pk.bundle.spk);
        const { state, plaintext } = await ratchetDecrypt(fresh, body.dr, ad, room.suite);
        pk.session = state;
        pk.ad = b64u(ad);
        pk.peer = { ed: signer, x: body.x, name: body.n };
        this.addSystem(room, `Secure session established with ${body.n} (X3DH + Double Ratchet). Compare safety numbers to rule out a man-in-the-middle.`, 'info', base.ts);
        this.deliverInner(room, base, plaintext);
        return;
      }
      if (!pk.session || !pk.ad) throw new CryptoError('ratchet', 'no session');
      const expected = pk.peer?.ed ?? pk.bundle.ed;
      if (signer !== expected) throw new CryptoError('ratchet', 'message from a device outside this 1:1 session');
      const { state, plaintext } = await ratchetDecrypt(pk.session, body.dr, fromB64u(pk.ad), room.suite);
      pk.session = state;
      if (pk.role === 'initiator' && pk.init) delete pk.init; // peer replied: handshake confirmed
      this.deliverInner(room, base, plaintext);
    } catch (e) {
      const why = e instanceof Error ? e.message : String(e);
      this.pushMessage(room, { ...base, kind: 'rejected', reason: `Rejected by the Double Ratchet: ${why}`, severity: 'danger' });
    }
  }

  private deliverInner(room: RoomState, base: Omit<ChatMessage, 'kind'>, plaintext: Bytes): void {
    const inner = JSON.parse(fromUtf8(plaintext)) as BodyContent;
    if (inner.k === 'text' && typeof inner.text === 'string') {
      this.pushMessage(room, { ...base, kind: 'text', text: inner.text.slice(0, LIMITS.maxMessageChars), ratchet: true });
      room.unread++;
    } else if (inner.k === 'file') {
      this.pushMessage(room, { ...base, kind: 'file', file: inner.file, ratchet: true });
      room.unread++;
    }
  }
}
