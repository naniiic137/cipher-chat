/**
 * RelayCore unit tests with raw protocol frames: what an honest relay accepts,
 * rejects and forgets. (RelayCore is synchronous, so no waiting is needed.)
 */
import { describe, expect, it } from 'vitest';
import {
  b64u,
  deriveRoomKeys,
  fromB64u,
  LIMITS,
  MemoryStore,
  newRoomId,
  newRoomSecret,
  proveMembership,
  randomBytes,
  RelayCore,
  sealHeader,
  signRekey,
  type RoomHeaderWire,
  type RoomKeys,
  type ServerFrame,
} from '../src/index.ts';

type Frame<T extends ServerFrame['t']> = Extract<ServerFrame, { t: T }>;

function harness(roomTtlMs = 10_000) {
  const clock = { t: 1_000_000 };
  const logs: string[] = [];
  const store = new MemoryStore();
  const relay = new RelayCore(store, {
    roomTtlMs,
    now: () => clock.t,
    log: (e, f) => logs.push(JSON.stringify({ e, ...f })),
  });
  function conn() {
    const frames: ServerFrame[] = [];
    const id = relay.connect((f) => frames.push(f));
    return {
      id,
      frames,
      send: (f: unknown) => relay.receive(id, typeof f === 'string' ? f : JSON.stringify(f)),
      last: () => frames[frames.length - 1]!,
      of: <T extends ServerFrame['t']>(t: T) => frames.filter((f) => f.t === t) as Frame<T>[],
      close: () => relay.disconnect(id),
    };
  }
  return { clock, logs, store, relay, conn };
}
type Conn = ReturnType<ReturnType<typeof harness>['conn']>;

async function makeRoom(epoch = 0, rid = newRoomId()) {
  const keys = deriveRoomKeys(newRoomSecret(), rid, epoch);
  const header = await sealHeader(
    rid,
    { v: 1, suite: 'aes-256-gcm', epoch },
    { name: 'secret room', mode: 'link', ttl: 0, createdAt: 1, createdBy: 'A' },
    keys,
  );
  return { rid, keys, header, verifier: b64u(keys.authPub) };
}

function create(c: Conn, r: { rid: string; header: RoomHeaderWire; verifier: string }) {
  c.send({ t: 'create', rid: r.rid, verifier: r.verifier, header: r.header });
  return c.frames.findLast((f) => f.t === 'joined' || f.t === 'error')!;
}

function join(c: Conn, rid: string, keys: RoomKeys, epoch = 0) {
  c.send({ t: 'join', rid });
  const ch = c.last() as Frame<'challenge'>;
  expect(ch.t).toBe('challenge');
  const sig = proveMembership(keys.authPriv, rid, fromB64u(ch.nonce), epoch);
  c.send({ t: 'auth', rid, sig });
  return { reply: c.frames.findLast((f) => f.t === 'joined' || f.t === 'error')!, sig };
}

const blob = () => b64u(randomBytes(64));
const errCode = (f: ServerFrame) => (f.t === 'error' ? f.code : f.t);

describe('RelayCore', () => {
  it('greets new connections with limits', () => {
    const h = harness();
    const a = h.conn();
    expect(a.frames[0]).toMatchObject({ t: 'welcome', v: 1, limits: LIMITS });
  });

  it('create -> joined (with a session nonce); duplicate create -> exists', async () => {
    const h = harness();
    const a = h.conn();
    const r = await makeRoom();
    const j = create(a, r) as Frame<'joined'>;
    expect(j).toMatchObject({ t: 'joined', rid: r.rid, history: [], members: 1 });
    expect(fromB64u(j.nonce)).toHaveLength(32);
    expect(errCode(create(h.conn(), r))).toBe('exists');
  });

  it('rejects creating a room at a non-zero epoch', async () => {
    const h = harness();
    const r = await makeRoom(1);
    expect(errCode(create(h.conn(), r))).toBe('bad-frame');
  });

  it('join of an unknown room -> no-room', () => {
    const h = harness();
    const a = h.conn();
    a.send({ t: 'join', rid: newRoomId() });
    expect(errCode(a.last())).toBe('no-room');
  });

  it('admits a member proving the key; rejects a wrong key', async () => {
    const h = harness();
    const r = await makeRoom();
    create(h.conn(), r);
    expect(join(h.conn(), r.rid, r.keys).reply.t).toBe('joined');
    const eve = h.conn();
    const bad = join(eve, r.rid, deriveRoomKeys(newRoomSecret(), r.rid, 0));
    expect(errCode(bad.reply)).toBe('auth-failed');
    eve.send({ t: 'send', rid: r.rid, id: newRoomId(), blob: blob(), persist: true });
    expect(errCode(eve.last())).toBe('not-member');
  });

  it('challenge nonces are single-use', async () => {
    const h = harness();
    const r = await makeRoom();
    create(h.conn(), r);
    const b = h.conn();
    b.send({ t: 'join', rid: r.rid });
    const ch = b.last() as Frame<'challenge'>;
    const sig = proveMembership(r.keys.authPriv, r.rid, fromB64u(ch.nonce), 0);
    b.send({ t: 'auth', rid: r.rid, sig });
    expect(b.last().t).toBe('presence');
    const c = h.conn();
    c.send({ t: 'join', rid: r.rid });
    c.send({ t: 'auth', rid: r.rid, sig }); // replay of B's proof
    expect(errCode(c.last())).toBe('auth-failed');
    c.send({ t: 'auth', rid: r.rid, sig }); // and no second attempt on the same challenge
    expect(errCode(c.last())).toBe('auth-failed');
  });

  it('send before auth -> not-member', async () => {
    const h = harness();
    const r = await makeRoom();
    create(h.conn(), r);
    const b = h.conn();
    b.send({ t: 'join', rid: r.rid });
    b.send({ t: 'send', rid: r.rid, id: newRoomId(), blob: blob(), persist: true });
    expect(errCode(b.last())).toBe('not-member');
  });

  it('broadcasts to members; stores persistent messages only', async () => {
    const h = harness();
    const r = await makeRoom();
    const a = h.conn();
    create(a, r);
    const b = h.conn();
    join(b, r.rid, r.keys);
    const id1 = newRoomId();
    const id2 = newRoomId();
    a.send({ t: 'send', rid: r.rid, id: id1, blob: blob(), persist: true });
    a.send({ t: 'send', rid: r.rid, id: id2, blob: blob(), persist: false });
    expect(b.of('msg').map((m) => [m.id, m.persist])).toEqual([
      [id1, true],
      [id2, false],
    ]);
    expect(a.of('msg')).toHaveLength(2); // echo to sender acts as an ack
    expect(h.store.listMsgs(r.rid, h.clock.t).map((m) => m.id)).toEqual([id1]);
    const c = h.conn();
    const j = join(c, r.rid, r.keys).reply as Frame<'joined'>;
    expect(j.history.map((m) => m.id)).toEqual([id1]);
  });

  it('history excludes expired messages', async () => {
    const h = harness();
    const r = await makeRoom();
    const a = h.conn();
    create(a, r);
    const keep = newRoomId();
    a.send({ t: 'send', rid: r.rid, id: newRoomId(), blob: blob(), persist: true, exp: h.clock.t + 1000 });
    a.send({ t: 'send', rid: r.rid, id: keep, blob: blob(), persist: true });
    h.clock.t += 2000;
    const j = join(h.conn(), r.rid, r.keys).reply as Frame<'joined'>;
    expect(j.history.map((m) => m.id)).toEqual([keep]);
    h.relay.sweep();
    expect(h.store.dump()).not.toContain('"exp"');
  });

  it('caps stored messages per room, dropping the oldest', async () => {
    const h = harness();
    const r = await makeRoom();
    const a = h.conn();
    create(a, r);
    const ids: string[] = [];
    for (let i = 0; i < LIMITS.maxStoredPerRoom + 5; i++) {
      const id = newRoomId();
      ids.push(id);
      a.send({ t: 'send', rid: r.rid, id, blob: 'AAAA', persist: true });
    }
    const stored = h.store.listMsgs(r.rid, h.clock.t).map((m) => m.id);
    expect(stored).toHaveLength(LIMITS.maxStoredPerRoom);
    expect(stored[0]).toBe(ids[5]);
    expect(stored.at(-1)).toBe(ids.at(-1));
  });

  it.each([
    ['bad JSON', '{"t":'],
    ['not an object', '[1,2]'],
    ['unknown type', { t: 'hack' }],
    ['bad room id', { t: 'join', rid: 'x' }],
    ['non-boolean persist', { t: 'send', rid: newRoomId(), id: newRoomId(), blob: 'AAAA', persist: 'yes' }],
    ['non-base64 blob', { t: 'send', rid: newRoomId(), id: newRoomId(), blob: 'hello world!', persist: true }],
    ['oversized blob', { t: 'send', rid: newRoomId(), id: newRoomId(), blob: 'A'.repeat(LIMITS.maxBlobChars + 1), persist: true }],
    ['bad signature length', { t: 'auth', rid: newRoomId(), sig: 'AAAA' }],
  ])('malformed frame (%s) -> bad-frame', (_n, f) => {
    const h = harness();
    const a = h.conn();
    a.send(f);
    expect(errCode(a.last())).toBe('bad-frame');
  });

  it('oversized frames -> too-large', () => {
    const h = harness();
    const a = h.conn();
    a.send('x'.repeat(LIMITS.maxFrameBytes + 1));
    expect(errCode(a.last())).toBe('too-large');
  });

  describe('rekey', () => {
    async function setup() {
      const h = harness();
      const r = await makeRoom();
      const a = h.conn();
      const joined = create(a, r) as Frame<'joined'>;
      const b = h.conn();
      join(b, r.rid, r.keys);
      const next = await makeRoom(1, r.rid);
      const session = fromB64u(joined.nonce);
      return { h, r, a, b, next, session };
    }

    it('wrong epoch -> stale-epoch', async () => {
      const { r, a, session } = await setup();
      const skip = await makeRoom(2, r.rid);
      a.send({
        t: 'rekey',
        rid: r.rid,
        epoch: 2,
        verifier: skip.verifier,
        header: skip.header,
        sig: signRekey(r.keys.authPriv, r.rid, 2, skip.verifier, skip.header, session),
      });
      expect(errCode(a.last())).toBe('stale-epoch');
    });

    it('signature by a non-holder or for another session -> auth-failed', async () => {
      const { r, a, next, session } = await setup();
      const outsider = deriveRoomKeys(newRoomSecret(), r.rid, 0);
      a.send({ t: 'rekey', rid: r.rid, epoch: 1, verifier: next.verifier, header: next.header, sig: signRekey(outsider.authPriv, r.rid, 1, next.verifier, next.header, session) });
      expect(errCode(a.last())).toBe('auth-failed');
      a.send({ t: 'rekey', rid: r.rid, epoch: 1, verifier: next.verifier, header: next.header, sig: signRekey(r.keys.authPriv, r.rid, 1, next.verifier, next.header, randomBytes(32)) });
      expect(errCode(a.last())).toBe('auth-failed');
    });

    it('valid rekey de-authorises other members; the rotator stays in', async () => {
      const { h, r, a, b, next, session } = await setup();
      a.send({ t: 'rekey', rid: r.rid, epoch: 1, verifier: next.verifier, header: next.header, sig: signRekey(r.keys.authPriv, r.rid, 1, next.verifier, next.header, session) });
      expect(b.of('rekeyed')).toHaveLength(1);
      expect(b.of('rekeyed')[0]).toMatchObject({ epoch: 1, header: next.header });
      expect(a.of('rekeyed')).toHaveLength(1);
      b.send({ t: 'send', rid: r.rid, id: newRoomId(), blob: blob(), persist: true });
      expect(errCode(b.last())).toBe('not-member');
      a.send({ t: 'send', rid: r.rid, id: newRoomId(), blob: blob(), persist: true });
      expect(a.last().t).toBe('msg');
      // old key no longer admits; new key does
      expect(errCode(join(h.conn(), r.rid, r.keys, 0).reply)).toBe('auth-failed');
      expect(join(b, r.rid, next.keys, 1).reply.t).toBe('joined');
    });
  });

  it('sweep deletes idle rooms only when nobody is connected', async () => {
    const h = harness(10_000);
    const r = await makeRoom();
    const a = h.conn();
    create(a, r);
    h.clock.t += 20_000;
    h.relay.sweep();
    expect(h.store.getRoom(r.rid)).toBeDefined();
    a.close();
    h.relay.sweep();
    expect(h.store.getRoom(r.rid)).toBeUndefined();
    const b = h.conn();
    b.send({ t: 'join', rid: r.rid });
    expect(errCode(b.last())).toBe('no-room');
  });

  it('presence counts authenticated members', async () => {
    const h = harness();
    const r = await makeRoom();
    const a = h.conn();
    create(a, r);
    const b = h.conn();
    join(b, r.rid, r.keys);
    expect(a.of('presence').at(-1)?.members).toBe(2);
    b.send({ t: 'leave', rid: r.rid });
    expect(b.last().t).toBe('left');
    expect(a.of('presence').at(-1)?.members).toBe(1);
    expect(h.relay.memberCount(r.rid)).toBe(1);
  });

  it('files: null until complete, then chunks in index order', async () => {
    const h = harness();
    const r = await makeRoom();
    const a = h.conn();
    create(a, r);
    const fid = newRoomId();
    a.send({ t: 'chunk', rid: r.rid, fid, idx: 1, total: 2, blob: 'BBBB' });
    a.send({ t: 'getFile', rid: r.rid, fid });
    expect(a.last()).toMatchObject({ t: 'file', fid, chunks: null });
    a.send({ t: 'chunk', rid: r.rid, fid, idx: 0, total: 2, blob: 'AAAA' });
    a.send({ t: 'getFile', rid: r.rid, fid });
    expect(a.last()).toMatchObject({ t: 'file', fid, chunks: ['AAAA', 'BBBB'] });
    const out = h.conn();
    out.send({ t: 'getFile', rid: r.rid, fid });
    expect(errCode(out.last())).toBe('not-member');
  });

  it('logs never contain room ids, blobs or verifiers', async () => {
    const h = harness();
    const r = await makeRoom();
    const a = h.conn();
    create(a, r);
    join(h.conn(), r.rid, r.keys);
    join(h.conn(), r.rid, deriveRoomKeys(newRoomSecret(), r.rid, 0));
    const b = blob();
    a.send({ t: 'send', rid: r.rid, id: newRoomId(), blob: b, persist: true, exp: h.clock.t + 1 });
    h.clock.t += 10;
    h.relay.sweep();
    const all = h.logs.join('\n');
    expect(h.logs.length).toBeGreaterThanOrEqual(4);
    for (const s of [r.rid, b, r.verifier, r.header.box]) expect(all).not.toContain(s);
  });
});
