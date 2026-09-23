/**
 * End-to-end behaviour of CipherClient against the real relay logic (in memory).
 * The WebSocket version of these guarantees lives in server/test/integration.
 */
import { describe, expect, it } from 'vitest';
import {
  b64u,
  deriveRoomKeys,
  fromB64u,
  generateIdentity,
  newRoomId,
  parseInvite,
  inviteLink,
  toQrString,
  toKeyFile,
  sealEnvelope,
  SUITES,
  utf8,
  type KeyMode,
  type SuiteId,
} from '../src/index.ts';
import { makeClient, makeRelay, online, texts, waitFor } from './helpers.ts';

type ModeCase = { mode: KeyMode; kdf?: 'argon2id' | 'pbkdf2-sha256'; via: 'link' | 'keyfile' | 'qr' | 'passphrase' };
const MODES: ModeCase[] = [
  { mode: 'link', via: 'link' },
  { mode: 'passphrase', kdf: 'argon2id', via: 'passphrase' },
  { mode: 'passphrase', kdf: 'pbkdf2-sha256', via: 'passphrase' },
  { mode: 'keyfile', via: 'keyfile' },
  { mode: 'keyfile', via: 'qr' },
  { mode: 'pk', via: 'link' },
];
const PASS = 'velvet-orbit-cactus-lantern-42';

async function setupRoom(suite: SuiteId, mc: ModeCase, ttl = 0) {
  const { relay, store, inbound } = makeRelay();
  const alice = makeClient(relay, 'Alice');
  const bob = makeClient(relay, 'Bob');
  await online(alice.client, bob.client);
  const room = await alice.client.createRoom({
    name: 'Project Nightingale',
    mode: mc.mode,
    suite,
    ttl,
    ...(mc.mode === 'passphrase' ? { passphrase: PASS, kdf: mc.kdf! } : {}),
  });
  const rid = room.rid;
  let text: string;
  if (mc.via === 'keyfile') text = JSON.stringify(toKeyFile(alice.client.keyInvite(rid)));
  else if (mc.via === 'qr') text = toQrString(alice.client.keyInvite(rid));
  else text = inviteLink('https://example.test/cipher-chat/', alice.client.inviteFor(rid));
  const invite = parseInvite(text);
  await bob.client.joinRoom(invite, mc.via === 'passphrase' ? PASS : undefined);
  return { relay, store, inbound, alice, bob, rid };
}

describe.each(SUITES)('suite %s', (suite) => {
  it.each(MODES)('key mode $mode via $via: round trip, room name hidden from relay', async (mc) => {
    const { alice, bob, rid, inbound, store } = await setupRoom(suite, mc);
    expect(bob.client.rooms.get(rid)?.name).toBe('Project Nightingale');
    if (mc.mode === 'pk') {
      // 1:1: the joiner (initiator) speaks first, then the creator can reply.
      expect(alice.client.canSend(rid).ok).toBe(false);
      await bob.client.sendText(rid, 'hi Alice, X3DH here');
      await waitFor(() => texts(alice.client, rid).includes('hi Alice, X3DH here'));
      await alice.client.sendText(rid, 'ratchet reply');
      await waitFor(() => texts(bob.client, rid).includes('ratchet reply'));
      expect(alice.client.rooms.get(rid)!.messages.find((m) => m.text === 'hi Alice, X3DH here')?.ratchet).toBe(true);
    } else {
      await alice.client.sendText(rid, 'attack at dawn');
      await waitFor(() => texts(bob.client, rid).includes('attack at dawn'));
      await bob.client.sendText(rid, 'copy that');
      await waitFor(() => texts(alice.client, rid).includes('copy that'));
    }
    const everything = inbound.join('\n') + store.dump();
    // Only distinctive strings: a 3-letter name like "Bob" occurs by chance in ~50 KB of base64 ciphertext.
    for (const secret of ['Project Nightingale', 'attack at dawn', 'copy that', 'X3DH here', 'ratchet reply', PASS]) {
      expect(everything).not.toContain(secret);
    }
    // the room key itself never reaches the relay
    expect(everything).not.toContain(alice.client.rooms.get(rid)!.keys['0']!);
  });
});

describe('access control', () => {
  it('a wrong passphrase is rejected by the membership proof', async () => {
    const { relay } = makeRelay();
    const alice = makeClient(relay, 'Alice');
    const eve = makeClient(relay, 'Eve');
    await online(alice.client, eve.client);
    const room = await alice.client.createRoom({ name: 'r', mode: 'passphrase', suite: 'aes-256-gcm', ttl: 0, passphrase: PASS, kdf: 'pbkdf2-sha256' });
    await expect(eve.client.joinRoom({ rid: room.rid, epoch: 0, mode: 'passphrase' }, 'wrong passphrase')).rejects.toThrow(/rejected/);
  });

  it('a random key is rejected', async () => {
    const { relay } = makeRelay();
    const alice = makeClient(relay, 'Alice');
    const eve = makeClient(relay, 'Eve');
    await online(alice.client, eve.client);
    const room = await alice.client.createRoom({ name: 'r', mode: 'link', suite: 'aes-256-gcm', ttl: 0 });
    await expect(eve.client.joinRoom({ rid: room.rid, epoch: 0, mode: 'link', key: new Uint8Array(32).fill(7) })).rejects.toThrow();
    expect(eve.client.rooms.has(room.rid)).toBe(false);
  });

  it('refuses KDF parameters a malicious relay downgraded', async () => {
    const { relay } = makeRelay();
    const alice = makeClient(relay, 'Alice');
    const bob = makeClient(relay, 'Bob');
    await online(alice.client, bob.client);
    const room = await alice.client.createRoom({ name: 'r', mode: 'passphrase', suite: 'aes-256-gcm', ttl: 0, passphrase: PASS, kdf: 'pbkdf2-sha256' });
    bob.transport.intercept = (f) =>
      f.t === 'challenge' && f.pub.kdf?.alg === 'pbkdf2-sha256' ? { ...f, pub: { ...f.pub, kdf: { ...f.pub.kdf, iter: 1000 } } } : f;
    await expect(bob.client.joinRoom({ rid: room.rid, epoch: 0, mode: 'passphrase' }, PASS)).rejects.toThrow(/downgrade/);
  });
});

describe('integrity: tampering, forgery, replay', () => {
  it('flags a ciphertext tampered in transit (simulated malicious relay)', async () => {
    const { alice, bob, rid } = await setupRoom('chacha20-poly1305', MODES[0]!);
    bob.client.tamperNext = true;
    await alice.client.sendText(rid, 'you will never see this');
    await waitFor(() => bob.client.rooms.get(rid)!.messages.some((m) => m.kind === 'rejected'));
    const r = bob.client.rooms.get(rid)!.messages.find((m) => m.kind === 'rejected')!;
    expect(r.reason).toMatch(/AEAD authentication failed/);
    expect(texts(bob.client, rid)).not.toContain('you will never see this');
  });

  it('flags a message forged by an insider who holds the room key', async () => {
    const { alice, bob, rid } = await setupRoom('aes-256-gcm', MODES[0]!);
    // An insider (here: through Bob's authenticated connection) crafts a frame claiming to be Alice.
    const room = alice.client.rooms.get(rid)!;
    const keys = deriveRoomKeys(fromB64u(room.keys['0']!), rid, 0);
    const aliceId = alice.client.me;
    const evil = generateIdentity();
    const id = newRoomId();
    const blob = await sealEnvelope({
      rid,
      id,
      persist: true,
      suite: 'aes-256-gcm',
      keys,
      identity: { ...evil, edPub: fromB64u(aliceId.ed) },
      body: { k: 'text', text: 'wire the money to Mallory', c: 99, ts: Date.now(), n: 'Alice', x: aliceId.x },
    });
    // Send through Bob's own authenticated connection (any member could do this).
    (bob.transport as unknown as { send: (s: string) => void }).send(JSON.stringify({ t: 'send', rid, id, blob, persist: true }));
    await waitFor(() => alice.client.rooms.get(rid)!.messages.some((m) => m.kind === 'rejected'));
    expect(alice.client.rooms.get(rid)!.messages.find((m) => m.kind === 'rejected')!.reason).toMatch(/Forged/);
    expect(texts(alice.client, rid)).not.toContain('wire the money to Mallory');
  });

  it('blocks a relay replaying an old frame the client no longer holds', async () => {
    const { alice, bob, rid } = await setupRoom('xchacha20-poly1305', MODES[0]!);
    const captured: string[] = [];
    bob.transport.intercept = (f) => {
      if (f.t === 'msg' && f.persist) captured.push(JSON.stringify(f));
      return f;
    };
    await alice.client.sendText(rid, 'transfer approved');
    await waitFor(() => texts(bob.client, rid).includes('transfer approved'));
    // Bob deletes it locally; the relay then re-delivers the same frame.
    const r = bob.client.rooms.get(rid)!;
    r.messages = r.messages.filter((m) => m.text !== 'transfer approved');
    const frame = JSON.parse(captured[0]!);
    (bob.client as unknown as { onRaw: (s: string) => Promise<void> }).onRaw(JSON.stringify(frame));
    await waitFor(() => r.messages.some((m) => m.kind === 'system' && /replayed/.test(m.text ?? '')));
    expect(texts(bob.client, rid)).not.toContain('transfer approved');
  });

  it('warns when a known name appears with a different identity key', async () => {
    const { relay, alice, bob, rid } = await setupRoom('aes-256-gcm', MODES[0]!);
    await bob.client.sendText(rid, 'hello from the real Bob');
    await waitFor(() => texts(alice.client, rid).includes('hello from the real Bob'));
    const fakeBob = makeClient(relay, 'Bob');
    await online(fakeBob.client);
    await fakeBob.client.joinRoom(parseInvite(inviteLink('https://x.test/', alice.client.inviteFor(rid))));
    await fakeBob.client.sendText(rid, 'hello from the other Bob');
    await waitFor(() => texts(alice.client, rid).includes('hello from the other Bob'));
    expect(alice.client.rooms.get(rid)!.messages.some((m) => m.kind === 'system' && /safety number changed/.test(m.text ?? ''))).toBe(true);
  });
});

describe('room features', () => {
  it('encrypted typing indicators and read receipts', async () => {
    const { alice, bob, rid } = await setupRoom('aes-256-gcm', MODES[0]!);
    await alice.client.sendTyping(rid, true);
    await waitFor(() => (bob.client.typing.get(rid)?.size ?? 0) === 1);
    expect([...bob.client.typing.get(rid)!.keys()][0]).toBe(alice.client.me.ed);
    const id = await alice.client.sendText(rid, 'read me');
    await waitFor(() => texts(bob.client, rid).includes('read me'));
    await bob.client.markRead(rid);
    await waitFor(() => alice.client.rooms.get(rid)!.messages.find((m) => m.id === id)?.readBy?.includes(bob.client.me.ed) === true);
  });

  it('typing indicators and receipts are not stored by the relay', async () => {
    const { alice, bob, rid, store } = await setupRoom('aes-256-gcm', MODES[0]!);
    await alice.client.sendTyping(rid, true);
    await waitFor(() => (bob.client.typing.get(rid)?.size ?? 0) === 1);
    expect(store.listMsgs(rid, Date.now())).toHaveLength(0);
  });

  it('encrypted file sharing (multi-chunk) - relay never sees name or content', async () => {
    const { alice, bob, rid, store, inbound } = await setupRoom('xchacha20-poly1305', MODES[0]!);
    const data = new Uint8Array(150_000);
    for (let i = 0; i < data.length; i++) data[i] = (i * 31) & 0xff;
    data.set(utf8('TOP-SECRET-FILE-CONTENT'), 1000);
    await alice.client.sendFile(rid, data, 'nightingale-plans.pdf', 'application/pdf');
    await waitFor(() => bob.client.rooms.get(rid)!.messages.some((m) => m.kind === 'file'));
    const m = bob.client.rooms.get(rid)!.messages.find((x) => x.kind === 'file')!;
    expect(m.file!.name).toBe('nightingale-plans.pdf');
    expect(m.file!.chunks).toBe(3);
    const got = await bob.client.fetchFile(rid, m.file!);
    expect(b64u(got)).toBe(b64u(data));
    const everything = inbound.join('') + store.dump();
    expect(everything).not.toContain('nightingale-plans');
    expect(everything).not.toContain('TOP-SECRET-FILE-CONTENT');
  });

  it('files in 1:1 rooms travel inside the ratchet', async () => {
    const { alice, bob, rid } = await setupRoom('aes-256-gcm', MODES[5]!);
    await bob.client.sendFile(rid, utf8('hello file'), 'note.txt', 'text/plain');
    await waitFor(() => alice.client.rooms.get(rid)!.messages.some((m) => m.kind === 'file'));
    const m = alice.client.rooms.get(rid)!.messages.find((x) => x.kind === 'file')!;
    expect(m.ratchet).toBe(true);
    expect(new TextDecoder().decode(await alice.client.fetchFile(rid, m.file!))).toBe('hello file');
  });

  it('disappearing messages: clients drop them and the relay purges ciphertext', async () => {
    let t = Date.now();
    const now = () => t;
    const { relay, store } = makeRelay({ now });
    const alice = makeClient(relay, 'Alice', { now });
    const bob = makeClient(relay, 'Bob', { now });
    await online(alice.client, bob.client);
    const room = await alice.client.createRoom({ name: 'ephemeral', mode: 'link', suite: 'aes-256-gcm', ttl: 60 });
    await bob.client.joinRoom(alice.client.inviteFor(room.rid));
    await alice.client.sendText(room.rid, 'self-destructs in 60s');
    await waitFor(() => texts(bob.client, room.rid).includes('self-destructs in 60s'));
    expect(bob.client.rooms.get(room.rid)!.messages.find((m) => m.kind === 'text')!.exp).toBeGreaterThan(t);
    expect(store.listMsgs(room.rid, t)).toHaveLength(1);
    t += 61_000;
    expect(bob.client.sweepExpired()).toBeGreaterThan(0);
    alice.client.sweepExpired();
    expect(texts(bob.client, room.rid)).toHaveLength(0);
    relay.sweep();
    expect(store.dump()).not.toContain(room.rid + '","blob');
    expect(store.listMsgs(room.rid, t)).toHaveLength(0);
  });

  it('rejects messages whose signed expiry has passed even if the relay keeps them', async () => {
    let t = Date.now();
    const now = () => t;
    const { relay } = makeRelay();
    const alice = makeClient(relay, 'Alice', { now });
    await online(alice.client);
    const room = await alice.client.createRoom({ name: 'e', mode: 'link', suite: 'aes-256-gcm', ttl: 5 });
    await alice.client.sendText(room.rid, 'short-lived');
    t += 10_000;
    // a late joiner gets the (relay-retained) frame but must not display it
    const late = makeClient(relay, 'Late', { now });
    await online(late.client);
    await late.client.joinRoom(alice.client.inviteFor(room.rid));
    expect(texts(late.client, room.rid)).toHaveLength(0);
  });
});

describe('key rotation', () => {
  it('in-band rotation: members follow, history stays readable, old invites stop working', async () => {
    const { relay, alice, bob, rid } = await setupRoom('aes-256-gcm', MODES[0]!);
    const oldInvite = alice.client.inviteFor(rid);
    await alice.client.sendText(rid, 'before rotation');
    await waitFor(() => texts(bob.client, rid).includes('before rotation'));
    await alice.client.rotateKey(rid, { distribute: true });
    await waitFor(() => bob.client.rooms.get(rid)!.epoch === 1 && alice.client.rooms.get(rid)!.epoch === 1);
    await waitFor(() => bob.client.canSend(rid).ok);
    await bob.client.sendText(rid, 'after rotation');
    await waitFor(() => texts(alice.client, rid).includes('after rotation'));
    expect(texts(bob.client, rid)).toContain('before rotation');
    expect(Object.keys(bob.client.rooms.get(rid)!.keys).sort()).toEqual(['0', '1']);

    const carol = makeClient(relay, 'Carol');
    await online(carol.client);
    await expect(carol.client.joinRoom(oldInvite)).rejects.toThrow();
    // with the new invite Carol gets in, but epoch-0 history stays locked for her
    const dave = makeClient(relay, 'Dave');
    await online(dave.client);
    await dave.client.joinRoom(alice.client.inviteFor(rid));
    const dm = dave.client.rooms.get(rid)!.messages;
    expect(dm.some((m) => m.kind === 'locked')).toBe(true);
    expect(dm.some((m) => m.text === 'after rotation')).toBe(true);
    expect(dm.some((m) => m.text === 'before rotation')).toBe(false);
  });

  it('out-of-band rotation evicts members until they import the new key', async () => {
    const { alice, bob, rid } = await setupRoom('chacha20-poly1305', MODES[0]!);
    await alice.client.rotateKey(rid, { distribute: false });
    await waitFor(() => bob.client.rooms.get(rid)!.needsKey === true);
    expect(bob.client.canSend(rid).ok).toBe(false);
    await alice.client.sendText(rid, 'only for key holders');
    await new Promise((r) => setTimeout(r, 50));
    expect(texts(bob.client, rid)).not.toContain('only for key holders');
    await bob.client.joinRoom(alice.client.inviteFor(rid));
    expect(bob.client.rooms.get(rid)!.needsKey).toBeUndefined();
    expect(texts(bob.client, rid)).toContain('only for key holders');
  });

  it('rotation in a passphrase room uses a new passphrase and fresh salt', async () => {
    const { alice, bob, rid } = await setupRoom('aes-256-gcm', MODES[2]!);
    const salt0 = alice.client.rooms.get(rid)!.pub.kdf!.salt;
    await alice.client.rotateKey(rid, { distribute: true, passphrase: 'a-brand-new-passphrase-2026' });
    await waitFor(() => bob.client.rooms.get(rid)!.epoch === 1);
    expect(bob.client.rooms.get(rid)!.pub.kdf!.salt).not.toBe(salt0);
  });
});

describe('1:1 public-key rooms', () => {
  it('a third party holding the link cannot read the ratchet conversation', async () => {
    const { relay, alice, bob, rid } = await setupRoom('aes-256-gcm', MODES[5]!);
    const carol = makeClient(relay, 'Carol');
    await online(carol.client);
    await carol.client.joinRoom(alice.client.inviteFor(rid));
    await bob.client.sendText(rid, 'for Alice only');
    await waitFor(() => texts(alice.client, rid).includes('for Alice only'));
    await alice.client.sendText(rid, 'for Bob only');
    await waitFor(() => texts(bob.client, rid).includes('for Bob only'));
    await new Promise((r) => setTimeout(r, 30));
    expect(texts(carol.client, rid)).toHaveLength(0);
    // Carol's own handshake attempt is refused by Alice (session is bound to Bob)
    await carol.client.sendText(rid, 'let me in');
    await waitFor(() => alice.client.rooms.get(rid)!.messages.some((m) => m.kind === 'rejected'));
    expect(texts(alice.client, rid)).not.toContain('let me in');
  });
});
