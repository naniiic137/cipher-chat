import { describe, expect, it } from 'vitest';
import {
  b64u,
  inviteFragment,
  inviteLink,
  KEYFILE_TYPE,
  newRoomId,
  newRoomSecret,
  parseInvite,
  QR_PREFIX,
  toKeyFile,
  toQrString,
  type RoomInvite,
} from '../src/index.ts';

const base = 'https://naniiic137.github.io/cipher-chat/';

function inv(over: Partial<RoomInvite> = {}): RoomInvite {
  return { rid: newRoomId(), key: newRoomSecret(), epoch: 0, mode: 'link', ...over };
}

describe('invite links', () => {
  it('round-trip, with the key only in the fragment', () => {
    const i = inv({ epoch: 3 });
    const link = inviteLink(base + '?utm=x#old', i);
    const [before, frag] = link.split('#');
    expect(before).toBe(base + '?utm=x');
    expect(before).not.toContain(b64u(i.key!));
    expect(frag).toContain(b64u(i.key!));
    const p = parseInvite(link);
    expect(p).toMatchObject({ rid: i.rid, epoch: 3, mode: 'link' });
    expect(b64u(p.key!)).toBe(b64u(i.key!));
  });

  it('accepts a bare fragment and preserves every mode code', () => {
    for (const mode of ['link', 'pk', 'keyfile'] as const) {
      const i = inv({ mode });
      expect(parseInvite(inviteFragment(i)).mode).toBe(mode);
      expect(parseInvite('#' + inviteFragment(i)).rid).toBe(i.rid);
    }
  });

  it('passphrase invites carry no key', () => {
    const i: RoomInvite = { rid: newRoomId(), epoch: 0, mode: 'passphrase' };
    const link = inviteLink(base, i);
    expect(link).not.toMatch(/[?&#]k=/);
    const p = parseInvite(link);
    expect(p.mode).toBe('passphrase');
    expect(p.key).toBeUndefined();
  });

  it('preserves the relay hint', () => {
    const i = inv({ relay: 'wss://relay.example.com/ws' });
    expect(parseInvite(inviteLink(base, i)).relay).toBe('wss://relay.example.com/ws');
  });
});

describe('key files', () => {
  it('JSON round trip with a warning and no room name', () => {
    const i = inv({ mode: 'keyfile', epoch: 2, relay: 'wss://r.example' });
    const kf = toKeyFile(i);
    expect(kf.type).toBe(KEYFILE_TYPE);
    expect(kf.warning).toMatch(/Anyone with this file/);
    const p = parseInvite(JSON.stringify(kf, null, 2));
    expect(p).toMatchObject({ rid: i.rid, epoch: 2, mode: 'keyfile', relay: 'wss://r.example' });
    expect(b64u(p.key!)).toBe(b64u(i.key!));
  });

  it('refuses to export without a key', () => {
    expect(() => toKeyFile({ rid: newRoomId(), epoch: 0, mode: 'passphrase' })).toThrow();
    expect(() => toQrString({ rid: newRoomId(), epoch: 0, mode: 'passphrase' })).toThrow();
  });
});

describe('QR strings', () => {
  it('round trip', () => {
    const i = inv({ mode: 'pk', epoch: 7 });
    const q = toQrString(i);
    expect(q.startsWith(QR_PREFIX)).toBe(true);
    const p = parseInvite('  ' + q + '\n');
    expect(p).toMatchObject({ rid: i.rid, epoch: 7, mode: 'pk' });
    expect(b64u(p.key!)).toBe(b64u(i.key!));
  });
});

describe('invalid input', () => {
  const rid = newRoomId();
  const key = b64u(newRoomSecret());
  it.each([
    ['garbage', 'hello world', /no room id/],
    ['bad JSON', '{not json', /not a valid key file/],
    ['wrong JSON type', JSON.stringify({ type: 'other', rid, key }), /not a CipherChat key file/],
    ['invalid room id', `#r=short&k=${key}`, /invalid room id/],
    ['short key', `#r=${rid}&k=${b64u(new Uint8Array(16))}`, /invalid key length/],
    ['link without key', `#r=${rid}&m=l`, /no key/],
    ['malformed QR', `${QR_PREFIX}${rid}.0`, /malformed QR/],
    ['negative epoch', `#r=${rid}&e=-1&k=${key}`, /invalid epoch/],
  ])('%s', (_name, input, err) => {
    expect(() => parseInvite(input)).toThrow(err);
  });
});
