/**
 * Moving room keys between devices/people:
 *  - invite links carry the key in the URL *fragment* (#...), which browsers
 *    never send to any server;
 *  - key files are small JSON documents;
 *  - QR codes carry a compact "cck1:" string (generated locally, no CDN).
 */
import { b64u, fromB64u, randomBytes, type Bytes } from './encoding.ts';
import { isId, type KeyMode } from './protocol.ts';

export interface RoomInvite {
  rid: string;
  /** room secret for this epoch (absent for passphrase invites) */
  key?: Bytes;
  epoch: number;
  mode: KeyMode;
  /** optional relay URL hint (e.g. wss://relay.example) */
  relay?: string;
}

export function newRoomId(): string {
  return b64u(randomBytes(16));
}

export function newRoomSecret(): Bytes {
  return randomBytes(32);
}

const MODE_CODE: Record<KeyMode, string> = { link: 'l', passphrase: 'p', pk: 'x', keyfile: 'f' };
const CODE_MODE: Record<string, KeyMode> = { l: 'link', p: 'passphrase', x: 'pk', f: 'keyfile' };

/** Fragment part only, e.g. "r=...&e=0&m=l&k=..." */
export function inviteFragment(inv: RoomInvite): string {
  const p = new URLSearchParams();
  p.set('r', inv.rid);
  p.set('e', String(inv.epoch));
  p.set('m', MODE_CODE[inv.mode]);
  if (inv.key) p.set('k', b64u(inv.key));
  if (inv.relay) p.set('s', inv.relay);
  return p.toString();
}

export function inviteLink(base: string, inv: RoomInvite): string {
  return `${base.split('#')[0]}#${inviteFragment(inv)}`;
}

export const KEYFILE_TYPE = 'cipherchat-room-key';
export const QR_PREFIX = 'cck1:';

export interface KeyFileJSON {
  type: typeof KEYFILE_TYPE;
  v: 1;
  rid: string;
  epoch: number;
  mode: KeyMode;
  key: string;
  relay?: string;
  warning: string;
}

export function toKeyFile(inv: RoomInvite): KeyFileJSON {
  if (!inv.key) throw new Error('no key to export');
  return {
    type: KEYFILE_TYPE,
    v: 1,
    rid: inv.rid,
    epoch: inv.epoch,
    mode: inv.mode,
    key: b64u(inv.key),
    ...(inv.relay ? { relay: inv.relay } : {}),
    warning: 'Anyone with this file can read the room. Share it only over a channel you trust.',
  };
}

export function toQrString(inv: RoomInvite): string {
  if (!inv.key) throw new Error('no key to export');
  return `${QR_PREFIX}${inv.rid}.${inv.epoch}.${MODE_CODE[inv.mode]}.${b64u(inv.key)}`;
}

function valid(inv: RoomInvite): RoomInvite {
  if (!isId(inv.rid)) throw new Error('invalid room id');
  if (!Number.isInteger(inv.epoch) || inv.epoch < 0) throw new Error('invalid epoch');
  if (inv.key && inv.key.length !== 32) throw new Error('invalid key length');
  if (!inv.key && inv.mode !== 'passphrase') throw new Error('this invite has no key');
  return inv;
}

/**
 * Accepts anything a user might paste: an invite URL, a bare fragment, key
 * file JSON, or a QR string. Throws a readable error otherwise.
 */
export function parseInvite(input: string): RoomInvite {
  const s = input.trim();
  if (s.startsWith('{')) {
    let j: Partial<KeyFileJSON>;
    try {
      j = JSON.parse(s) as Partial<KeyFileJSON>;
    } catch {
      throw new Error('not a valid key file');
    }
    if (j.type !== KEYFILE_TYPE || typeof j.key !== 'string' || typeof j.rid !== 'string') {
      throw new Error('not a CipherChat key file');
    }
    return valid({
      rid: j.rid,
      epoch: Number(j.epoch ?? 0),
      mode: (j.mode as KeyMode) ?? 'keyfile',
      key: fromB64u(j.key),
      ...(j.relay ? { relay: j.relay } : {}),
    });
  }
  if (s.startsWith(QR_PREFIX)) {
    const [rid, epoch, m, key] = s.slice(QR_PREFIX.length).split('.');
    if (!rid || !epoch || !m || !key) throw new Error('malformed QR payload');
    return valid({ rid, epoch: Number(epoch), mode: CODE_MODE[m] ?? 'keyfile', key: fromB64u(key) });
  }
  const frag = s.includes('#') ? s.slice(s.indexOf('#') + 1) : s;
  const p = new URLSearchParams(frag.replace(/^\/?(join)?\??/, ''));
  const rid = p.get('r');
  if (!rid) throw new Error('no room id found - paste the full invite link, key file or QR text');
  const k = p.get('k');
  const relay = p.get('s');
  return valid({
    rid,
    epoch: Number(p.get('e') ?? 0),
    mode: CODE_MODE[p.get('m') ?? 'l'] ?? 'link',
    ...(k ? { key: fromB64u(k) } : {}),
    ...(relay ? { relay } : {}),
  });
}
