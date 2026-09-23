import { SUITE_INFO, type KeyMode, type RoomState } from '@cipher-chat/shared';
import type { IconName } from './Icon.tsx';

export const MODE_INFO: Record<KeyMode, { label: string; short: string; icon: IconName; desc: string; best: string }> = {
  link: {
    label: 'Secret link',
    short: 'Secret link',
    icon: 'link',
    desc: 'A random 256-bit key lives in the invite link after the #. Browsers never send that part to any server.',
    best: 'Best for: quick group chats over a channel you already trust.',
  },
  passphrase: {
    label: 'Passphrase',
    short: 'Passphrase',
    icon: 'key',
    desc: 'Everyone types the same passphrase. Argon2id stretches it into a key, with a random per-room salt.',
    best: 'Best for: sharing the secret by voice or in person.',
  },
  pk: {
    label: '1:1 public key',
    short: '1:1 · Double Ratchet',
    icon: 'shieldCheck',
    desc: 'Identity keys + an X3DH handshake and a Double Ratchet: fresh keys for every message (forward secrecy).',
    best: 'Best for: private one-to-one conversations. Verify safety numbers.',
  },
  keyfile: {
    label: 'Key file / QR',
    short: 'Key file',
    icon: 'qr',
    desc: 'Export the room key as a file or a QR code generated on your device; import it by file, paste or photo.',
    best: 'Best for: moving a key between your own devices, or air-gapped sharing.',
  },
};

export function modeLabel(r: RoomState): string {
  if (r.mode === 'passphrase') return `Passphrase · ${r.pub.kdf?.alg === 'pbkdf2-sha256' ? 'PBKDF2' : 'Argon2id'}`;
  return MODE_INFO[r.mode].short;
}

export function suiteLabel(r: RoomState): string {
  return SUITE_INFO[r.suite].label;
}
