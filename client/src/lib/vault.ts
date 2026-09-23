/**
 * Local key storage. Everything this device knows (identity keys, room keys,
 * ratchet sessions, message history) lives in ONE IndexedDB record. It can be
 * wrapped with a device passphrase: Argon2id -> AES-256-GCM. The key used to
 * re-wrap on save is held in memory only while the app is unlocked.
 */
import {
  b64u,
  fromB64u,
  fromUtf8,
  identityFromJSON,
  identityToJSON,
  newKdfParams,
  openPacked,
  passphraseToRoomSecret,
  sealPacked,
  utf8,
  generateIdentity,
  type ClientSnapshot,
  type Identity,
  type IdentityJSON,
  type KdfParams,
} from '@cipher-chat/shared';

const STORE = 'kv';
const KEY = 'vault';
const AAD = utf8('cipherchat/v1/vault');

export interface Settings {
  /** 'demo' = BroadcastChannel relay in this browser; otherwise a ws(s):// URL */
  relay: string;
}

export interface VaultData {
  v: 1;
  identity: IdentityJSON;
  name: string;
  snapshot: ClientSnapshot;
  settings: Settings;
  createdAt: number;
}

type Stored = { v: 1; plain: VaultData } | { v: 1; wrapped: { kdf: KdfParams; box: string } };

function idb(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB unavailable'));
  });
}

async function get(name: string): Promise<Stored | undefined> {
  const db = await idb(name);
  return new Promise((resolve, reject) => {
    const r = db.transaction(STORE, 'readonly').objectStore(STORE).get(KEY);
    r.onsuccess = () => {
      resolve(r.result as Stored | undefined);
      db.close();
    };
    r.onerror = () => reject(r.error);
  });
}

async function put(name: string, v: Stored): Promise<void> {
  const db = await idb(name);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(v, KEY);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}

export class Vault {
  constructor(public readonly db = 'cipherchat') {}

  private wrapKey: Uint8Array | null = null;
  private kdf: KdfParams | null = null;
  data: VaultData | null = null;

  get locked(): boolean {
    return this.data === null;
  }

  get protectedByPassphrase(): boolean {
    return this.kdf !== null;
  }

  /** 'new' (first run), 'locked' (needs passphrase) or 'ready'. */
  async load(): Promise<'new' | 'locked' | 'ready'> {
    const s = await get(this.db);
    if (!s) return 'new';
    if ('plain' in s) {
      this.data = s.plain;
      return 'ready';
    }
    this.kdf = s.wrapped.kdf;
    return 'locked';
  }

  async unlock(passphrase: string): Promise<void> {
    const s = await get(this.db);
    if (!s || !('wrapped' in s)) throw new Error('vault is not locked');
    const key = await passphraseToRoomSecret(passphrase, s.wrapped.kdf);
    try {
      const pt = await openPacked('aes-256-gcm', key, fromB64u(s.wrapped.box), AAD);
      this.data = JSON.parse(fromUtf8(pt)) as VaultData;
      this.wrapKey = key;
      this.kdf = s.wrapped.kdf;
    } catch {
      throw new Error('Wrong device passphrase');
    }
  }

  create(name: string, settings: Settings): { identity: Identity } {
    const identity = generateIdentity();
    this.data = {
      v: 1,
      identity: identityToJSON(identity),
      name,
      snapshot: { rooms: [], contacts: {} },
      settings,
      createdAt: Date.now(),
    };
    return { identity };
  }

  identity(): Identity {
    if (!this.data) throw new Error('locked');
    return identityFromJSON(this.data.identity);
  }

  async save(): Promise<void> {
    if (!this.data) return;
    if (this.wrapKey && this.kdf) {
      const box = await sealPacked('aes-256-gcm', this.wrapKey, utf8(JSON.stringify(this.data)), AAD);
      await put(this.db, { v: 1, wrapped: { kdf: this.kdf, box: b64u(box) } });
    } else {
      await put(this.db, { v: 1, plain: this.data });
    }
  }

  /** Wrap (or re-wrap) the vault with a device passphrase; null removes protection. */
  async setPassphrase(passphrase: string | null): Promise<void> {
    if (!passphrase) {
      this.wrapKey = null;
      this.kdf = null;
    } else {
      this.kdf = newKdfParams('argon2id');
      this.wrapKey = await passphraseToRoomSecret(passphrase, this.kdf);
    }
    await this.save();
  }

  lock(): void {
    this.wrapKey?.fill(0);
    this.wrapKey = null;
    this.data = null;
  }

  /** Destroys every key and message on this device. */
  async wipe(): Promise<void> {
    await new Promise<void>((resolve) => {
      const r = indexedDB.deleteDatabase(this.db);
      r.onsuccess = r.onerror = r.onblocked = () => resolve();
    });
    try {
      // The demo relay's ciphertext store is shared "server" state - leave it alone.
      for (const k of Object.keys(localStorage)) if (k.startsWith('cipherchat') && !k.startsWith('cipherchat-demo-relay')) localStorage.removeItem(k);
      sessionStorage.clear();
    } catch {
      /* storage may be unavailable */
    }
  }
}
