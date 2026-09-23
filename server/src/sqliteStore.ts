/**
 * Optional SQLite persistence (Node's built-in `node:sqlite`, no native
 * add-ons). Only what the relay already sees is written: random room ids,
 * public headers, Ed25519 verifiers and opaque ciphertext. `secure_delete`
 * overwrites purged rows so disappearing messages do not linger in free pages.
 *
 * node:sqlite ships with Node >= 22.5. On 22.13+ it works without a flag
 * (it prints an ExperimentalWarning); on 22.5-22.12 start Node with
 * `--experimental-sqlite`. If it cannot be loaded, `openSqliteStore` returns
 * null and the server falls back to the in-memory store.
 */
import type { DatabaseSync } from 'node:sqlite';
import type { RelayStore, StoredRoom, WireMsg } from '@cipher-chat/shared';

type Row = Record<string, unknown>;

export class SqliteStore implements RelayStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`
      PRAGMA journal_mode = DELETE;
      PRAGMA secure_delete = ON;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS rooms (
        rid TEXT PRIMARY KEY,
        verifier TEXT NOT NULL,
        header TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_active INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS msgs (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        rid TEXT NOT NULL REFERENCES rooms(rid) ON DELETE CASCADE,
        id TEXT NOT NULL,
        blob TEXT NOT NULL,
        ts INTEGER NOT NULL,
        exp INTEGER
      );
      CREATE INDEX IF NOT EXISTS msgs_rid ON msgs(rid, seq);
      CREATE TABLE IF NOT EXISTS files (
        rid TEXT NOT NULL REFERENCES rooms(rid) ON DELETE CASCADE,
        fid TEXT NOT NULL,
        total INTEGER NOT NULL,
        exp INTEGER,
        PRIMARY KEY (rid, fid)
      );
      CREATE TABLE IF NOT EXISTS chunks (
        rid TEXT NOT NULL,
        fid TEXT NOT NULL,
        idx INTEGER NOT NULL,
        blob TEXT NOT NULL,
        PRIMARY KEY (rid, fid, idx),
        FOREIGN KEY (rid, fid) REFERENCES files(rid, fid) ON DELETE CASCADE
      );
    `);
  }

  private toRoom(r: Row): StoredRoom {
    return {
      rid: String(r.rid),
      verifier: String(r.verifier),
      header: JSON.parse(String(r.header)) as StoredRoom['header'],
      createdAt: Number(r.created_at),
      lastActive: Number(r.last_active),
    };
  }

  getRoom(rid: string): StoredRoom | undefined {
    const r = this.db.prepare('SELECT * FROM rooms WHERE rid = ?').get(rid);
    return r ? this.toRoom(r) : undefined;
  }

  putRoom(room: StoredRoom): void {
    this.db
      .prepare(
        `INSERT INTO rooms (rid, verifier, header, created_at, last_active) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(rid) DO UPDATE SET verifier = excluded.verifier, header = excluded.header,
           last_active = excluded.last_active`,
      )
      .run(room.rid, room.verifier, JSON.stringify(room.header), room.createdAt, room.lastActive);
  }

  deleteRoom(rid: string): void {
    this.db.prepare('DELETE FROM rooms WHERE rid = ?').run(rid);
  }

  listRooms(): StoredRoom[] {
    return this.db.prepare('SELECT * FROM rooms').all().map((r) => this.toRoom(r));
  }

  addMsg(rid: string, msg: WireMsg, maxPerRoom: number): void {
    this.db.prepare('INSERT INTO msgs (rid, id, blob, ts, exp) VALUES (?, ?, ?, ?, ?)').run(rid, msg.id, msg.blob, msg.ts, msg.exp ?? null);
    this.db
      .prepare(
        `DELETE FROM msgs WHERE rid = ? AND seq NOT IN
           (SELECT seq FROM msgs WHERE rid = ? ORDER BY seq DESC LIMIT ?)`,
      )
      .run(rid, rid, maxPerRoom);
  }

  listMsgs(rid: string, now: number): WireMsg[] {
    return this.db
      .prepare('SELECT id, blob, ts, exp FROM msgs WHERE rid = ? AND (exp IS NULL OR exp > ?) ORDER BY seq')
      .all(rid, now)
      .map((r) => ({
        id: String(r.id),
        blob: String(r.blob),
        ts: Number(r.ts),
        ...(r.exp !== null && r.exp !== undefined ? { exp: Number(r.exp) } : {}),
      }));
  }

  putChunk(rid: string, fid: string, idx: number, total: number, blob: string, exp: number | undefined): void {
    const f = this.db.prepare('SELECT total FROM files WHERE rid = ? AND fid = ?').get(rid, fid);
    if (!f || Number(f.total) !== total) {
      this.db.prepare('DELETE FROM files WHERE rid = ? AND fid = ?').run(rid, fid);
      this.db.prepare('INSERT INTO files (rid, fid, total, exp) VALUES (?, ?, ?, ?)').run(rid, fid, total, exp ?? null);
    }
    this.db
      .prepare('INSERT INTO chunks (rid, fid, idx, blob) VALUES (?, ?, ?, ?) ON CONFLICT(rid, fid, idx) DO UPDATE SET blob = excluded.blob')
      .run(rid, fid, idx, blob);
  }

  getChunks(rid: string, fid: string, now: number): string[] | null {
    const f = this.db.prepare('SELECT total, exp FROM files WHERE rid = ? AND fid = ?').get(rid, fid);
    if (!f) return null;
    if (f.exp !== null && f.exp !== undefined && Number(f.exp) <= now) return null;
    const rows = this.db.prepare('SELECT blob FROM chunks WHERE rid = ? AND fid = ? ORDER BY idx').all(rid, fid);
    if (rows.length !== Number(f.total)) return null;
    return rows.map((r) => String(r.blob));
  }

  countFiles(rid: string): number {
    const r = this.db.prepare('SELECT COUNT(*) AS n FROM files WHERE rid = ?').get(rid);
    return Number(r?.n ?? 0);
  }

  purgeExpired(now: number): number {
    const a = this.db.prepare('DELETE FROM msgs WHERE exp IS NOT NULL AND exp <= ?').run(now);
    const b = this.db.prepare('DELETE FROM files WHERE exp IS NOT NULL AND exp <= ?').run(now);
    return Number(a.changes) + Number(b.changes);
  }

  /** Debug/test helper: everything stored, serialised. */
  dump(): string {
    return JSON.stringify({
      rooms: this.db.prepare('SELECT * FROM rooms').all(),
      msgs: this.db.prepare('SELECT * FROM msgs').all(),
      files: this.db.prepare('SELECT * FROM files').all(),
      chunks: this.db.prepare('SELECT * FROM chunks').all(),
    });
  }

  close(): void {
    this.db.close();
  }
}

/** Opens (or creates) a SQLite store. Returns null if node:sqlite is unavailable. */
export async function openSqliteStore(path: string): Promise<SqliteStore | null> {
  let mod: typeof import('node:sqlite');
  try {
    mod = await import('node:sqlite');
  } catch {
    return null;
  }
  return new SqliteStore(new mod.DatabaseSync(path));
}
