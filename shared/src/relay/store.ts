/**
 * Storage interface for the blind relay. Implementations only ever receive
 * ciphertext blobs, public headers and verifiers (Ed25519 public keys).
 */
import type { RoomHeaderWire, WireMsg } from '../protocol.ts';

export interface StoredRoom {
  rid: string;
  verifier: string;
  header: RoomHeaderWire;
  createdAt: number;
  lastActive: number;
}

export interface RelayStore {
  getRoom(rid: string): StoredRoom | undefined;
  putRoom(room: StoredRoom): void;
  deleteRoom(rid: string): void;
  listRooms(): StoredRoom[];
  addMsg(rid: string, msg: WireMsg, maxPerRoom: number): void;
  listMsgs(rid: string, now: number): WireMsg[];
  putChunk(rid: string, fid: string, idx: number, total: number, blob: string, exp: number | undefined): void;
  /** Ordered chunks, or null if the file is unknown/incomplete. */
  getChunks(rid: string, fid: string, now: number): string[] | null;
  countFiles(rid: string): number;
  /** Deletes expired messages/chunks. Returns number of items removed. */
  purgeExpired(now: number): number;
}

interface FileRec {
  total: number;
  exp: number | undefined;
  chunks: (string | undefined)[];
}

export class MemoryStore implements RelayStore {
  protected rooms = new Map<string, StoredRoom>();
  protected msgs = new Map<string, WireMsg[]>();
  protected files = new Map<string, Map<string, FileRec>>();

  getRoom(rid: string): StoredRoom | undefined {
    return this.rooms.get(rid);
  }
  putRoom(room: StoredRoom): void {
    this.rooms.set(room.rid, room);
  }
  deleteRoom(rid: string): void {
    this.rooms.delete(rid);
    this.msgs.delete(rid);
    this.files.delete(rid);
  }
  listRooms(): StoredRoom[] {
    return [...this.rooms.values()];
  }
  addMsg(rid: string, msg: WireMsg, maxPerRoom: number): void {
    const list = this.msgs.get(rid) ?? [];
    list.push(msg);
    while (list.length > maxPerRoom) list.shift();
    this.msgs.set(rid, list);
  }
  listMsgs(rid: string, now: number): WireMsg[] {
    return (this.msgs.get(rid) ?? []).filter((m) => m.exp === undefined || m.exp > now);
  }
  putChunk(rid: string, fid: string, idx: number, total: number, blob: string, exp: number | undefined): void {
    let room = this.files.get(rid);
    if (!room) this.files.set(rid, (room = new Map()));
    let rec = room.get(fid);
    if (!rec || rec.total !== total) room.set(fid, (rec = { total, exp, chunks: new Array(total) }));
    rec.chunks[idx] = blob;
  }
  getChunks(rid: string, fid: string, now: number): string[] | null {
    const rec = this.files.get(rid)?.get(fid);
    if (!rec || (rec.exp !== undefined && rec.exp <= now)) return null;
    // Note: Array#some skips holes in sparse arrays, so check every index explicitly.
    for (let i = 0; i < rec.total; i++) if (rec.chunks[i] === undefined) return null;
    return rec.chunks as string[];
  }
  countFiles(rid: string): number {
    return this.files.get(rid)?.size ?? 0;
  }
  purgeExpired(now: number): number {
    let n = 0;
    for (const [rid, list] of this.msgs) {
      const keep = list.filter((m) => m.exp === undefined || m.exp > now);
      n += list.length - keep.length;
      this.msgs.set(rid, keep);
    }
    for (const room of this.files.values()) {
      for (const [fid, rec] of room) {
        if (rec.exp !== undefined && rec.exp <= now) {
          room.delete(fid);
          n++;
        }
      }
    }
    return n;
  }

  /** Test/debug helper: everything this store holds, serialised. */
  dump(): string {
    return JSON.stringify({
      rooms: [...this.rooms.values()],
      msgs: Object.fromEntries(this.msgs),
      files: Object.fromEntries([...this.files].map(([k, v]) => [k, Object.fromEntries(v)])),
    });
  }

  /** Snapshot/restore (used by the in-browser demo relay to survive tab hand-over). */
  snapshot(): unknown {
    return JSON.parse(this.dump());
  }
  restore(snap: unknown): void {
    const s = snap as {
      rooms?: StoredRoom[];
      msgs?: Record<string, WireMsg[]>;
      files?: Record<string, Record<string, FileRec>>;
    };
    for (const r of s.rooms ?? []) this.rooms.set(r.rid, r);
    for (const [rid, list] of Object.entries(s.msgs ?? {})) this.msgs.set(rid, list);
    for (const [rid, files] of Object.entries(s.files ?? {})) {
      this.files.set(rid, new Map(Object.entries(files).map(([fid, rec]) => [fid, { ...rec, chunks: rec.chunks.map((c) => c ?? undefined) }])));
    }
  }
}
