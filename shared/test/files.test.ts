import { describe, expect, it } from 'vitest';
import { b64u, decryptFile, encryptFile, LIMITS, newRoomId, randomBytes, type SuiteId } from '../src/index.ts';

const rid = newRoomId();
const roomFileKey = randomBytes(32);
const suite: SuiteId = 'chacha20-poly1305';
const opts = { rid, suite, roomFileKey, epoch: 0 };
const meta = { name: 'plans.pdf', mime: 'application/pdf' };

describe('encrypted files', () => {
  it.each([0, 1, LIMITS.chunkBytes, LIMITS.chunkBytes + 1, 200_000])('round-trips %i bytes', async (n) => {
    const data = randomBytes(n);
    const { manifest, chunks } = await encryptFile(data, meta, opts);
    expect(manifest.size).toBe(n);
    expect(manifest.chunks).toBe(Math.max(1, Math.ceil(n / LIMITS.chunkBytes)));
    expect(chunks).toHaveLength(manifest.chunks);
    const out = await decryptFile(chunks, manifest, { rid, suite, roomFileKey });
    expect(b64u(out)).toBe(b64u(data));
  });

  it('all chunk blobs have identical length (length hiding)', async () => {
    const { chunks } = await encryptFile(randomBytes(LIMITS.chunkBytes * 2 + 17), meta, opts);
    expect(new Set(chunks.map((c) => c.length)).size).toBe(1);
    const tiny = await encryptFile(randomBytes(3), meta, opts);
    expect(tiny.chunks[0]!.length).toBe(chunks[0]!.length);
  });

  it('each file gets its own key: same data twice gives different chunks', async () => {
    const data = randomBytes(1000);
    const a = await encryptFile(data, meta, opts);
    const b = await encryptFile(data, meta, opts);
    expect(a.manifest.fid).not.toBe(b.manifest.fid);
    expect(a.manifest.secret).not.toBe(b.manifest.secret);
    expect(a.chunks[0]).not.toBe(b.chunks[0]);
    expect(a.manifest.sha256).toBe(b.manifest.sha256);
  });

  it('works with every suite', async () => {
    for (const s of ['aes-256-gcm', 'xchacha20-poly1305'] as const) {
      const data = randomBytes(70_000);
      const { manifest, chunks } = await encryptFile(data, meta, { ...opts, suite: s });
      expect(b64u(await decryptFile(chunks, manifest, { rid, suite: s, roomFileKey }))).toBe(b64u(data));
    }
  });

  describe('rejections', () => {
    const data = randomBytes(LIMITS.chunkBytes * 2 + 5);
    const ready = encryptFile(data, meta, opts);

    it('tampered chunk', async () => {
      const { manifest, chunks } = await ready;
      const c = chunks[1]!;
      const bad = [...chunks];
      bad[1] = c.slice(0, 100) + (c[100] === 'A' ? 'B' : 'A') + c.slice(101);
      await expect(decryptFile(bad, manifest, { rid, suite, roomFileKey })).rejects.toMatchObject({ code: 'auth-failed' });
    });

    it('swapped chunk order', async () => {
      const { manifest, chunks } = await ready;
      const swapped = [chunks[1]!, chunks[0]!, chunks[2]!];
      await expect(decryptFile(swapped, manifest, { rid, suite, roomFileKey })).rejects.toMatchObject({ code: 'auth-failed' });
    });

    it('chunk from another file', async () => {
      const { manifest, chunks } = await ready;
      const other = await encryptFile(randomBytes(LIMITS.chunkBytes * 2 + 5), meta, opts);
      const mixed = [chunks[0]!, other.chunks[1]!, chunks[2]!];
      await expect(decryptFile(mixed, manifest, { rid, suite, roomFileKey })).rejects.toMatchObject({ code: 'auth-failed' });
    });

    it('missing chunk', async () => {
      const { manifest, chunks } = await ready;
      await expect(decryptFile(chunks.slice(0, 2), manifest, { rid, suite, roomFileKey })).rejects.toMatchObject({ code: 'bad-format' });
    });

    it('wrong room file key', async () => {
      const { manifest, chunks } = await ready;
      await expect(decryptFile(chunks, manifest, { rid, suite, roomFileKey: randomBytes(32) })).rejects.toMatchObject({ code: 'auth-failed' });
    });

    it('wrong room id', async () => {
      const { manifest, chunks } = await ready;
      await expect(decryptFile(chunks, manifest, { rid: newRoomId(), suite, roomFileKey })).rejects.toMatchObject({ code: 'auth-failed' });
    });

    it('wrong per-file secret in the manifest', async () => {
      const { manifest, chunks } = await ready;
      await expect(
        decryptFile(chunks, { ...manifest, secret: b64u(randomBytes(32)) }, { rid, suite, roomFileKey }),
      ).rejects.toMatchObject({ code: 'auth-failed' });
    });

    it('manifest sha256 or size mismatch', async () => {
      const { manifest, chunks } = await ready;
      await expect(decryptFile(chunks, { ...manifest, sha256: '00'.repeat(32) }, { rid, suite, roomFileKey })).rejects.toMatchObject({
        code: 'auth-failed',
      });
      await expect(decryptFile(chunks, { ...manifest, size: manifest.size - 1 }, { rid, suite, roomFileKey })).rejects.toMatchObject({
        code: 'auth-failed',
      });
    });

    it('oversize files', async () => {
      await expect(encryptFile(new Uint8Array(LIMITS.maxFileBytes + 1), meta, opts)).rejects.toMatchObject({ code: 'too-large' });
    });
  });

  it('manifest truncates overlong names and defaults the MIME type', async () => {
    const { manifest } = await encryptFile(randomBytes(4), { name: 'x'.repeat(500), mime: '' }, opts);
    expect(manifest.name).toHaveLength(200);
    expect(manifest.mime).toBe('application/octet-stream');
  });
});
