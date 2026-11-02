import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import {
  checkSiteImage,
  decodeBase64,
  MAX_SITE_IMAGE_BYTES,
  sanitizeSiteImageRef,
  siteImageVersion,
  sniffImage,
} from './siteImage';

const poster = new Uint8Array(
  readFileSync(resolve(__dirname, '../../src/client/assets/home-poster.png')),
);

const bytes = (...parts: (number[] | string)[]) =>
  new Uint8Array(
    parts.flatMap((p) => (typeof p === 'string' ? [...p].map((c) => c.charCodeAt(0)) : p)),
  );
const le16 = (n: number) => [n & 0xff, (n >> 8) & 0xff];
const le24 = (n: number) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff];
const be16 = (n: number) => [(n >> 8) & 0xff, n & 0xff];
const riff = (chunk: string, body: number[]) =>
  bytes('RIFF', [0, 0, 0, 0], 'WEBP', chunk, [body.length, 0, 0, 0], body);

describe('sniffImage', () => {
  test('reads a PNG header (the built-in poster)', () => {
    expect(sniffImage(poster)).toEqual({ contentType: 'image/png', width: 1000, height: 1440 });
  });

  test('reads a JPEG frame header after other segments', () => {
    const jpeg = bytes(
      [0xff, 0xd8],
      [0xff, 0xe0, 0x00, 0x10],
      'JFIF',
      [0, 1, 1, 0, 0, 1, 0, 1, 0, 0],
      [0xff, 0xc2, 0x00, 0x11, 0x08],
      be16(900),
      be16(640),
      [3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1],
    );
    expect(sniffImage(jpeg)).toEqual({ contentType: 'image/jpeg', width: 640, height: 900 });
  });

  test('swaps the JPEG size when EXIF turns the picture a quarter', () => {
    // An APP1 Exif segment with one Orientation entry, in either byte order.
    const exif = (le: boolean, orientation: number) => {
      const w16 = (n: number) => (le ? le16(n) : be16(n));
      const w32 = (n: number) => (le ? [...le16(n), 0, 0] : [0, 0, ...be16(n)]);
      const body = [
        ...bytes('Exif', [0, 0], le ? 'II' : 'MM'),
        ...w16(42),
        ...w32(8),
        ...w16(1),
        ...[...w16(0x0112), ...w16(3), ...w32(1), ...w16(orientation), 0, 0],
        ...w32(0),
      ];
      return [0xff, 0xe1, ...be16(body.length + 2), ...body];
    };
    const jpeg = (app1: number[]) =>
      bytes(
        [0xff, 0xd8],
        app1,
        [0xff, 0xc0, 0x00, 0x11, 0x08],
        be16(3000), // stored height
        be16(4000), // stored width
        [3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1],
      );
    const size = (b: Uint8Array) => {
      const info = sniffImage(b);
      return info && [info.width, info.height];
    };
    expect(size(jpeg(exif(false, 6)))).toEqual([3000, 4000]);
    expect(size(jpeg(exif(true, 8)))).toEqual([3000, 4000]);
    // Upside down (3) or no flag at all keeps the stored size.
    expect(size(jpeg(exif(true, 3)))).toEqual([4000, 3000]);
    expect(size(jpeg([]))).toEqual([4000, 3000]);
  });

  test('refuses a JPEG that reaches image data before a frame header', () => {
    const jpeg = bytes([0xff, 0xd8], [0xff, 0xda, 0x00, 0x08], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect(sniffImage(jpeg)).toBeNull();
  });

  test('reads the three WebP flavours', () => {
    const lossy = riff('VP8 ', [0, 0, 0, 0x9d, 0x01, 0x2a, ...le16(640), ...le16(900), 0, 0]);
    const packed = 639 | (899 << 14);
    const lossless = riff('VP8L', [
      0x2f,
      ...[0, 8, 16, 24].map((s) => (packed >>> s) & 0xff),
      ...new Array<number>(8).fill(0), // the start of the image data
    ]);
    const extended = riff('VP8X', [0, 0, 0, 0, ...le24(639), ...le24(899)]);
    for (const webp of [lossy, lossless, extended]) {
      expect(sniffImage(webp)).toEqual({ contentType: 'image/webp', width: 640, height: 900 });
    }
  });

  test('refuses SVG, GIF and text', () => {
    expect(sniffImage(bytes('<svg xmlns="http://www.w3.org/2000/svg"></svg>'))).toBeNull();
    expect(sniffImage(bytes('GIF89a', [1, 0, 1, 0, 0, 0, 0]))).toBeNull();
    expect(sniffImage(bytes('hello there, not an image at all'))).toBeNull();
  });
});

describe('checkSiteImage', () => {
  test('passes the built-in poster', () => {
    expect(checkSiteImage(poster)).toEqual({
      ok: true,
      info: { contentType: 'image/png', width: 1000, height: 1440 },
    });
  });

  test('refuses empty, oversized, unknown and badly sized files', () => {
    const code = (b: Uint8Array) => {
      const r = checkSiteImage(b);
      return r.ok ? 'ok' : r.code;
    };
    expect(code(new Uint8Array())).toBe('site_image.empty');
    const big = new Uint8Array(MAX_SITE_IMAGE_BYTES + 1);
    big.set(poster.subarray(0, 64));
    expect(code(big)).toBe('site_image.too_large');
    expect(code(bytes('<svg></svg>'))).toBe('site_image.unsupported_type');
    const tiny = riff('VP8X', [0, 0, 0, 0, ...le24(31), ...le24(899)]);
    expect(code(tiny)).toBe('site_image.bad_dimensions');
    const huge = riff('VP8X', [0, 0, 0, 0, ...le24(9999), ...le24(899)]);
    expect(code(huge)).toBe('site_image.bad_dimensions');
  });
});

describe('decodeBase64', () => {
  test('round-trips and refuses anything but plain base64', () => {
    expect(Array.from(decodeBase64(btoa('\x00\x01\xff')) ?? [])).toEqual([0, 1, 255]);
    expect(decodeBase64('data:image/png;base64,AAAA')).toBeNull();
    expect(decodeBase64('AA AA')).toBeNull();
    expect(decodeBase64('AAA')).toBeNull();
  });
});

describe('sanitizeSiteImageRef', () => {
  test('keeps a well-formed reference and drops anything else', async () => {
    const version = await siteImageVersion(poster);
    expect(version).toMatch(/^[0-9a-f]{16}$/);
    const ref = { version, width: 1000, height: 1440 };
    expect(sanitizeSiteImageRef({ ...ref, extra: 1 })).toEqual(ref);
    expect(sanitizeSiteImageRef(undefined)).toBeNull();
    expect(sanitizeSiteImageRef({ ...ref, version: '../etc' })).toBeNull();
    expect(sanitizeSiteImageRef({ ...ref, width: 10.5 })).toBeNull();
    expect(sanitizeSiteImageRef({ ...ref, height: 0 })).toBeNull();
  });
});
