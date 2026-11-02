/**
 * The home page image: a picture an admin uploads to replace the built-in one
 * (src/client/assets/home-poster.png) next to the hero headline. The bytes live
 * in the `siteImages` table, inside the Postgres datastore, so the regular
 * database backups carry them (Convex's own file storage sits outside those
 * dumps). A small `site.homeImage` appSettings row holds what /api/v1/config
 * needs to point at it: a content version and the pixel size, so the page can
 * reserve the space before the image arrives. One mutation writes both.
 *
 * The server reads the format and size from the bytes themselves instead of
 * trusting a declared type. Only PNG, JPEG and WebP pass; SVG never does
 * (served from this origin, an SVG opened directly could run script).
 */

export const HOME_IMAGE_SLOT = 'homeImage';
export const HOME_IMAGE_SETTING_KEY = 'site.homeImage';

/** Upload cap: well under Convex's 1 MiB document limit, and a sane weight for
 *  the most-visited page on slow, filtered connections. */
export const MAX_SITE_IMAGE_BYTES = 512 * 1024;
export const MIN_SITE_IMAGE_SIDE = 64;
export const MAX_SITE_IMAGE_SIDE = 4096;

export type SiteImageType = 'image/png' | 'image/jpeg' | 'image/webp';

export interface SiteImageInfo {
  contentType: SiteImageType;
  width: number;
  height: number;
}

/** What the public config carries about an uploaded image. */
export interface SiteImageRef {
  /** First 16 hex chars of the bytes' SHA-256: changes with every new upload,
   *  so the image URL can be cached for good. */
  version: string;
  width: number;
  height: number;
}

const u16be = (b: Uint8Array, i: number) => ((b[i] ?? 0) << 8) | (b[i + 1] ?? 0);
const u16le = (b: Uint8Array, i: number) => (b[i] ?? 0) | ((b[i + 1] ?? 0) << 8);
const u24le = (b: Uint8Array, i: number) => u16le(b, i) | ((b[i + 2] ?? 0) << 16);
const u32be = (b: Uint8Array, i: number) => u16be(b, i) * 0x10000 + u16be(b, i + 2);
const ascii = (b: Uint8Array, i: number, n: number) => String.fromCharCode(...b.subarray(i, i + n));

function sniffPng(b: Uint8Array): SiteImageInfo | null {
  const SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (b.length < 24 || SIG.some((v, i) => b[i] !== v)) return null;
  // The first chunk is always IHDR: width and height, big-endian.
  if (ascii(b, 12, 4) !== 'IHDR') return null;
  return { contentType: 'image/png', width: u32be(b, 16), height: u32be(b, 20) };
}

// Start-of-frame markers carry the frame size (C4, C8 and CC are other tables).
const JPEG_SOF = new Set([
  0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
]);

function sniffJpeg(b: Uint8Array): SiteImageInfo | null {
  if (b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) return null;
  let i = 2;
  while (i + 9 < b.length) {
    if (b[i] !== 0xff) return null;
    // Markers may be padded with extra 0xFF bytes.
    while (b[i] === 0xff && i < b.length) i++;
    const marker = b[i] ?? 0;
    if (JPEG_SOF.has(marker)) {
      return { contentType: 'image/jpeg', height: u16be(b, i + 4), width: u16be(b, i + 6) };
    }
    // Image data or the end before any frame header: not a usable file.
    if (marker === 0xda || marker === 0xd9) return null;
    const len = u16be(b, i + 1);
    if (len < 2) return null;
    i += 1 + len;
  }
  return null;
}

function sniffWebp(b: Uint8Array): SiteImageInfo | null {
  if (b.length < 30 || ascii(b, 0, 4) !== 'RIFF' || ascii(b, 8, 4) !== 'WEBP') return null;
  const chunk = ascii(b, 12, 4);
  if (chunk === 'VP8 ') {
    // Lossy: a 3-byte frame tag, the 9D 01 2A start code, then 14-bit sizes.
    if (b[23] !== 0x9d || b[24] !== 0x01 || b[25] !== 0x2a) return null;
    return {
      contentType: 'image/webp',
      width: u16le(b, 26) & 0x3fff,
      height: u16le(b, 28) & 0x3fff,
    };
  }
  if (chunk === 'VP8L') {
    // Lossless: a 0x2F signature, then 14-bit width-1 and height-1, packed.
    if (b[20] !== 0x2f) return null;
    const b1 = b[21] ?? 0;
    const b2 = b[22] ?? 0;
    const b3 = b[23] ?? 0;
    const b4 = b[24] ?? 0;
    return {
      contentType: 'image/webp',
      width: 1 + (((b2 & 0x3f) << 8) | b1),
      height: 1 + (((b4 & 0x0f) << 10) | (b3 << 2) | ((b2 & 0xc0) >> 6)),
    };
  }
  if (chunk === 'VP8X') {
    // Extended: 24-bit canvas width-1 and height-1.
    return { contentType: 'image/webp', width: 1 + u24le(b, 24), height: 1 + u24le(b, 27) };
  }
  return null;
}

/** The format and pixel size read from the file's own header, or null when it
 *  is none of the accepted formats. */
export function sniffImage(bytes: Uint8Array): SiteImageInfo | null {
  return sniffPng(bytes) ?? sniffJpeg(bytes) ?? sniffWebp(bytes);
}

export type SiteImageCheck =
  | { ok: true; info: SiteImageInfo }
  | { ok: false; code: string; message: string };

/** Everything an upload must pass before it is stored. */
export function checkSiteImage(bytes: Uint8Array): SiteImageCheck {
  if (bytes.length === 0) {
    return { ok: false, code: 'site_image.empty', message: 'No image was sent.' };
  }
  if (bytes.length > MAX_SITE_IMAGE_BYTES) {
    return {
      ok: false,
      code: 'site_image.too_large',
      message: `Images can be at most ${MAX_SITE_IMAGE_BYTES / 1024} KB.`,
    };
  }
  const info = sniffImage(bytes);
  if (!info) {
    return {
      ok: false,
      code: 'site_image.unsupported_type',
      message: 'Use a PNG, JPEG or WebP image.',
    };
  }
  const side = (n: number) => n >= MIN_SITE_IMAGE_SIDE && n <= MAX_SITE_IMAGE_SIDE;
  if (!side(info.width) || !side(info.height)) {
    return {
      ok: false,
      code: 'site_image.bad_dimensions',
      message: `Each side must be between ${MIN_SITE_IMAGE_SIDE} and ${MAX_SITE_IMAGE_SIDE} pixels.`,
    };
  }
  return { ok: true, info };
}

/** Strict base64 (no data: prefix, no whitespace) to bytes; null when malformed. */
export function decodeBase64(s: string): Uint8Array<ArrayBuffer> | null {
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export async function siteImageVersion(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest.subarray(0, 8), (x) => x.toString(16).padStart(2, '0')).join('');
}

const VERSION_RE = /^[0-9a-f]{16}$/;

/** The stored `site.homeImage` value, checked; null when unset or malformed. */
export function sanitizeSiteImageRef(v: unknown): SiteImageRef | null {
  if (typeof v !== 'object' || v === null) return null;
  const { version, width, height } = v as Record<string, unknown>;
  const side = (n: unknown): n is number =>
    typeof n === 'number' &&
    Number.isInteger(n) &&
    n >= MIN_SITE_IMAGE_SIDE &&
    n <= MAX_SITE_IMAGE_SIDE;
  if (typeof version !== 'string' || !VERSION_RE.test(version)) return null;
  if (!side(width) || !side(height)) return null;
  return { version, width, height };
}
