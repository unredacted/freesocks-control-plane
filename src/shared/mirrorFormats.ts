/**
 * The formats a subscription mirror is kept in (docs/mirrors.md "Formats").
 * The main link (`/api/v1/sub/<token>`) picks the body's format per request
 * from the app's User-Agent; a mirror is static objects in a bucket that
 * cannot, so it holds one object per format, at sibling paths of one random
 * id, and each app is handed the path in its own format:
 *
 *  - `links`: the share-link list (base64), at the bare path: what every
 *    mirror held before, so a link a member already added keeps its meaning;
 *  - `clash`: Clash / Mihomo YAML, at `<path>.yaml`;
 *  - `singbox`: sing-box JSON, at `<path>.json`.
 *
 * Shared by the server (what it writes, reads back and deletes) and the
 * member page (which link an app gets). The suffix says the format only;
 * nothing about the member or their country is in a path.
 */

export const MIRROR_FORMATS = ['links', 'clash', 'singbox'] as const;
export type MirrorFormat = (typeof MIRROR_FORMATS)[number];

const SUFFIX: Record<MirrorFormat, string> = { links: '', clash: '.yaml', singbox: '.json' };

export function isMirrorFormat(x: unknown): x is MirrorFormat {
  return typeof x === 'string' && (MIRROR_FORMATS as readonly string[]).includes(x);
}

/** A format's object path, or URL, from the mirror's own (the `links` one). */
export function mirrorFormatPath(base: string, format: MirrorFormat): string {
  return `${base}${SUFFIX[format]}`;
}

/** Every object path a mirror may have written (what removing it deletes). */
export function mirrorObjectPaths(base: string): string[] {
  return MIRROR_FORMATS.map((f) => mirrorFormatPath(base, f));
}

/**
 * The formats a mirror entry holds: a mirror from before the formats (no
 * list) holds the `links` object only.
 */
export function mirrorFormatsOf(entry: { formats?: readonly string[] | null }): MirrorFormat[] {
  const listed = (entry.formats ?? ['links']).filter(isMirrorFormat);
  return MIRROR_FORMATS.filter((f) => listed.includes(f));
}
