/**
 * How each mirror format is rendered (src/shared/mirrorFormats.ts has the
 * formats and their paths; docs/mirrors.md "Formats"). A mirror object is
 * rendered like the main link's answer to an app of that format: the body
 * the backend serves that app's User-Agent, edge-rendered for that client
 * family and finished with member-facing names. Pure.
 */
import { v } from 'convex/values';
import { sha256Hex } from './crypto';
import { capabilitiesOf } from './backends/capabilities';
import type { BackendId } from './backendIds';
import type { RenderClientFamily } from './edgeConfig';
import { classifyClient, type SubscriptionFormat } from './edges/clientFamilies';
import { MIRROR_FORMATS, type MirrorFormat } from '../../src/shared/mirrorFormats';

export { MIRROR_FORMATS, type MirrorFormat };

export const mirrorFormatValidator = v.union(
  v.literal('links'),
  v.literal('clash'),
  v.literal('singbox'),
);

/**
 * The User-Agent each format's body is fetched with. `links` sends none (the
 * backend's default, what every mirror held before). The others are an app of
 * that format the backend recognizes (lib/backends/remnawave.ts and
 * lib/appNotice.ts `PANEL_MIHOMO_UA`): a current Mihomo, never a legacy
 * Clash core (its template has no VLESS), and the official sing-box app in the
 * canonical form the main link rewrites the other shells to.
 */
export const MIRROR_FETCH_UA: Record<MirrorFormat, string | undefined> = {
  links: undefined,
  clash: 'mihomo/1.19.30',
  singbox: 'SFA/1.12.0 (sing-box 1.12.0)',
};

/** The client family a format is rendered for (the edge render's per-client rules). */
export function mirrorFamily(format: MirrorFormat): RenderClientFamily {
  const ua = MIRROR_FETCH_UA[format];
  return ua ? classifyClient(ua).family : 'other';
}

const FORMAT_OF: Record<SubscriptionFormat, MirrorFormat> = {
  links: 'links',
  'clash-yaml': 'clash',
  'singbox-json': 'singbox',
};

/** The mirror format an app reads, from its catalog name (the rules a User-Agent goes by). */
export function mirrorFormatOfApp(name: string): MirrorFormat {
  return FORMAT_OF[classifyClient(name).expectedFormat];
}

/**
 * The formats a key's mirror is kept in: one bare access key (an Outline key)
 * has no other format, so it keeps the one object; a subscription document
 * gets all three.
 */
export function mirrorFormatsFor(backend: BackendId): MirrorFormat[] {
  return capabilitiesOf(backend).accessKeyDelivery ? ['links'] : [...MIRROR_FORMATS];
}

/**
 * The one hash of a copy's objects: what the sync ledger compares (written,
 * served, read back). A copy of the `links` object alone hashes as that body,
 * as before formats, so every hash recorded before them still means what it
 * did; a copy of several hashes each object under its format, in format order.
 */
export async function mirrorSetHash(
  hashes: readonly { format: MirrorFormat; hash: string }[],
): Promise<string> {
  const ordered = MIRROR_FORMATS.flatMap((f) => hashes.filter((h) => h.format === f));
  if (ordered.length === 1 && ordered[0]!.format === 'links') return ordered[0]!.hash;
  return sha256Hex(`fcp-mirror-set/1\n${ordered.map((h) => `${h.format} ${h.hash}`).join('\n')}`);
}
