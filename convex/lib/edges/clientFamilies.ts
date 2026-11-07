/**
 * Classify a subscription fetch's User-Agent into a client FAMILY (the unit the
 * admin's per-client render rules key on) and the subscription FORMAT the backend
 * serves it (which decides which renderer applies). Conservative: unknown UAs
 * are `other` + `links`, and the renderer confirms the format from the body.
 */
import { RENDER_CLIENT_FAMILIES, type RenderClientFamily } from '../edgeConfig';
import { formatSupported, type ListenerProto, type RenderFormat } from './protocols';

export type SubscriptionFormat = 'links' | 'singbox-json' | 'clash-yaml';

export interface ClientClassification {
  family: RenderClientFamily;
  /** The format this family USUALLY receives; the body decides in the end. */
  expectedFormat: SubscriptionFormat;
}

const RULES: Array<{ re: RegExp; family: RenderClientFamily; format: SubscriptionFormat }> = [
  // Auto-capable clients first. Keep the official-shell prefix list in step
  // with SINGBOX_*_UA_RE in lib/backends/remnawave.ts (the sub-fetch rewrite):
  // a shell the backend is served sing-box JSON for must classify as `singbox`.
  { re: /^(?:SFA|SFI|SFM|SFT|SFL|SFW)\//i, family: 'singbox', format: 'singbox-json' },
  { re: /sing-?box/i, family: 'singbox', format: 'singbox-json' },
  { re: /karing/i, family: 'singbox', format: 'singbox-json' },
  {
    re: /(?:mihomo|clash[.-]?meta|clash[- ]?verge|flclash|clashx|stash|clash)/i,
    family: 'mihomo',
    format: 'clash-yaml',
  },
  // Link-list clients with their own quirks.
  { re: /happ/i, family: 'happ', format: 'links' },
  { re: /hiddify/i, family: 'hiddify', format: 'links' },
  { re: /streisand/i, family: 'streisand', format: 'links' },
  { re: /v2rayng/i, family: 'v2rayng', format: 'links' },
  // Anywhere (iOS, `Anywhere/<version>`): imports a plain link list and has no
  // automatic group, so its members get the link entries (main, then backup).
  // Anchored: "anywhere" is an ordinary word inside other User-Agents.
  { re: /^Anywhere\//i, family: 'xray-links', format: 'links' },
  {
    re: /(?:v2ray|xray|nekobox|nekoray|shadowrocket|v2box|foxray|fair|loon)/i,
    family: 'xray-links',
    format: 'links',
  },
];

export function classifyClient(userAgent: string | undefined | null): ClientClassification {
  const ua = (userAgent ?? '').trim();
  for (const r of RULES) {
    if (r.re.test(ua)) return { family: r.family, expectedFormat: r.format };
  }
  return { family: 'other', expectedFormat: 'links' };
}

/** Sniff the served body's format; the renderer trusts this over the UA. */
export function detectBodyFormat(body: string): SubscriptionFormat | 'html' | 'unknown' {
  const t = body.trim();
  if (!t) return 'unknown';
  if (t.startsWith('{')) {
    try {
      const j = JSON.parse(t) as { outbounds?: unknown };
      if (!Array.isArray(j.outbounds)) return 'unknown';
      // An Xray config's outbounds carry `protocol`, sing-box's `type`: an Xray
      // JSON body is no sing-box one.
      const xray = j.outbounds.some(
        (o) => !!o && typeof o === 'object' && 'protocol' in o && !('type' in o),
      );
      return xray ? 'unknown' : 'singbox-json';
    } catch {
      return 'unknown';
    }
  }
  // An array of Xray configs (the backend's Xray JSON subscription): never links.
  if (t.startsWith('[')) return 'unknown';
  if (t.startsWith('<')) return 'html';
  if (/^proxies:/m.test(t) || /^proxy-groups:/m.test(t)) return 'clash-yaml';
  return 'links';
}

/** The base format each family receives (the body still decides at render time). */
export const CLIENT_FAMILY_FORMATS: Record<RenderClientFamily, SubscriptionFormat> = {
  singbox: 'singbox-json',
  mihomo: 'clash-yaml',
  'xray-links': 'links',
  happ: 'links',
  hiddify: 'links',
  streisand: 'links',
  v2rayng: 'links',
  other: 'links',
};

/** The renderer codec (lib/edges/protocols.ts `CODECS`) of each subscription format. */
export const RENDER_FORMAT_OF: Record<SubscriptionFormat, RenderFormat> = {
  links: 'links',
  'singbox-json': 'singbox',
  'clash-yaml': 'clash',
};

/** Whether a family's format can carry the listener at all (sing-box has no XHTTP). */
export function familyCarries(family: RenderClientFamily, proto: ListenerProto): boolean {
  return formatSupported(proto, RENDER_FORMAT_OF[CLIENT_FAMILY_FORMATS[family]]);
}

/**
 * The family the setup status samples an origin with: the first one (in
 * `RENDER_CLIENT_FAMILIES` order, so sing-box wherever it can) that carries at
 * least one of the origin's live listeners; null when none carries any. An
 * XHTTP-only origin samples Mihomo: sing-box has no XHTTP, so the panel gives
 * sing-box members no entry for it.
 */
export function sampleFamilyFor(protos: readonly ListenerProto[]): RenderClientFamily | null {
  return RENDER_CLIENT_FAMILIES.find((f) => protos.some((p) => familyCarries(f, p))) ?? null;
}
