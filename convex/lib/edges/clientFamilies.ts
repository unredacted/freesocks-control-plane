/**
 * Classify a subscription fetch's User-Agent into a client FAMILY (the unit the
 * admin's per-client render rules key on) and the subscription FORMAT the panel
 * serves it (which decides which renderer applies). Conservative: unknown UAs
 * are `other` + `links`, and the renderer confirms the format from the body.
 */
import type { RenderClientFamily } from '../edgeConfig';

export type SubscriptionFormat = 'links' | 'singbox-json' | 'clash-yaml';

export interface ClientClassification {
  family: RenderClientFamily;
  /** The format this family USUALLY receives; the body decides in the end. */
  expectedFormat: SubscriptionFormat;
}

const RULES: Array<{ re: RegExp; family: RenderClientFamily; format: SubscriptionFormat }> = [
  // Auto-capable clients first.
  { re: /^(?:SFA|SFI|SFM|SFT|SFL)\//i, family: 'singbox', format: 'singbox-json' },
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
      return Array.isArray(j.outbounds) ? 'singbox-json' : 'unknown';
    } catch {
      return 'unknown';
    }
  }
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
