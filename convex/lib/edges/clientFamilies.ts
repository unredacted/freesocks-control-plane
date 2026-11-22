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
  // The real User-Agent of each app, with its evidence, is pinned in
  // tests/compat/userAgents.ts (convex/clientUserAgents.test.ts): a change
  // here must keep every app there in its family and format.
  //
  // Apps whose User-Agent names other apps come first. Karing's may list the
  // apps it can pass for (HiddifyNext, mihomo, sing-box, ...), Hiddify's ends
  // `like ClashMeta v2ray sing-box`, NekoBox's `(Prefer ClashMeta Format)`,
  // Husi's `(sing-box <ver>)`.
  { re: /karing/i, family: 'singbox', format: 'singbox-json' },
  { re: /hiddify/i, family: 'hiddify', format: 'links' },
  // NekoBox (Android, and NekoRay on desktop: `NekoBox/PC/...`): the panel
  // serves it a link list, and its sing-box fork has no VLESS Encryption, so
  // it takes the plain rule of the apps FCP does not tell apart.
  { re: /^NekoBox\//i, family: 'other', format: 'links' },
  // Husi reads link lists (the panel's answer to it) and its core speaks
  // VLESS Encryption.
  { re: /^husi\//i, family: 'xray-links', format: 'links' },
  // Auto-capable clients. Keep the official-shell prefix list in step
  // with SINGBOX_*_UA_RE in lib/backends/remnawaveUserAgent.ts (the sub-fetch
  // rewrite): a shell the backend is served sing-box JSON for must classify as
  // `singbox`. Since sing-box 1.14 a shell sends `SFA (sing-box <ver>; ...)`.
  {
    re: /^(?:SFA|SFI|SFM|SFT|SFL|SFW)(?:\/| \(sing-box)/i,
    family: 'singbox',
    format: 'singbox-json',
  },
  { re: /sing-?box/i, family: 'singbox', format: 'singbox-json' },
  {
    re: /(?:mihomo|clash[.-]?meta|clash[- ]?verge|flclash|clashx|stash|clash)/i,
    family: 'mihomo',
    format: 'clash-yaml',
  },
  // The rest of the panel's Mihomo rule (remnawaveUserAgent.ts).
  { re: /^(?:rabbit|flowvy|murge|prizrak-box)/i, family: 'mihomo', format: 'clash-yaml' },
  // Link-list clients with their own quirks.
  { re: /happ/i, family: 'happ', format: 'links' },
  { re: /streisand/i, family: 'streisand', format: 'links' },
  { re: /v2rayng/i, family: 'v2rayng', format: 'links' },
  // Anywhere (iOS): imports a plain link list and has no automatic group, so
  // its members get the link entries (main, then backup). Its subscription
  // fetch sends the bare name (`User-Agent: Anywhere`, its
  // SubscriptionFetcher.swift); `Anywhere/<version>` is taken too. Anchored
  // and whole: "anywhere" is an ordinary word inside other User-Agents.
  { re: /^Anywhere(?:\/|$)/i, family: 'xray-links', format: 'links' },
  // Xray-cored link-list apps named by an ordinary word: anchored.
  { re: /^(?:Throne|Exclave)\//i, family: 'xray-links', format: 'links' },
  // Link-list apps NOT known to speak VLESS Encryption from a link: the plain
  // rule of the apps FCP does not tell apart, so an encrypted-only rule on
  // `xray-links` never reaches them (tests/compat/userAgents.ts says why for
  // each). Before the broad Xray rule below, which some of them would match.
  { re: /^(?:Shadowrocket|INCY|v2RayTun|FoXray|Loon)\//i, family: 'other', format: 'links' },
  {
    re: /(?:v2ray|xray|nekoray|shadowrocket|v2box|foxray|fair|loon)/i,
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
