/**
 * Classify a subscription fetch's User-Agent into a client FAMILY (the unit the
 * admin's per-client render rules key on) and the subscription FORMAT the backend
 * serves it (which decides which renderer applies). Conservative: unknown UAs
 * are `other` + `links`, and the renderer confirms the format from the body.
 */
import { RENDER_CLIENT_FAMILIES, type RenderClientFamily } from '../edgeConfig';
import { formatSupported, type ListenerProto, type RenderFormat } from './protocols';
import type { EncryptionCap } from '../../../src/shared/encryptionRule';

export type SubscriptionFormat = 'links' | 'singbox-json' | 'clash-yaml';

export interface ClientClassification {
  family: RenderClientFamily;
  /** The format this family USUALLY receives; the body decides in the end. */
  expectedFormat: SubscriptionFormat;
  /**
   * The most this app may be handed whatever its family's rule says
   * (`ENCRYPTION_FLOORS`): `plain` for a version known not to speak VLESS
   * Encryption, `prefer` where its User-Agent cannot tell. Absent = the
   * family's rule decides.
   */
  encryptionCap?: EncryptionCap;
}

/**
 * The first version of each app that speaks VLESS Encryption from a
 * subscription, read from the version its subscription fetch puts in its
 * User-Agent: that version and every later one get their family's rule, an
 * earlier one the plain rule. The model for every app: one row per app (the
 * first whose `match` matches decides), each with its evidence here and the
 * app's User-Agent in tests/compat/userAgents.ts. An app with no row follows
 * its family's rule.
 *
 * A floor is only ever a limit: a row never hands an app more than its
 * family's rule. Where a release is inferred rather than confirmed, the floor
 * is the later candidate.
 */
export interface EncryptionFloor {
  /** The app, as tests/compat/userAgents.ts names it. */
  app: string;
  /** Recognises the app's User-Agent. */
  match: RegExp;
  /**
   * Captures the version's parts (up to three; a missing part counts as 0)
   * and names the first that speaks it. Absent: the app sends no version.
   */
  version?: { re: RegExp; floor: readonly [number, ...number[]] };
  /**
   * What a User-Agent of this app with no readable version gets: its family's
   * rule, at most both entries (`prefer`), or the plain entry.
   */
  noVersion: 'family' | EncryptionCap;
}

const semver = (prefix: string) => new RegExp(`^${prefix}\\/v?(\\d+)\\.(\\d+)\\.(\\d+)`, 'i');

export const ENCRYPTION_FLOORS: readonly EncryptionFloor[] = [
  // Its link converter reads `encryption=` and its sing-box fork speaks the
  // layer from app 5.5.5 (2026-11-04); earlier apps import the entry as plain
  // VLESS. Sends `HiddifyNext/<version> (<platform>) like ClashMeta v2ray sing-box`.
  {
    app: 'Hiddify',
    // Anchored: Karing's User-Agent may name HiddifyNext among the apps it passes for.
    match: /^Hiddify(?:Next)?(?:[/ ]|$)/i,
    version: { re: /^hiddify(?:next)?\/v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/i, floor: [5, 5, 5] },
    noVersion: 'plain',
  },

  // --- Mihomo-based apps ----------------------------------------------------
  // The first release that bundled Mihomo >= 1.19.13, the core that added
  // VLESS Encryption (2025-08-27). FCP's client strings carry no padding,
  // which 1.19.13 already parses.
  {
    app: 'Clash Verge Rev',
    match: /^clash-verge\//i,
    // v2.4.1 (2025-08-30): "Mihomo(Meta) 内核升级至 v1.19.13".
    version: { re: semver('clash-verge'), floor: [2, 4, 1] },
    noVersion: 'family',
  },
  {
    app: 'FlClash',
    // `FlClash/`, `clash/` on Windows, `fl_clash/` on Linux, then `clash-verge Platform/<os>`.
    match: /^(?:FlClash|fl_clash|clash)\/v\S* clash-verge Platform\//i,
    // v0.8.88 (2025-09-23): its core submodule is Mihomo 1.19.13 plus one commit.
    version: { re: semver('(?:FlClash|fl_clash|clash)'), floor: [0, 8, 88] },
    noVersion: 'family',
  },
  {
    app: 'Clash Meta for Android',
    match: /^ClashMetaForAndroid\//i,
    // v2.11.16 (2025-08-27): its core submodule is Mihomo v1.19.13.
    version: { re: semver('ClashMetaForAndroid'), floor: [2, 11, 16] },
    noVersion: 'family',
  },
  {
    app: 'Clash Party',
    match: /^mihomo\.party\//i,
    // v1.8.6 (2025-08-31): "Mihomo(Meta)内核更新至 v1.19.13".
    version: { re: semver('mihomo\\.party'), floor: [1, 8, 6] },
    noVersion: 'family',
  },
  {
    app: 'Prizrak-Box',
    match: /^prizrak-box\//i,
    // v1.0.17 (2025-09-01, then Pandora-Box): its Mihomo fork has VLESS Encryption.
    version: { re: semver('prizrak-box'), floor: [1, 0, 17] },
    noVersion: 'family',
  },
  {
    app: 'Mihomo',
    // The core's own fetches (`clash.meta/v<version>`), and `mihomo/<version>`.
    match: /^(?:clash\.meta|mihomo)\//i,
    // v1.19.13 (2025-08-27): "support vless encryption". Alpha builds
    // (`alpha-<sha>`) carry no version and follow the family.
    version: { re: semver('(?:clash\\.meta|mihomo)'), floor: [1, 19, 13] },
    noVersion: 'family',
  },

  // --- Xray-based apps ------------------------------------------------------
  // Xray-core added VLESS Encryption in v25.8.29 (XTLS/Xray-core#5067) and
  // changed its wire two days later in v25.8.31 (1-RTT padding), which the
  // first version cannot speak: an app's floor is the first release that both
  // reads `encryption=` from a link and bundles a core at v25.8.31 or later.
  {
    app: 'v2rayNG',
    match: /^v2rayNG\//i,
    // 1.10.21 (2025-09-01): Xray v25.8.31. 1.10.20 bundled v25.8.29. Its link
    // parser already read `encryption=` (VlessFmt.kt).
    version: { re: semver('v2rayNG'), floor: [1, 10, 21] },
    noVersion: 'plain',
  },
  {
    app: 'v2rayN',
    match: /^v2rayN\//i,
    // 7.14.1 (2025-08-17, 2dust/v2rayN#7782) stopped resetting `encryption`
    // to none on import; its core is pulled at build time, so the floor is the
    // first release built after Xray v25.8.31: 7.14.6 (2025-09-03).
    version: { re: semver('v2rayN'), floor: [7, 14, 6] },
    noVersion: 'plain',
  },
  {
    app: 'Throne',
    match: /^Throne\//i,
    // 1.1.0 (2026-03-07): a link with `encryption` goes to its Xray v25.12.8
    // outbound. Its User-Agent drops the pre-release tag, so 1.1.0-beta.1 and
    // beta.2 (which dropped the field) read as 1.1.0 too: the floor is the
    // next release, 1.1.1, which no pre-release can pass for.
    version: { re: semver('Throne'), floor: [1, 1, 1] },
    noVersion: 'plain',
  },
  {
    app: 'Exclave',
    match: /^Exclave\//i,
    // 0.16.2 (2025-09-01): "Sync VLESS encryption incompatible breaking
    // changes". 0.16.1 spoke the first wire.
    version: { re: semver('Exclave'), floor: [0, 16, 2] },
    noVersion: 'plain',
  },
  {
    app: 'Husi',
    match: /^husi\//i,
    // v0.14.2-alpha (2025-11-09) enabled the link field as experimental and
    // v0.14.2-rc fixed it; the first stable release after is v0.15.0 (2025-12-05).
    version: { re: semver('husi'), floor: [0, 15, 0] },
    noVersion: 'plain',
  },
  {
    app: 'V2Box',
    match: /^V2Box\//i,
    // 9.8.8 (2026-02-22) "Bump Xray-Core 26.1.23"; through 9.8.7 its notes
    // name Xray 25.7.26. Inferred from the core: no note names the layer.
    version: { re: semver('V2Box'), floor: [9, 8, 8] },
    noVersion: 'plain',
  },
  {
    app: 'Streisand',
    match: /^Streisand(?:\/|$)/i,
    // 1.6.62 (2025-09-04) "Updated core to v25.8.31". Inferred from the core.
    version: { re: semver('Streisand'), floor: [1, 6, 62] },
    noVersion: 'family',
  },
  {
    app: 'Anywhere',
    match: /^Anywhere(?:\/|$)/i,
    // It sends no version (`Anywhere`; builds before 1.1(84) a fixed
    // `Anywhere/1.0`), it reads the field from 1.10 (2026-05-11), and it
    // installs on iOS 18 but refuses the layer below iOS 26
    // (ProxyClient+VLESS.swift), which its User-Agent does not show either:
    // both entries, so an older phone connects on the plain one.
    noVersion: 'prefer',
  },
];

/** A dotted version, compared part by part (a missing part is 0). */
export function versionAtLeast(have: readonly number[], floor: readonly number[]): boolean {
  for (let i = 0; i < Math.max(have.length, floor.length); i++) {
    const h = have[i] ?? 0;
    const f = floor[i] ?? 0;
    if (h !== f) return h > f;
  }
  return true;
}

/** The floor row that decides this User-Agent, if any. */
export function encryptionFloorOf(ua: string): EncryptionFloor | undefined {
  return ENCRYPTION_FLOORS.find((f) => f.match.test(ua));
}

/** The version read from this User-Agent by its row, if it has one. */
export function encryptionVersionOf(row: EncryptionFloor, ua: string): number[] | undefined {
  const m = row.version?.re.exec(ua);
  return m
    ? m
        .slice(1)
        .filter((x) => x !== undefined)
        .map(Number)
    : undefined;
}

/** The most this User-Agent's app may be handed (absent = its family's rule). */
export function encryptionCapOf(ua: string): EncryptionCap | undefined {
  const row = encryptionFloorOf(ua);
  if (!row) return undefined;
  const have = encryptionVersionOf(row, ua);
  if (!have || !row.version) return row.noVersion === 'family' ? undefined : row.noVersion;
  return versionAtLeast(have, row.version.floor) ? undefined : 'plain';
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
    if (r.re.test(ua)) {
      const cap = encryptionCapOf(ua);
      return { family: r.family, expectedFormat: r.format, ...(cap ? { encryptionCap: cap } : {}) };
    }
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
