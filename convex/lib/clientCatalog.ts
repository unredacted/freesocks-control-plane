/**
 * The member-facing "recommended VPN client apps" catalog — DB-driven + CMS-managed
 * (the `clients` table + convex/clients.ts CRUD), mirroring the mirrorProviders
 * pattern. A compiled `DEFAULT_CLIENTS` seeds a fresh deploy and is the fail-safe
 * fallback when the table is empty (so the "set up your app" section is never
 * blank). No secrets — the whole record is public-safe (projected via publicConfig).
 *
 * The fussy per-app import URL SCHEME is NOT stored here: it stays a tested code
 * builder in src/client/lib/appLinks.ts, referenced by `schemeId`. `schemeId: null`
 * = the app has no one-tap import scheme (manual paste / in-app QR only, e.g.
 * Streisand, Outline). Adding a client that reuses an existing scheme is 100% CMS;
 * a genuinely new scheme is a small code add to appLinks.ts + this default list.
 */
import type { DatabaseReader } from '../_generated/server';
import type { BackendId } from './backendIds';
import { mirrorFormatOfApp, type MirrorFormat } from './mirrorFormats';

export type ClientBackend = BackendId;

/** Ease-of-use rating: sorts within each open-source group (easier first) and
 *  drives an "Easy to use" / "Advanced" badge. Missing = treated as moderate. */
export type ClientEase = 'easy' | 'moderate' | 'advanced';

const EASE_RANK: Record<ClientEase, number> = { easy: 0, moderate: 1, advanced: 2 };
const easeRank = (e: ClientEase | undefined): number => EASE_RANK[e ?? 'moderate'];

/** A catalog row (internal shape). No secrets → the public shape drops only the
 *  CMS-only fields (enabled/priority). */
export interface CatalogClient {
  name: string;
  platforms: string[]; // 'android' | 'ios' | 'windows' | 'desktop'
  backends: ClientBackend[];
  homepageUrl: string;
  schemeId: string | null; // an appLinks builder id; null = manual / QR only
  hwid: boolean; // supports Remnawave device-id (so the per-account device limit is honored)
  openSource?: boolean; // true → OSS badge + ranked ahead of proprietary apps
  license?: string; // short label, e.g. 'GPL-3.0', 'Apache-2.0', 'Proprietary'
  sourceUrl?: string; // public source repo (OSS only)
  easeOfUse?: ClientEase; // easy/moderate/advanced; missing = moderate
  // IPv6 through the tunnel, as VERIFIED behavior: true = works, false = the
  // app is IPv4-only (e.g. its own tun has no inet6), missing = untested.
  // Tri-state on purpose — only claim what was actually observed.
  ipv6?: boolean;
  // XHTTP under REALITY (the `freedom-xhttp` mode) as it reaches the app
  // through FCP's delivery, not what the app's own core could do: an app FCP
  // serves sing-box bodies is false, because the panel builds those without
  // XHTTP. true = works, false = can't (hidden from members on an XHTTP
  // mode), missing = untested (still shown). Same tri-state as `ipv6`.
  xhttp?: boolean;
  // Hysteria 2 (the `privacy-hysteria` mode) as FCP delivers it, pin included:
  // true = recorded evidence that the app imports FCP's raw config, connects
  // over UDP and refuses a server with another certificate
  // (tests/compat/application-evidence.json, the `hysteria2` check); false =
  // it can't, or drops the pin; missing = untested. Unlike `xhttp` this is an
  // allowlist: on a Hysteria mode only `true` is offered, because an app that
  // ignores the pin hands the member's password to whoever answers.
  hysteria2?: boolean;
  // The subscription format the app reads: which of a mirror's objects it
  // imports (docs/mirrors.md "Formats"). Missing = from the app's name, by
  // the rules a User-Agent goes by (`mirrorFormatOfApp`); set it whenever the
  // name does not say (a renamed or localized label).
  format?: MirrorFormat;
  // Admin-set member-facing blurb, shown verbatim in every locale. The defaults
  // deliberately DON'T set it: their copy lives in the SPA's i18n catalog
  // (setup.clientDesc.*) so it translates; an admin value overrides that.
  description?: string;
  enabled: boolean;
  priority: number;
}

/** Public-safe projection — exactly what publicConfig.get ships (no CMS internals). */
export interface PublicClient {
  name: string;
  platforms: string[];
  backends: ClientBackend[];
  homepageUrl: string;
  schemeId: string | null;
  hwid: boolean;
  openSource: boolean;
  license?: string;
  sourceUrl?: string;
  easeOfUse?: ClientEase;
  ipv6?: boolean;
  xhttp?: boolean;
  hysteria2?: boolean;
  description?: string;
  /**
   * The subscription format the app reads (from its name, by the rules a
   * User-Agent goes by): which of a mirror's objects it imports
   * (docs/mirrors.md "Formats").
   */
  format: MirrorFormat;
}

/**
 * Compiled defaults — what a fresh/unseeded deploy shows, and the seed source.
 * The `hwid` flag marks apps that honor Remnawave device identification (Karing /
 * Throne today), which the device-limited free tier needs. `schemeId` values map
 * to the appLinks builders; Throne + Outline have none (manual / QR import).
 */
export const DEFAULT_CLIENTS: CatalogClient[] = [
  {
    name: 'Hiddify',
    format: 'links',
    platforms: ['android', 'ios', 'windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://hiddify.com',
    schemeId: 'hiddify',
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/hiddify/hiddify-app',
    easeOfUse: 'easy',
    xhttp: true, // its sing-box fork carries XHTTP from app v4.0.4 (2026-02)
    hysteria2: false, // its link parser ignores pinSHA256, so the pin never reaches the core
    enabled: true,
    priority: 10,
  },
  {
    name: 'Karing',
    format: 'singbox',
    platforms: ['android', 'ios', 'windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://karing.app',
    schemeId: 'karing',
    hwid: true,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/KaringX/karing',
    easeOfUse: 'moderate',
    xhttp: false, // FCP serves it sing-box bodies, which the panel builds without XHTTP
    enabled: true,
    priority: 20,
  },
  {
    // One of the very few open-source Xray/VLESS clients on iOS. Apple-only
    // (iOS/iPadOS/tvOS; runs on Apple-silicon Macs as the iPad app) — NOT
    // Android/Windows/Linux. Distributed via the App Store (the GitHub releases
    // page has no installable assets).
    name: 'Anywhere',
    format: 'links',
    platforms: ['ios', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://apps.apple.com/us/app/anywhere-vless-proxy/id6758235178',
    schemeId: 'anywhere',
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/NodePassProject/Anywhere',
    easeOfUse: 'easy',
    ipv6: true, // IPv6 works (verified 2026-10-17; supersedes the 2026-08-30 v4-only reading)
    xhttp: true,
    enabled: true,
    priority: 25,
  },
  {
    name: 'sing-box',
    format: 'singbox',
    platforms: ['android', 'ios', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://sing-box.sagernet.org/clients/',
    schemeId: 'sing-box',
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/SagerNet/sing-box',
    easeOfUse: 'advanced',
    ipv6: true, // dual-stack tun from the backend template (verified live 2026-08-30)
    xhttp: false, // sing-box has no XHTTP transport
    enabled: true,
    priority: 30,
  },
  {
    name: 'v2rayNG',
    format: 'links',
    platforms: ['android'],
    backends: ['remnawave'],
    // No Play Store listing anymore (delisted) - the releases page is the
    // canonical install source.
    homepageUrl: 'https://github.com/2dust/v2rayNG/releases/latest',
    schemeId: 'v2rayng',
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/2dust/v2rayNG',
    easeOfUse: 'moderate',
    xhttp: true, // Xray-core inside
    enabled: true,
    priority: 40,
  },
  {
    // The canonical open-source Xray desktop GUI (sibling to v2rayNG). Manual /
    // QR import (no one-tap URL scheme).
    name: 'v2rayN',
    format: 'links',
    platforms: ['windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/2dust/v2rayN/releases/latest',
    schemeId: null,
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/2dust/v2rayN',
    easeOfUse: 'advanced',
    xhttp: true, // Xray-core inside
    enabled: true,
    priority: 45,
  },
  {
    name: 'Clash',
    format: 'clash',
    platforms: ['windows', 'desktop', 'android'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest',
    schemeId: 'clash',
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/clash-verge-rev/clash-verge-rev',
    easeOfUse: 'advanced',
    xhttp: true, // Mihomo v1.19.22+: Clash Verge Rev 2.5.0 or later
    enabled: true,
    priority: 60,
  },
  {
    // Clash-family (mihomo core) → needs the Clash-format subscription. Manual
    // import (paste the subscription URL) to avoid shipping an unverified scheme.
    name: 'FlClash',
    format: 'clash',
    platforms: ['android', 'windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/chen08209/FlClash/releases/latest',
    schemeId: null,
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/chen08209/FlClash',
    easeOfUse: 'moderate',
    xhttp: true, // Mihomo v1.19.22+: FlClash 0.8.93 or later
    enabled: true,
    priority: 62,
  },
  {
    // Clash-family (mihomo core) → needs the Clash-format subscription. Manual import.
    name: 'Mihomo Party',
    format: 'clash',
    platforms: ['windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/mihomo-party-org/mihomo-party/releases/latest',
    schemeId: null,
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/mihomo-party-org/mihomo-party',
    easeOfUse: 'moderate',
    xhttp: true, // Mihomo v1.19.22+: Mihomo Party 1.9.5 or later
    enabled: true,
    priority: 64,
  },
  {
    name: 'Throne',
    format: 'links',
    platforms: ['windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/throneproj/Throne/releases/latest',
    schemeId: null,
    hwid: true,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/throneproj/Throne',
    easeOfUse: 'advanced',
    xhttp: true, // Xray-core inside
    enabled: true,
    priority: 70,
  },
  {
    // The one proprietary app we still recommend (popular, capable iOS client) —
    // labeled as such and sorted after every open-source option.
    name: 'Shadowrocket',
    format: 'links',
    platforms: ['ios'],
    backends: ['remnawave'],
    homepageUrl: 'https://apps.apple.com/app/shadowrocket/id932747118',
    schemeId: 'shadowrocket',
    hwid: false,
    openSource: false,
    license: 'Proprietary',
    easeOfUse: 'easy',
    // xhttp left unset: XHTTP since about 2.2.69, under REALITY unverified.
    enabled: true,
    priority: 75,
  },
  {
    name: 'Outline',
    format: 'links',
    platforms: ['android', 'ios', 'windows', 'desktop'],
    backends: ['outline'],
    homepageUrl: 'https://getoutline.org/get-started/#step-3',
    schemeId: null,
    hwid: false,
    openSource: true,
    license: 'Apache-2.0',
    sourceUrl: 'https://github.com/Jigsaw-Code/outline-apps',
    easeOfUse: 'easy',
    xhttp: false, // Shadowsocks keys only
    enabled: true,
    priority: 80,
  },
];

/**
 * Resolve the catalog: the `clients` table rows if any exist, else the compiled
 * defaults (never blank). Returns the raw list; `publicClients()` filters + projects.
 */
export async function resolveClients(db: DatabaseReader): Promise<CatalogClient[]> {
  const rows = await db.query('clients').collect();
  if (rows.length === 0) return DEFAULT_CLIENTS;
  return rows.map((r) => ({
    name: r.name,
    platforms: r.platforms,
    backends: r.backends as ClientBackend[],
    homepageUrl: r.homepageUrl,
    schemeId: r.schemeId ?? null,
    hwid: r.hwid,
    openSource: r.openSource ?? false,
    license: r.license ?? undefined,
    sourceUrl: r.sourceUrl ?? undefined,
    easeOfUse: r.easeOfUse ?? undefined,
    ipv6: r.ipv6 ?? undefined,
    xhttp: r.xhttp ?? undefined,
    hysteria2: r.hysteria2 ?? undefined,
    format: r.format ?? undefined,
    description: r.description ?? undefined,
    enabled: r.enabled,
    priority: r.priority,
  }));
}

/** Public-safe, enabled-only list for publicConfig.get. Open-source apps rank
 *  ahead of proprietary ones (more trustworthy for this audience), then easier
 *  apps ahead of harder ones, then by the admin-set priority. */
export function publicClients(clients: CatalogClient[]): PublicClient[] {
  return clients
    .filter((c) => c.enabled)
    .slice()
    .sort(
      (a, b) =>
        Number(!!b.openSource) - Number(!!a.openSource) ||
        easeRank(a.easeOfUse) - easeRank(b.easeOfUse) ||
        a.priority - b.priority,
    )
    .map((c) => ({
      name: c.name,
      platforms: c.platforms,
      backends: c.backends,
      homepageUrl: c.homepageUrl,
      schemeId: c.schemeId,
      hwid: c.hwid,
      openSource: c.openSource ?? false,
      license: c.license,
      sourceUrl: c.sourceUrl,
      easeOfUse: c.easeOfUse,
      ipv6: c.ipv6,
      xhttp: c.xhttp,
      hysteria2: c.hysteria2,
      description: c.description,
      format: c.format ?? mirrorFormatOfApp(c.name),
    }));
}

/**
 * The backends on which at least one enabled catalog app has recorded
 * Hysteria 2 evidence (`hysteria2: true`). A Hysteria mode is available only
 * there (lib/placement.ts), and the CMS refuses to turn one on where it is
 * empty: a member would be offered no app, since the setup page offers only
 * those (src/shared/hysteriaModes.ts).
 */
export function hysteriaAppBackends(clients: readonly CatalogClient[]): Set<ClientBackend> {
  const out = new Set<ClientBackend>();
  for (const c of clients)
    if (c.enabled && c.hysteria2 === true) for (const b of c.backends) out.add(b);
  return out;
}
