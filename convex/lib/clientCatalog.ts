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

export type ClientBackend = 'remnawave' | 'outline';

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
    platforms: ['android', 'ios', 'windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://hiddify.com',
    schemeId: 'hiddify',
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/hiddify/hiddify-app',
    easeOfUse: 'easy',
    enabled: true,
    priority: 10,
  },
  {
    name: 'Karing',
    platforms: ['android', 'ios', 'windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://karing.app',
    schemeId: 'karing',
    hwid: true,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/KaringX/karing',
    easeOfUse: 'moderate',
    enabled: true,
    priority: 20,
  },
  {
    // One of the very few open-source Xray/VLESS clients on iOS (also Android).
    name: 'Anywhere',
    platforms: ['ios', 'android', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/NodePassProject/Anywhere/releases/latest',
    schemeId: 'anywhere',
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/NodePassProject/Anywhere',
    easeOfUse: 'easy',
    enabled: true,
    priority: 25,
  },
  {
    name: 'sing-box',
    platforms: ['android', 'ios', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://sing-box.sagernet.org/clients/',
    schemeId: 'sing-box',
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/SagerNet/sing-box',
    easeOfUse: 'advanced',
    enabled: true,
    priority: 30,
  },
  {
    name: 'v2rayNG',
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
    enabled: true,
    priority: 40,
  },
  {
    // The canonical open-source Xray desktop GUI (sibling to v2rayNG). Manual /
    // QR import (no one-tap URL scheme).
    name: 'v2rayN',
    platforms: ['windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/2dust/v2rayN/releases/latest',
    schemeId: null,
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/2dust/v2rayN',
    easeOfUse: 'advanced',
    enabled: true,
    priority: 45,
  },
  {
    name: 'Clash',
    platforms: ['windows', 'desktop', 'android'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest',
    schemeId: 'clash',
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/clash-verge-rev/clash-verge-rev',
    easeOfUse: 'advanced',
    enabled: true,
    priority: 60,
  },
  {
    // Clash-family (mihomo core) → needs the Clash-format subscription. Manual
    // import (paste the subscription URL) to avoid shipping an unverified scheme.
    name: 'FlClash',
    platforms: ['android', 'windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/chen08209/FlClash/releases/latest',
    schemeId: null,
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/chen08209/FlClash',
    easeOfUse: 'moderate',
    enabled: true,
    priority: 62,
  },
  {
    // Clash-family (mihomo core) → needs the Clash-format subscription. Manual import.
    name: 'Mihomo Party',
    platforms: ['windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/mihomo-party-org/mihomo-party/releases/latest',
    schemeId: null,
    hwid: false,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/mihomo-party-org/mihomo-party',
    easeOfUse: 'moderate',
    enabled: true,
    priority: 64,
  },
  {
    name: 'Throne',
    platforms: ['windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/throneproj/Throne/releases/latest',
    schemeId: null,
    hwid: true,
    openSource: true,
    license: 'GPL-3.0',
    sourceUrl: 'https://github.com/throneproj/Throne',
    easeOfUse: 'advanced',
    enabled: true,
    priority: 70,
  },
  {
    // The one proprietary app we still recommend (popular, capable iOS client) —
    // labeled as such and sorted after every open-source option.
    name: 'Shadowrocket',
    platforms: ['ios'],
    backends: ['remnawave'],
    homepageUrl: 'https://apps.apple.com/app/shadowrocket/id932747118',
    schemeId: 'shadowrocket',
    hwid: false,
    openSource: false,
    license: 'Proprietary',
    easeOfUse: 'easy',
    enabled: true,
    priority: 75,
  },
  {
    name: 'Outline',
    platforms: ['android', 'ios', 'windows', 'desktop'],
    backends: ['outline'],
    homepageUrl: 'https://getoutline.org/get-started/#step-3',
    schemeId: null,
    hwid: false,
    openSource: true,
    license: 'Apache-2.0',
    sourceUrl: 'https://github.com/Jigsaw-Code/outline-apps',
    easeOfUse: 'easy',
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
    }));
}
