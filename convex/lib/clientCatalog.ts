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

/** A catalog row (internal shape). No secrets → the public shape drops only the
 *  CMS-only fields (enabled/priority). */
export interface CatalogClient {
  name: string;
  platforms: string[]; // 'android' | 'ios' | 'windows' | 'desktop'
  backends: ClientBackend[];
  homepageUrl: string;
  schemeId: string | null; // an appLinks builder id; null = manual / QR only
  hwid: boolean; // supports Remnawave device-id (so the per-account device limit is honored)
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
    enabled: true,
    priority: 20,
  },
  {
    name: 'sing-box',
    platforms: ['android', 'ios', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://sing-box.sagernet.org',
    schemeId: 'sing-box',
    hwid: false,
    enabled: true,
    priority: 30,
  },
  {
    name: 'v2rayNG',
    platforms: ['android'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/2dust/v2rayNG',
    schemeId: 'v2rayng',
    hwid: false,
    enabled: true,
    priority: 40,
  },
  {
    name: 'Shadowrocket',
    platforms: ['ios'],
    backends: ['remnawave'],
    homepageUrl: 'https://apps.apple.com/app/shadowrocket/id932747118',
    schemeId: 'shadowrocket',
    hwid: false,
    enabled: true,
    priority: 50,
  },
  {
    name: 'Clash',
    platforms: ['windows', 'desktop', 'android'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/clash-verge-rev/clash-verge-rev',
    schemeId: 'clash',
    hwid: false,
    enabled: true,
    priority: 60,
  },
  {
    name: 'Throne',
    platforms: ['windows', 'desktop'],
    backends: ['remnawave'],
    homepageUrl: 'https://github.com/throneproj/Throne',
    schemeId: null,
    hwid: true,
    enabled: true,
    priority: 70,
  },
  {
    name: 'Outline',
    platforms: ['android', 'ios', 'windows', 'desktop'],
    backends: ['outline'],
    homepageUrl: 'https://getoutline.org/get-started/#step-3',
    schemeId: null,
    hwid: false,
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
    enabled: r.enabled,
    priority: r.priority,
  }));
}

/** Public-safe, enabled-only, priority-sorted list for publicConfig.get. */
export function publicClients(clients: CatalogClient[]): PublicClient[] {
  return clients
    .filter((c) => c.enabled)
    .slice()
    .sort((a, b) => a.priority - b.priority)
    .map((c) => ({
      name: c.name,
      platforms: c.platforms,
      backends: c.backends,
      homepageUrl: c.homepageUrl,
      schemeId: c.schemeId,
      hwid: c.hwid,
    }));
}
