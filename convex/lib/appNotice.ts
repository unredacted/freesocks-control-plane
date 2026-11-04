/**
 * The app notice (docs/edges.md "Apps that get no connection"): an app that
 * cannot speak what the member's mode serves gets, from the panel, a body
 * that parses but holds no connection (the legacy Clash core has no VLESS,
 * and every FreeSocks mode is VLESS; sing-box has no XHTTP). Before, such an
 * app silently failed. FCP now answers it with a small valid config of the
 * same format whose only entries are inert ones named with the notice:
 *
 *   ⚠ App too old for FreeSocks
 *   Install FlClash or Mihomo Party
 *   Help: your FreeSocks account page
 *
 * The body decides, never the User-Agent alone: a body holding any entry is
 * never replaced. And an empty body is a notice only when FCP can tell the
 * app is the reason (`appNoticeFor`): the panel's legacy Clash template for a
 * legacy Clash User-Agent, or a format that carries none of the place's
 * listeners while another format does. Anything else stays what it was (the
 * edge 503 keeps the app's last configuration), so a working app whose body is
 * empty for another reason never loses its last config to a wrong notice.
 *
 * Each notice entry goes nowhere: a SOCKS5 (Clash), SOCKS (sing-box) or VLESS
 * (links) connection to 127.0.0.1 on port 1, where nothing listens, so the app
 * fails closed and nothing leaves the device. The one group holding them is
 * what all traffic routes to (`MATCH`, `route.final`), never DIRECT.
 *
 * The words are English only: an app's fetch carries no language, and member
 * copy is never machine-translated (translation-review/README.md).
 */
import YAML from 'yaml';
import { v } from 'convex/values';
import { type AppNoticeFamily } from './appNoticeFamilies';
import { publicClients, type CatalogClient } from './clientCatalog';
import { SINGBOX_JSON } from './backend/subscriptionTemplates/SINGBOX';
import {
  classifyClient,
  detectBodyFormat,
  RENDER_FORMAT_OF,
  type SubscriptionFormat,
} from './edges/clientFamilies';
import { formatSupported, RENDER_FORMATS, type ListenerProto } from './edges/protocols';
import { carriesNoEntry } from './edges/render';
import { decodeLinkList } from './edges/render/links';
import { encodeBase64 } from './edges/render/base64';
import { DEFAULT_SITE_NAME } from './memberEntryNames';

export {
  APP_NOTICE_FAMILIES,
  appNoticeFamilyValidator,
  type AppNoticeFamily,
} from './appNoticeFamilies';

/** Why the app got nothing: it is too old (no VLESS), or its format cannot carry the mode. */
export type AppNoticeWhy = 'old_app' | 'mode';
export const appNoticeWhyValidator = v.union(v.literal('old_app'), v.literal('mode'));

export interface AppNotice {
  family: AppNoticeFamily;
  why: AppNoticeWhy;
}

const FAMILY_OF_FORMAT: Record<SubscriptionFormat, AppNoticeFamily> = {
  'clash-yaml': 'clash',
  'singbox-json': 'singbox',
  links: 'links',
};
const FORMAT_OF_FAMILY: Record<AppNoticeFamily, SubscriptionFormat> = {
  clash: 'clash-yaml',
  singbox: 'singbox-json',
  links: 'links',
};

/**
 * The panel's rule for the Mihomo template (Remnawave's default response
 * rules): a Clash-named User-Agent it does NOT match gets the legacy CLASH
 * template, which has no VLESS.
 */
const PANEL_MIHOMO_UA =
  /^(?:flclash|rabbit|flowvy|murge|mihomo|prizrak-box|koala-clash|clash(?:-verge|-nyanpasu|x meta|[-.]?meta))/i;

/**
 * A legacy Clash core (Clash for Windows, ClashX, the original Clash for
 * Android, `clash`, `Clash/<ver>`): what the panel serves its legacy CLASH
 * template. Read with the body, never alone.
 */
export function legacyClashCore(ua: string): boolean {
  const t = ua.trim();
  return /^clash/i.test(t) && !PANEL_MIHOMO_UA.test(t);
}

/**
 * Whether this body is answered with the notice, and which. The body must
 * read as its format and hold no entry at all (render.ts `carriesNoEntry`),
 * and the app must be the reason: a legacy Clash core given the Clash
 * template (`old_app`), or a format that carries none of the place's
 * listeners while some other format carries one (`mode`: sing-box on XHTTP).
 * `listeners` is what the place serves, null where FCP does not know it (a
 * place no origin covers): only `old_app` can be told there.
 */
export function appNoticeFor(input: {
  body: string;
  ua: string;
  listeners: readonly ListenerProto[] | null;
}): AppNotice | null {
  const format = detectBodyFormat(input.body);
  if (format !== 'links' && format !== 'singbox-json' && format !== 'clash-yaml') return null;
  if (!carriesNoEntry(input.body, format)) return null;
  const family = FAMILY_OF_FORMAT[format];
  if (format === 'clash-yaml' && legacyClashCore(input.ua)) return { family, why: 'old_app' };
  const listeners = input.listeners ?? [];
  const own = RENDER_FORMAT_OF[format];
  if (
    listeners.length > 0 &&
    listeners.every((p) => !formatSupported(p, own)) &&
    listeners.some((p) => RENDER_FORMATS.some((f) => formatSupported(p, f)))
  )
    return { family, why: 'mode' };
  return null;
}

/** Catalog names that read as a legacy core: "Install Clash" would only confuse a Clash user. */
const LEGACY_APP_NAMES = new Set(['clash', 'clashx', 'clashforwindows', 'clashforandroid']);
const squash = (name: string) => name.toLowerCase().replace(/[^a-z0-9]/g, '');

/** The format an app reads, from its catalog name (the same rules as a User-Agent). */
function formatOfApp(name: string): SubscriptionFormat {
  return classifyClient(name).expectedFormat;
}

/** How many apps the notice names. */
export const NOTICE_APPS_MAX = 2;

/**
 * The apps the notice names, from the client catalog in the setup page's
 * order (open source, then easier, then priority): enabled, on the key's
 * backend, never one marked unable to use an XHTTP mode while the member is
 * on one, never one that reads as a legacy core. An old app is pointed at a
 * current app of its own kind first (it imports the same link); an app whose
 * format cannot carry the mode is never pointed at another of that format.
 */
export function noticeApps(
  clients: readonly CatalogClient[],
  opts: { backend: string; xhttpMode: boolean; notice: AppNotice },
): string[] {
  const format = FORMAT_OF_FAMILY[opts.notice.family];
  const usable = publicClients([...clients]).filter(
    (c) =>
      (c.backends as string[]).includes(opts.backend) &&
      !(opts.xhttpMode && c.xhttp === false) &&
      !LEGACY_APP_NAMES.has(squash(c.name)) &&
      !(opts.notice.why === 'mode' && formatOfApp(c.name) === format),
  );
  const ranked =
    opts.notice.why === 'old_app'
      ? [
          ...usable.filter((c) => formatOfApp(c.name) === format),
          ...usable.filter((c) => formatOfApp(c.name) !== format),
        ]
      : usable;
  return ranked.slice(0, NOTICE_APPS_MAX).map((c) => c.name);
}

/** One line an app shows as an entry name: printable, one line, bounded. */
function cleanLine(s: string): string {
  return (
    s
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u001f\u007f]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 64)
  );
}

/**
 * The notice's words, one per entry: what is wrong, which apps to install
 * (when the catalog names any) and one line on where to get help, by the
 * service name. No address and no domain: the member knows where their
 * account page is, and a domain could be the one that is blocked.
 */
export function noticeLines(
  notice: AppNotice,
  apps: readonly string[],
  siteName: string,
): string[] {
  const site = cleanLine(siteName) || DEFAULT_SITE_NAME;
  const names = apps.map(cleanLine).filter((n) => n.length > 0);
  const lines = [
    notice.why === 'old_app' ? `⚠ App too old for ${site}` : `⚠ App can't use this connection mode`,
    names.length >= 2
      ? `Install ${names[0]} or ${names[1]}`
      : names.length === 1
        ? `Install ${names[0]}`
        : null,
    notice.why === 'old_app'
      ? `Help: your ${site} account page`
      : `Or switch mode on your ${site} account page`,
  ];
  return [...new Set(lines.filter((l): l is string => !!l).map(cleanLine))];
}

/** Where every notice entry points: loopback, a port nothing listens on. */
export const NOTICE_HOST = '127.0.0.1';
export const NOTICE_PORT = 1;
/** The VLESS id of a notice link (a well-formed id no server knows). */
const NOTICE_UUID = '00000000-0000-4000-8000-000000000000';

/**
 * The notice body in the app's own format. The group is named as every
 * member body's is (`<site name> Select`, lib/memberEntryNames.ts) and is
 * where all traffic goes. A link list is encoded the way the panel encoded
 * the one it replaces.
 */
export function appNoticeBody(
  notice: AppNotice,
  lines: readonly string[],
  siteName: string,
  replaced: string,
): string {
  const group = `${cleanLine(siteName) || DEFAULT_SITE_NAME} Select`;
  if (notice.family === 'clash')
    return YAML.stringify({
      mode: 'rule',
      'log-level': 'warning',
      proxies: lines.map((name) => ({
        name,
        type: 'socks5',
        server: NOTICE_HOST,
        port: NOTICE_PORT,
      })),
      'proxy-groups': [{ name: group, type: 'select', proxies: [...lines] }],
      rules: [`MATCH,${group}`],
    });
  if (notice.family === 'singbox')
    return JSON.stringify(
      {
        log: { level: 'warn' },
        // The shipped template's own tun and local proxy: an app that runs the
        // profile captures traffic as it would, and it goes to the notice.
        inbounds: SINGBOX_JSON.inbounds,
        outbounds: [
          { type: 'selector', tag: group, outbounds: [...lines], default: lines[0] },
          ...lines.map((tag) => ({
            type: 'socks',
            tag,
            server: NOTICE_HOST,
            server_port: NOTICE_PORT,
          })),
        ],
        route: { final: group, auto_detect_interface: true },
      },
      null,
      2,
    );
  const links = lines
    .map(
      (name) =>
        `vless://${NOTICE_UUID}@${NOTICE_HOST}:${NOTICE_PORT}?encryption=none&security=none&type=tcp#${encodeURIComponent(name)}`,
    )
    .join('\n');
  return decodeLinkList(replaced)?.encoded ? encodeBase64(links) : links;
}

/** How long a recorded notice stands before it is written again (the write throttle). */
export const APP_NOTICE_RESTAMP_MS = 6 * 60 * 60_000;
/** How long the account page shows the hint after the last notice. */
export const APP_NOTICE_WINDOW_MS = 7 * 24 * 60 * 60_000;

export interface StoredAppNotice {
  family: AppNoticeFamily;
  at: number;
}

/**
 * Whether serving this notice writes the key's record: only when there is
 * none, it names another kind of app, or it is older than the throttle. A
 * notice served every poll writes a few times a day at most.
 */
export function appNoticeDue(
  stored: StoredAppNotice | null | undefined,
  family: AppNoticeFamily,
  now: number,
): boolean {
  return !stored || stored.family !== family || now - stored.at >= APP_NOTICE_RESTAMP_MS;
}

/**
 * The hint the account page shows: a notice served within the window, else
 * none. Kept through good fetches meanwhile, since one key may serve a working
 * app and a too-old one.
 */
export function appNoticeShown(
  stored: StoredAppNotice | null | undefined,
  now: number,
): StoredAppNotice | null {
  return stored && now - stored.at < APP_NOTICE_WINDOW_MS ? stored : null;
}
