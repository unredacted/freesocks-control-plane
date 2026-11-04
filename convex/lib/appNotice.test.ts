/**
 * The app notice (lib/appNotice.ts): which bodies are answered with it (the
 * body decides, the app must be the reason), the apps and words it says, the
 * notice bodies in each format (inert entries, one group all traffic goes to),
 * and the record's write throttle and hint window. Example names only.
 */
import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { CLASH_YAML } from './backend/subscriptionTemplates/CLASH';
import { SINGBOX_JSON } from './backend/subscriptionTemplates/SINGBOX';
import { defaultRouteFaults } from './backend/subscriptionTemplates/defaultRoute';
import { DEFAULT_CLIENTS, type CatalogClient } from './clientCatalog';
import { detectBodyFormat } from './edges/clientFamilies';
import type { ListenerProto } from './edges/protocols';
import { carriesNoEntry } from './edges/render';
import { decodeBase64Loose, encodeBase64 } from './edges/render/base64';
import { parseProxyUri } from './edges/render/uri';
import {
  APP_NOTICE_RESTAMP_MS,
  APP_NOTICE_SWITCH_MS,
  APP_NOTICE_WINDOW_MS,
  appNoticeBody,
  appNoticeDue,
  appNoticeFor,
  appNoticeShown,
  legacyClashCore,
  NOTICE_HOST,
  NOTICE_PORT,
  noticeApps,
  noticeLines,
  type AppNotice,
} from './appNotice';

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const WS: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
const XHTTP: ListenerProto = { protocol: 'vless', streamTransport: 'xhttp', security: 'reality' };
const UUID = '11111111-2222-4333-8444-555555555555';

/** The legacy CLASH template as the panel serves it to an app with no VLESS: no proxy at all. */
const LEGACY_EMPTY = CLASH_YAML.replace(/ # LEAVE THIS LINE!/g, '');
/** The panel's sing-box template with no entry (the XHTTP-only place). */
const SINGBOX_EMPTY = JSON.stringify(SINGBOX_JSON);
const CLASH_WITH_ENTRY = `mode: rule
proxies:
  - name: entry-a
    type: vless
    server: 198.51.100.1
    port: 443
    uuid: ${UUID}
proxy-groups:
  - name: select
    type: select
    proxies:
      - entry-a
rules:
  - MATCH,select
`;

const LEGACY_UAS = [
  'clash',
  'Clash/1.18.0',
  'ClashX/1.118.0',
  'ClashforWindows/0.20.39',
  'ClashForAndroid/2.5.12',
];
const MODERN_UAS = [
  'mihomo/1.19.33',
  'FlClash/v0.8.93 clash-verge Platform/android',
  'clash-verge/v2.4.0',
  'clash.meta',
  'ClashMetaForAndroid/2.11.5.Meta',
  'ClashX Meta/1.4.0',
  'Stash/2.6.0',
  'SFA/1.12.0',
  'v2rayNG/1.9.0',
];

describe('which bodies get the notice', () => {
  test('a legacy Clash core is told apart from every Clash-named modern one', () => {
    for (const ua of LEGACY_UAS) expect(legacyClashCore(ua), ua).toBe(true);
    for (const ua of MODERN_UAS) expect(legacyClashCore(ua), ua).toBe(false);
  });

  test('the legacy Clash template with no proxy, fetched by a legacy core: too old', () => {
    expect(carriesNoEntry(LEGACY_EMPTY, 'clash-yaml')).toBe(true);
    for (const ua of LEGACY_UAS) {
      // At a place no origin covers (listeners unknown) and at a covered one alike.
      expect(appNoticeFor({ body: LEGACY_EMPTY, ua, listeners: null })).toEqual({
        family: 'clash',
        why: 'old_app',
      });
      expect(appNoticeFor({ body: LEGACY_EMPTY, ua, listeners: [WS] })?.why).toBe('old_app');
    }
  });

  test('never by the User-Agent alone: a body holding an entry is never replaced', () => {
    for (const ua of LEGACY_UAS)
      expect(appNoticeFor({ body: CLASH_WITH_ENTRY, ua, listeners: null })).toBeNull();
    // A link list or sing-box body with an entry, whatever asks.
    const link = `vless://${UUID}@198.51.100.1:443?security=reality&type=tcp#entry-a`;
    expect(appNoticeFor({ body: link, ua: 'clash', listeners: [XHTTP] })).toBeNull();
    expect(appNoticeFor({ body: encodeBase64(link), ua: 'clash', listeners: null })).toBeNull();
    const singbox = JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'select', outbounds: ['entry-a'] },
        { type: 'vless', tag: 'entry-a', server: '198.51.100.1', server_port: 443, uuid: UUID },
      ],
    });
    expect(appNoticeFor({ body: singbox, ua: 'SFA/1.12.0', listeners: [XHTTP] })).toBeNull();
  });

  test('an empty body is a notice only when the app is the reason', () => {
    // A modern Mihomo app given no proxy (a panel or fleet problem): no notice,
    // so a covered place keeps its 503 and the app its last configuration.
    for (const ua of MODERN_UAS)
      expect(appNoticeFor({ body: LEGACY_EMPTY, ua, listeners: [REALITY] })).toBeNull();
    // An HTML page or an unknown body is never a notice.
    expect(appNoticeFor({ body: '<html></html>', ua: 'clash', listeners: null })).toBeNull();
    expect(appNoticeFor({ body: '', ua: 'clash', listeners: null })).toBeNull();
  });

  test('sing-box at a place it cannot carry (XHTTP only): its format cannot carry the mode', () => {
    expect(appNoticeFor({ body: SINGBOX_EMPTY, ua: 'SFA/1.12.0', listeners: [XHTTP] })).toEqual({
      family: 'singbox',
      why: 'mode',
    });
    // A place it can carry, or one it carries in part: a fleet matter, no notice.
    expect(appNoticeFor({ body: SINGBOX_EMPTY, ua: 'Karing/1', listeners: [REALITY] })).toBeNull();
    expect(
      appNoticeFor({ body: SINGBOX_EMPTY, ua: 'Karing/1', listeners: [REALITY, XHTTP] }),
    ).toBeNull();
    // Where FCP does not know the place's listeners, only an old app can be told.
    expect(appNoticeFor({ body: SINGBOX_EMPTY, ua: 'SFA/1.12.0', listeners: null })).toBeNull();
  });

  test('a link list with no entry: link apps carry every transport, so never the app', () => {
    for (const listeners of [[REALITY], [XHTTP], [WS], null])
      expect(appNoticeFor({ body: 'not a link', ua: 'v2rayNG/1.9.0', listeners })).toBeNull();
  });

  test('a listener no format carries says nothing about the app', () => {
    // A combination with no codec at all (CODECS has no entry for it).
    const odd: ListenerProto = { protocol: 'vless', streamTransport: 'udp', security: 'none' };
    expect(appNoticeFor({ body: SINGBOX_EMPTY, ua: 'SFA/1.12.0', listeners: [odd] })).toBeNull();
  });
});

const OLD: AppNotice = { family: 'clash', why: 'old_app' };
const SINGBOX_MODE: AppNotice = { family: 'singbox', why: 'mode' };

describe('the apps it names', () => {
  test('an old Clash app is pointed at current Clash apps first, never at "Clash"', () => {
    const apps = noticeApps(DEFAULT_CLIENTS, {
      backend: 'remnawave',
      xhttpMode: false,
      notice: OLD,
    });
    expect(apps).toEqual(['FlClash', 'Mihomo Party']);
    // Named for what it is, the Clash Verge Rev entry is offered too.
    const renamed = DEFAULT_CLIENTS.map((c) =>
      c.name === 'Clash' ? { ...c, name: 'Clash Verge Rev', easeOfUse: 'easy' as const } : c,
    );
    expect(noticeApps(renamed, { backend: 'remnawave', xhttpMode: false, notice: OLD })[0]).toBe(
      'Clash Verge Rev',
    );
  });

  test('sing-box on an XHTTP mode: never an app of its own format, even with no flags set', () => {
    const apps = noticeApps(DEFAULT_CLIENTS, {
      backend: 'remnawave',
      xhttpMode: true,
      notice: SINGBOX_MODE,
    });
    expect(apps).toEqual(['Hiddify', 'Anywhere']);
    const unflagged: CatalogClient[] = DEFAULT_CLIENTS.map(({ xhttp: _xhttp, ...c }) => c);
    const named = noticeApps(unflagged, {
      backend: 'remnawave',
      xhttpMode: true,
      notice: SINGBOX_MODE,
    });
    expect(named).not.toContain('Karing');
    expect(named).not.toContain('sing-box');
  });

  test('on a device-limited plan, apps that honour the limit come first', () => {
    expect(
      noticeApps(DEFAULT_CLIENTS, {
        backend: 'remnawave',
        xhttpMode: false,
        deviceLimited: true,
        notice: OLD,
      }),
    ).toEqual(['Karing', 'Throne']);
    // sing-box on XHTTP: Karing reads sing-box too, so Throne, then the rest.
    expect(
      noticeApps(DEFAULT_CLIENTS, {
        backend: 'remnawave',
        xhttpMode: true,
        deviceLimited: true,
        notice: SINGBOX_MODE,
      }),
    ).toEqual(['Throne', 'Hiddify']);
  });

  test('only enabled apps on the key backend, at most two', () => {
    const one: CatalogClient[] = DEFAULT_CLIENTS.map((c) => ({
      ...c,
      enabled: c.name === 'Mihomo Party' || c.name === 'Outline',
    }));
    expect(noticeApps(one, { backend: 'remnawave', xhttpMode: false, notice: OLD })).toEqual([
      'Mihomo Party',
    ]);
    expect(noticeApps([], { backend: 'remnawave', xhttpMode: false, notice: OLD })).toEqual([]);
  });
});

describe('the words', () => {
  test('what is wrong, what to install, where to get help: by the service name, no domain', () => {
    expect(noticeLines(OLD, ['FlClash', 'Mihomo Party'], 'FreeSocks')).toEqual([
      '⚠ App too old for FreeSocks',
      'Install FlClash or Mihomo Party',
      'Help: your FreeSocks account page',
    ]);
    expect(noticeLines(SINGBOX_MODE, ['Hiddify'], 'Example VPN')).toEqual([
      "⚠ App can't use this connection mode",
      'Install Hiddify',
      'Or switch mode on your Example VPN account page',
    ]);
    // No app to name: the install line goes.
    expect(noticeLines(OLD, [], 'FreeSocks')).toHaveLength(2);
    for (const line of noticeLines(OLD, ['FlClash', 'Mihomo Party'], 'FreeSocks')) {
      expect(line).not.toContain('—');
      expect(line).not.toMatch(/https?:|\.org|\.com/);
    }
  });

  test('a catalog or site name never breaks a line', () => {
    const lines = noticeLines(OLD, ['Evil\nApp', ''], 'Site\tName');
    expect(lines).toEqual([
      '⚠ App too old for Site Name',
      'Install Evil App',
      'Help: your Site Name account page',
    ]);
    expect(noticeLines(OLD, [], '   ')[0]).toBe('⚠ App too old for FreeSocks');
  });
});

describe('the notice bodies', () => {
  const lines = noticeLines(OLD, ['FlClash', 'Mihomo Party'], 'FreeSocks');

  test('Clash: inert SOCKS5 entries the legacy core parses, one select group, MATCH to it', () => {
    const body = appNoticeBody(OLD, lines, 'FreeSocks', LEGACY_EMPTY);
    expect(detectBodyFormat(body)).toBe('clash-yaml');
    expect(carriesNoEntry(body, 'clash-yaml')).toBe(false);
    const doc = YAML.parse(body) as {
      mode: string;
      proxies: Array<Record<string, unknown>>;
      'proxy-groups': Array<{ name: string; type: string; proxies: string[] }>;
      rules: string[];
    };
    expect(doc.mode).toBe('rule');
    expect(doc.proxies.map((p) => p.name)).toEqual(lines);
    for (const p of doc.proxies)
      expect(p).toEqual({ name: p.name, type: 'socks5', server: NOTICE_HOST, port: NOTICE_PORT });
    expect(doc['proxy-groups']).toEqual([{ name: 'FreeSocks', type: 'select', proxies: lines }]);
    expect(doc.rules).toEqual(['MATCH,FreeSocks']);
    // Nothing defaults to DIRECT or REJECT (the template rule every member body keeps).
    expect(defaultRouteFaults(body, 'FreeSocks')).toEqual([]);
  });

  test('sing-box: inert SOCKS outbounds, the selector is the final route, the template inbounds', () => {
    const said = noticeLines(SINGBOX_MODE, ['Hiddify', 'Anywhere'], 'FreeSocks');
    const body = appNoticeBody(SINGBOX_MODE, said, 'FreeSocks', SINGBOX_EMPTY);
    expect(detectBodyFormat(body)).toBe('singbox-json');
    expect(carriesNoEntry(body, 'singbox-json')).toBe(false);
    const doc = JSON.parse(body) as {
      inbounds: unknown[];
      outbounds: Array<Record<string, unknown>>;
      route: { final: string };
    };
    expect(doc.inbounds).toEqual(SINGBOX_JSON.inbounds);
    expect(doc.outbounds[0]).toEqual({
      type: 'selector',
      tag: 'FreeSocks',
      outbounds: said,
      default: said[0],
    });
    expect(doc.outbounds.slice(1)).toEqual(
      said.map((tag) => ({ type: 'socks', tag, server: NOTICE_HOST, server_port: NOTICE_PORT })),
    );
    expect(doc.route.final).toBe('FreeSocks');
    expect(defaultRouteFaults(body, 'FreeSocks')).toEqual([]);
  });

  test('links: one inert VLESS link per line, encoded as the list it replaces', () => {
    const notice: AppNotice = { family: 'links', why: 'mode' };
    const plain = appNoticeBody(notice, lines, 'FreeSocks', 'not a link');
    const parsed = plain.split('\n').map((l) => parseProxyUri(l)!);
    expect(parsed.map((p) => decodeURIComponent(p.fragment ?? ''))).toEqual(lines);
    for (const p of parsed) {
      expect(p.scheme).toBe('vless');
      expect(p.host).toBe(NOTICE_HOST);
      expect(p.port).toBe(NOTICE_PORT);
    }
    const encoded = appNoticeBody(notice, lines, 'FreeSocks', encodeBase64('vless://x@y:1#z'));
    expect(decodeBase64Loose(encoded)).toBe(plain);
  });
});

describe('the record: write throttle and hint window', () => {
  const now = 10 * APP_NOTICE_WINDOW_MS;

  test('written when there is none, or once it is a few hours old', () => {
    expect(appNoticeDue(null, 'clash', now)).toBe(true);
    expect(appNoticeDue({ family: 'clash', at: now - 60_000 }, 'clash', now)).toBe(false);
    expect(
      appNoticeDue({ family: 'clash', at: now - APP_NOTICE_RESTAMP_MS + 1 }, 'clash', now),
    ).toBe(false);
    expect(appNoticeDue({ family: 'clash', at: now - APP_NOTICE_RESTAMP_MS }, 'clash', now)).toBe(
      true,
    );
    // Another kind of app replaces a record only once it is an hour old: two
    // affected apps polling one key never write once per poll.
    expect(appNoticeDue({ family: 'singbox', at: now - 60_000 }, 'clash', now)).toBe(false);
    expect(
      appNoticeDue({ family: 'singbox', at: now - APP_NOTICE_SWITCH_MS + 1 }, 'clash', now),
    ).toBe(false);
    expect(appNoticeDue({ family: 'singbox', at: now - APP_NOTICE_SWITCH_MS }, 'clash', now)).toBe(
      true,
    );
  });

  test('shown for 7 days after the last notice, then not', () => {
    const at = now - APP_NOTICE_WINDOW_MS + 1;
    expect(appNoticeShown({ family: 'clash', at }, now)).toEqual({ family: 'clash', at });
    expect(appNoticeShown({ family: 'clash', at: now - APP_NOTICE_WINDOW_MS }, now)).toBeNull();
    expect(appNoticeShown(undefined, now)).toBeNull();
  });
});
