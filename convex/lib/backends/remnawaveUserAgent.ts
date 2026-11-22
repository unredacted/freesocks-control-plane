/**
 * What the Remnawave panel does with a subscription fetch's User-Agent, and
 * how FCP rewrites the few real app User-Agents the panel misreads.
 *
 * The panel picks the body by its subscription response rules: the first rule
 * whose condition matches answers. The rules below are the User-Agent rules
 * of its DEFAULT set (remnawave/backend 3.4.11
 * `prisma/seed/default/response-rules.ts`, the test panel's image), matched as
 * the panel does: a case-insensitive RegExp test of the header. An operator
 * can edit the rules on the panel; FCP assumes the defaults.
 */

export type RemnawaveResponseType = 'MIHOMO' | 'STASH' | 'SINGBOX' | 'CLASH' | 'XRAY_BASE64';

/** The default rules' User-Agent conditions, in the panel's order. */
export const REMNAWAVE_DEFAULT_UA_RULES: ReadonlyArray<{
  re: RegExp;
  response: Exclude<RemnawaveResponseType, 'XRAY_BASE64'>;
}> = [
  {
    re: /^(?:flclash|rabbit|flowvy|murge|mihomo|prizrak-box|koala-clash|clash(?:-verge|-nyanpasu|x meta|[-.]?meta))/i,
    response: 'MIHOMO',
  },
  { re: /^stash/i, response: 'STASH' },
  // Only the first alternative is anchored: the panel's own regex.
  { re: /^sfa|sfi|sfm|sft|karing|singbox/i, response: 'SINGBOX' },
  { re: /^clash/i, response: 'CLASH' },
];

/** The body the panel's default rules give a User-Agent (as the panel receives it). */
export function remnawaveDefaultResponse(ua: string | undefined): RemnawaveResponseType {
  const t = ua ?? '';
  return REMNAWAVE_DEFAULT_UA_RULES.find((r) => r.re.test(t))?.response ?? 'XRAY_BASE64';
}

/**
 * Remnawave picks the subscription FORMAT by User-Agent, keying on the client
 * app's UA prefix. Probed live against the production backend (2026-08-30):
 * "SFA/…" → sing-box JSON, but the newer official sing-box shells fall through
 * to the base64 default — which sing-box then fails to import ("decode config:
 * invalid character 'd'…", base64 of vless://). Until the backend recognizes
 * them, rewrite a UA that IS sing-box but lacks a recognized prefix to a
 * canonical SFA one, carrying the core version through (the backend may pick the
 * legacy vs modern template by it). Deliberately narrow — only UAs that START
 * with "SFL/" / "SFW/", the official desktop shells' "SFL (sing-box ..." /
 * "SFW (sing-box ..." form (sing-box-for-desktop `src/main/userAgent.ts`: the
 * app name is SFL on Linux, SFW elsewhere), or "sing-box" — so sing-box-CORED
 * third-party apps with their own backend templates (Karing, Happ, …) are never
 * touched. `lib/edges/clientFamilies.ts` keeps the same shell list.
 *
 * Three Mihomo apps are rewritten too, each to a form the panel's Mihomo rule
 * takes (tests/compat/userAgents.ts holds the evidence):
 *  - FlClash builds `<appName>/v<ver> clash-verge Platform/<os>`, and its
 *    app name is `clash` on Windows (the Runner.rc ProductName) and `fl_clash`
 *    on Linux (the pubspec name). The panel reads the Windows form as a legacy
 *    Clash core (the CLASH template, no VLESS: FCP would answer the app
 *    notice) and the Linux one as nothing (base64 links). Both become
 *    `FlClash/v<ver> clash-verge Platform/<os>`, the Android/macOS form.
 *  - ClashX Meta sets no User-Agent, so macOS sends its CFNetwork default,
 *    the bundle name percent-encoded (`ClashX%20Meta/<build> CFNetwork/…`),
 *    which the panel's `clashx meta` misses: `%20` becomes the space.
 *  - Everywhere (iOS) sends `Everywhere/1.0 Clash/1.11.0` whichever of its
 *    cores (Xray, sing-box, Mihomo) the member picked, and stores the body
 *    as its core's whole config: a link list (the panel's answer, its rules
 *    being anchored) works with none of them. It is asked for as its bundled
 *    Mihomo, so the Mihomo core works.
 */
const SINGBOX_RECOGNIZED_UA_RE = /^SF[AIMT]\//;
const SINGBOX_UNRECOGNIZED_UA_RE = /^(?:SF[LW](?:\/|\s+\(sing-box\s)|sing-?box)/i;
const FLCLASH_RENAMED_UA_RE = /^(?:clash|fl_clash)(\/v?\d\S* clash-verge Platform\/)/i;
const CLASHX_META_CFNETWORK_UA_RE = /^ClashX%20Meta\//i;
const EVERYWHERE_UA_RE = /^Everywhere\//i;
/** The Mihomo Everywhere bundles (EverywhereCore v2026.11.15). */
const EVERYWHERE_PANEL_UA = 'mihomo/1.19.34';
export function normalizeSubscriptionUserAgent(ua: string | undefined): string | undefined {
  if (!ua) return ua;
  if (FLCLASH_RENAMED_UA_RE.test(ua)) return ua.replace(FLCLASH_RENAMED_UA_RE, 'FlClash$1');
  if (CLASHX_META_CFNETWORK_UA_RE.test(ua)) return ua.replace(/^ClashX%20Meta/i, 'ClashX Meta');
  if (EVERYWHERE_UA_RE.test(ua)) return EVERYWHERE_PANEL_UA;
  if (SINGBOX_RECOGNIZED_UA_RE.test(ua) || !SINGBOX_UNRECOGNIZED_UA_RE.test(ua)) return ua;
  const ver =
    /sing-?box[/ ]v?(\d+(?:\.\d+){1,2})/i.exec(ua)?.[1] ??
    /^SF[LW]\/v?(\d+(?:\.\d+){1,2})/i.exec(ua)?.[1] ??
    '1.12.0';
  return `SFA/${ver} (sing-box ${ver})`;
}
