/**
 * How every Hysteria 2 entry of a subscription body verifies its server (pure).
 *
 * A Hysteria password is the member's VLESS id, so an entry that would trust
 * anyone who answers (or any certificate a CA signed) hands that credential to
 * whoever sits in the path. FCP accepts exactly one trust model for these
 * entries: the node's own certificate, by pin.
 *
 *   links    `hysteria2://` / `hy2://`: `pinSHA256` is an expected certificate
 *            pin, and `insecure` is absent or `0`.
 *   clash    `type: hysteria2`: `fingerprint` is an expected certificate pin,
 *            and `skip-cert-verify` is off as Mihomo reads it (its decoder is
 *            weakly typed: `1`, `"true"`, `"t"` all switch verification off).
 *            An entry with neither is CA-only, which is refused as well.
 *   singbox  `type: hysteria2`: `tls.certificate_public_key_sha256` is a
 *            non-empty list of expected PUBLIC-KEY pins, `tls.insecure` is not
 *            true, and no `tls.certificate` / `certificate_path` overrides it.
 *   xray     `protocol: hysteria` (an object or an array of configs): every
 *            value of `tlsSettings.pinnedPeerCertSha256` is an expected
 *            certificate pin, and `allowInsecure` is not set.
 *
 * Structured bodies are read by their parser, never by their text: JSON and
 * YAML can spell `hysteria2` with escapes. A body whose shape is no single
 * format (Clash proxies beside outbounds; sing-box `type` beside Xray
 * `protocol` markers) is not guessed at: if anything in it, parsed, names
 * Hysteria, it is unreadable.
 *
 * `pinHex` (certificate DER) and `spkiB64` (public key) are different digests,
 * both observed on the profile (`hysteriaAuth`); neither is derived from the
 * other here.
 *
 * Used by a node's Hysteria rehearsal (does the panel's body for the check
 * account carry the entry, pinned?) and by the member delivery guard (drop or
 * refuse anything else).
 */
import YAML from 'yaml';
import { decodeLinkList } from './edges/render/links';
import { decodeBase64Loose } from './edges/render/base64';
import { parseProxyUri } from './edges/render/uri';
import { normalizePinHex } from './backend/hysteriaCert';

export interface ExpectedPins {
  /** Certificate pins (lowercase hex, no separators). */
  pinHex: readonly string[];
  /** Public-key pins (standard base64). */
  spkiB64: readonly string[];
}

/** `pinned`: verified by an expected pin. Anything else is refused. */
export type HysteriaTrust = 'pinned' | 'insecure' | 'no_pin' | 'wrong_pin';

export type BodyFormat = 'links' | 'clash' | 'singbox' | 'xray';

export interface HysteriaEntry {
  /** How the entry is found again: a link's line index, a proxy name, an outbound tag or index path. */
  ref: string;
  address: string;
  port: number;
  sni: string | null;
  trust: HysteriaTrust;
}

export interface HysteriaScan {
  format: BodyFormat | 'other';
  entries: HysteriaEntry[];
  /** The body names Hysteria somewhere this scan could not read as an entry. */
  unreadable: boolean;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const truthy = (v: string | null) => v !== null && v !== '' && v !== '0' && v !== 'false';

/** Something in the body that says Hysteria, whatever its format. */
export const MENTIONS_HYSTERIA = /hysteria|hy2:\/\//i;

/** Whether a parsed value names Hysteria anywhere: keys, values, binary scalars. */
function deepMentions(v: unknown): boolean {
  if (typeof v === 'string') return MENTIONS_HYSTERIA.test(v);
  if (v instanceof Uint8Array) return MENTIONS_HYSTERIA.test(new TextDecoder().decode(v));
  if (Array.isArray(v)) return v.some(deepMentions);
  if (v instanceof Map)
    return [...v.entries()].some(([k, x]) => deepMentions(k) || deepMentions(x));
  if (isObj(v)) return Object.entries(v).some(([k, x]) => deepMentions(k) || deepMentions(x));
  return false;
}

/**
 * A flag as Mihomo decodes it (weak typing): off only when absent, false,
 * zero, or a string strconv.ParseBool reads as false. Anything else, an
 * unparseable string included, counts as on.
 */
function mihomoOn(v: unknown): boolean {
  if (v === undefined || v === null || v === false || v === 0) return false;
  if (typeof v === 'string') return !['0', 'f', 'F', 'false', 'FALSE', 'False'].includes(v);
  return true;
}

/** A strictly typed flag (sing-box, Xray): any value but false switches it on. */
const strictOn = (v: unknown) => v !== undefined && v !== null && v !== false;

const kindOf = (v: unknown) => (typeof v === 'string' ? v.toLowerCase() : '');

function pinVerdict(values: readonly string[], expected: readonly string[]): HysteriaTrust {
  if (values.length === 0) return 'no_pin';
  return values.every((v) => expected.includes(v)) ? 'pinned' : 'wrong_pin';
}

function scanLinks(body: string, pins: ExpectedPins): HysteriaScan | null {
  const decoded = decodeLinkList(body);
  if (!decoded) return null;
  const entries: HysteriaEntry[] = [];
  let unreadable = false;
  decoded.lines.forEach((line, i) => {
    if (!/^(hysteria2|hy2):\/\//i.test(line)) {
      if (MENTIONS_HYSTERIA.test(line)) unreadable = true;
      return;
    }
    const u = parseProxyUri(line);
    if (!u) {
      unreadable = true;
      return;
    }
    const p = u.params;
    const values = (p.get('pinSHA256') ?? '').split(',').map(normalizePinHex).filter(Boolean);
    entries.push({
      ref: String(i),
      address: u.host,
      port: u.port,
      sni: p.get('sni') ?? p.get('peer'),
      trust: truthy(p.get('insecure')) ? 'insecure' : pinVerdict(values, pins.pinHex),
    });
  });
  return { format: 'links', entries, unreadable };
}

function scanClash(doc: Obj, pins: ExpectedPins): HysteriaScan {
  const entries: HysteriaEntry[] = [];
  let unreadable = false;
  for (const p of Array.isArray(doc.proxies) ? doc.proxies : []) {
    if (!isObj(p) || kindOf(p.type) !== 'hysteria2') continue;
    if (typeof p.name !== 'string' || typeof p.server !== 'string') {
      unreadable = true;
      continue;
    }
    const fp = typeof p.fingerprint === 'string' ? normalizePinHex(p.fingerprint) : '';
    entries.push({
      ref: p.name,
      address: p.server,
      port: Number(p.port),
      sni: typeof p.sni === 'string' ? p.sni : null,
      // Verification switched off is never a pin, whatever else the entry says.
      trust: mihomoOn(p['skip-cert-verify']) ? 'insecure' : pinVerdict(fp ? [fp] : [], pins.pinHex),
    });
  }
  return { format: 'clash', entries, unreadable };
}

function singboxTrust(o: Obj, pins: ExpectedPins): HysteriaTrust {
  const tls = isObj(o.tls) ? o.tls : null;
  if (!tls) return 'no_pin';
  if (strictOn(tls.insecure)) return 'insecure';
  if (tls.certificate !== undefined || tls.certificate_path !== undefined) return 'wrong_pin';
  const list = Array.isArray(tls.certificate_public_key_sha256)
    ? tls.certificate_public_key_sha256.filter((x): x is string => typeof x === 'string')
    : [];
  return pinVerdict(list, pins.spkiB64);
}

function scanSingbox(doc: Obj, pins: ExpectedPins): HysteriaScan {
  const entries: HysteriaEntry[] = [];
  let unreadable = false;
  (Array.isArray(doc.outbounds) ? doc.outbounds : []).forEach((o, i) => {
    if (!isObj(o) || kindOf(o.type) !== 'hysteria2') return;
    if (typeof o.server !== 'string') {
      unreadable = true;
      return;
    }
    const tls = isObj(o.tls) ? o.tls : {};
    entries.push({
      ref: typeof o.tag === 'string' ? o.tag : `#${i}`,
      address: o.server,
      port: Number(o.server_port),
      sni: typeof tls.server_name === 'string' ? tls.server_name : null,
      trust: singboxTrust(o, pins),
    });
  });
  return { format: 'singbox', entries, unreadable };
}

function scanXray(configs: Obj[], pins: ExpectedPins): HysteriaScan {
  const entries: HysteriaEntry[] = [];
  let unreadable = false;
  configs.forEach((cfg, c) => {
    (Array.isArray(cfg.outbounds) ? cfg.outbounds : []).forEach((o, i) => {
      if (!isObj(o) || !['hysteria', 'hysteria2'].includes(kindOf(o.protocol))) return;
      const settings = isObj(o.settings) ? o.settings : {};
      const stream = isObj(o.streamSettings) ? o.streamSettings : {};
      const tls = isObj(stream.tlsSettings) ? stream.tlsSettings : {};
      if (typeof settings.address !== 'string') {
        unreadable = true;
        return;
      }
      const raw = tls.pinnedPeerCertSha256;
      const values = (Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(',') : [])
        .filter((x): x is string => typeof x === 'string')
        .map(normalizePinHex)
        .filter(Boolean);
      entries.push({
        ref: `${c}/${i}`,
        address: settings.address,
        port: Number(settings.port),
        sni: typeof tls.serverName === 'string' ? tls.serverName : null,
        trust: strictOn(tls.allowInsecure) ? 'insecure' : pinVerdict(values, pins.pinHex),
      });
    });
  });
  return { format: 'xray', entries, unreadable };
}

/**
 * Every Hysteria entry of a body and how it verifies its server. A body that
 * mentions Hysteria in a way no reader understands is `unreadable`: callers
 * that must not pass an unverified entry refuse it.
 */
export function scanHysteria(body: string, pins: ExpectedPins): HysteriaScan {
  const t = body.trim();
  if (!t) return { format: 'other', entries: [], unreadable: false };
  const textMentions = () => {
    if (MENTIONS_HYSTERIA.test(t)) return true;
    const decoded = decodeBase64Loose(t);
    return decoded !== null && MENTIONS_HYSTERIA.test(decoded);
  };
  const other = (parsed?: unknown): HysteriaScan => ({
    format: 'other',
    entries: [],
    unreadable: textMentions() || deepMentions(parsed),
  });
  if (t.startsWith('<')) return other();
  // JSON is YAML too (and a flow mapping JSON refuses is still YAML a client
  // reads); a link list parses to a scalar, or not at all.
  const parsed = parseLoose(t);
  if (isObj(parsed) || Array.isArray(parsed)) return scanStructured(parsed, pins) ?? other(parsed);
  if (parsed === undefined && !isLinkList(t))
    // Unreadable to us but maybe not to a client (whose parser may differ):
    // any escape or tag could hide the word, so none is let through.
    return { format: 'other', entries: [], unreadable: textMentions() || /[\\!]/.test(t) };
  return scanLinks(t, pins) ?? other();
}

/** The body parsed as JSON, else YAML; undefined when neither reads it. */
function parseLoose(t: string): unknown {
  if (t.startsWith('{') || t.startsWith('['))
    try {
      return JSON.parse(t);
    } catch {
      /* YAML below */
    }
  try {
    return YAML.parse(t);
  } catch {
    return undefined;
  }
}

/** Every line (of the body, or of its base64) a link or a comment. */
function isLinkList(t: string): boolean {
  const decoded = decodeLinkList(t);
  const lines = (decoded?.lines ?? []).filter((l) => l && !l.startsWith('#'));
  return lines.length > 0 && lines.every((l) => /^[a-z][a-z0-9+.-]*:\/\//i.test(l));
}

/** A parsed body of one known shape, or null (no shape, or more than one). */
function scanStructured(json: Obj | unknown[], pins: ExpectedPins): HysteriaScan | null {
  const configs = (Array.isArray(json) ? json : [json]).filter(isObj);
  const outbounds = configs.flatMap((c) => (Array.isArray(c.outbounds) ? c.outbounds : []));
  const clash = !Array.isArray(json) && Array.isArray(json.proxies);
  // sing-box outbounds carry `type`, Xray's `protocol`; a body with both, or
  // with Clash proxies too, is no one format.
  const typed = outbounds.some((o) => isObj(o) && o.type !== undefined);
  const proto = outbounds.some((o) => isObj(o) && o.protocol !== undefined);
  if ([clash, typed, proto].filter(Boolean).length > 1) return null;
  if (clash) return scanClash(json as Obj, pins);
  if (typed && !Array.isArray(json)) return scanSingbox(json, pins);
  if (proto) return scanXray(configs, pins);
  return null;
}

const sameHost = (a: string, b: string) =>
  a
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '') ===
  b
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');

/**
 * The rehearsal's question: does this body carry a Hysteria entry for the
 * endpoint, presenting the server name, verified by an expected pin?
 */
export function hysteriaEndpointVerified(
  body: string,
  pins: ExpectedPins,
  e: { address: string; port: number; sni: string },
): { found: boolean; trust: HysteriaTrust | null; format: HysteriaScan['format'] } {
  const scan = scanHysteria(body, pins);
  const at = scan.entries.filter((x) => sameHost(x.address, e.address) && x.port === e.port);
  const ok = at.find((x) => x.trust === 'pinned' && sameHost(x.sni ?? '', e.sni));
  if (ok) return { found: true, trust: 'pinned', format: scan.format };
  return { found: false, trust: at[0]?.trust ?? null, format: scan.format };
}
