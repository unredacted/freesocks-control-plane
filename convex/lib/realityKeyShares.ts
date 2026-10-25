/**
 * The REALITY key share a Mihomo body asks for (pure; unit-tested).
 *
 * From Xray-core v26.9.8 on (XTLS/REALITY 8cdf7bf9) a REALITY server lets a
 * client in only when its Client Hello offers an X25519MLKEM768 key share
 * ahead of any X25519 one; any other Client Hello is passed to the target like
 * a probe, and the client fails with `REALITY authentication failed`. Mihomo
 * removes that key share unless the proxy says
 * `reality-opts: {support-x25519mlkem768: true}` (Mihomo v1.19.9 and later;
 * older releases ignore the key and always remove it), and the backend writes
 * the key only for a Host whose Mihomo override is ticked. So every REALITY
 * proxy of a Clash / Mihomo / Stash body gets the key here, and so does the
 * `download-settings` of an XHTTP proxy. A REALITY server that speaks
 * X25519MLKEM768 (Xray v25.5.16 and later) accepts it, so it is safe on the
 * releases before v26.9.8 too. A key the body already sets, true or false, is
 * the operator's own choice on the Host and stays.
 *
 * The key only keeps the share the fingerprint offers: of Mihomo's
 * fingerprints only `chrome` (the backend's default) offers X25519MLKEM768.
 * sing-box removes the share whatever its configuration says, so no body can
 * let it in (docs/client-compatibility.md § "REALITY client versions").
 *
 * It runs on the body the member receives, next to the member-facing names,
 * and asks for the key once, so a cached body goes through it again when it is
 * served. Fail-open: a body it cannot read, or one that already asks
 * everywhere, comes back verbatim.
 */
import YAML from 'yaml';

/** The Mihomo `reality-opts` key that keeps X25519MLKEM768 in the Client Hello. */
export const MLKEM_KEY_SHARE_OPTION = 'support-x25519mlkem768';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

export interface KeyShareResult {
  content: string;
  /** `reality-opts` the key was added to (0 = the body came back verbatim). */
  added: number;
}

/** Ask for the key in one `reality-opts` holder (a proxy, or its download settings). */
function askIn(holder: Obj): number {
  const opts = holder['reality-opts'];
  if (!isObj(opts) || MLKEM_KEY_SHARE_OPTION in opts) return 0;
  holder['reality-opts'] = { ...opts, [MLKEM_KEY_SHARE_OPTION]: true };
  return 1;
}

/**
 * Add `support-x25519mlkem768: true` to every `reality-opts` of a Clash-format
 * body that does not set it. Any other body (links, sing-box or Xray JSON, an
 * HTML page), and any parse failure, comes back verbatim.
 */
export function askMlkemKeyShare(content: string): KeyShareResult {
  const verbatim = { content, added: 0 };
  try {
    const trimmed = content.trim();
    if (!trimmed || /^[{[<]/.test(trimmed) || !/^proxies:/m.test(trimmed)) return verbatim;
    const doc = YAML.parse(trimmed) as unknown;
    if (!isObj(doc) || !Array.isArray(doc.proxies)) return verbatim;
    let added = 0;
    for (const p of doc.proxies) {
      if (!isObj(p)) continue;
      added += askIn(p);
      const xhttp = p['xhttp-opts'];
      if (isObj(xhttp) && isObj(xhttp['download-settings']))
        added += askIn(xhttp['download-settings']);
    }
    return added === 0 ? verbatim : { content: YAML.stringify(doc, { lineWidth: 0 }), added };
  } catch {
    return verbatim;
  }
}
