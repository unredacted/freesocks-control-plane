/**
 * Link-list renderer (vless:// lines, optionally base64-wrapped): the format
 * plain VLESS clients import. The template line for a slot is found by its
 * `#remark`; each assigned endpoint becomes a copy of that line with the edge
 * address/port, the selected SNI and a friendly label. Everything else in the
 * list (other transports, comments) passes through untouched.
 */
import { bracketIfV6 } from '../ip';
import { orderEndpoints, type RenderInput, type RenderOutput } from './types';

const PROXY_LINE_RE = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//i;

function looksLikeBase64(s: string): boolean {
  return /^[A-Za-z0-9+/=\r\n]+$/.test(s) && s.replace(/[\r\n]/g, '').length % 4 === 0;
}

export function remarkOf(line: string): string | null {
  const i = line.indexOf('#');
  if (i < 0 || i === line.length - 1) return null;
  try {
    return decodeURIComponent(line.slice(i + 1));
  } catch {
    return null;
  }
}

/**
 * Rewrite one proxy line's host, port, remark and (when given) SNI. Returns
 * null if unparseable. A null `sni` leaves the line's own TLS parameters alone
 * (a non-REALITY slot terminates TLS on the node with its real name).
 */
export function rewriteVlessLine(
  line: string,
  target: { address: string; port: number; sni: string | null; label: string },
): string | null {
  const hashIdx = line.indexOf('#');
  const main = hashIdx >= 0 ? line.slice(0, hashIdx) : line;
  const m = /^((?:vless|trojan|ss):\/\/)([^@]+)@(\[[^\]]+\]|[^:/?#]+):(\d+)(\?[^#]*)?$/i.exec(main);
  if (!m) return null;
  const [, scheme, user, , , query] = m;
  const params = new URLSearchParams(query ? query.slice(1) : '');
  if (target.sni !== null) {
    params.set('sni', target.sni);
    // REALITY never wants the address as the SNI; keep serverName-style params in sync.
    if (params.has('host')) params.set('host', target.sni);
  }
  const q = params.toString();
  return `${scheme}${user}@${bracketIfV6(target.address)}:${target.port}${q ? `?${q}` : ''}#${encodeURIComponent(target.label)}`;
}

export function renderLinks(input: RenderInput): RenderOutput {
  const trimmed = input.body.trim();
  if (!trimmed) return { body: input.body, applied: false, reason: 'empty', emitted: 0 };
  let encoded = false;
  let body = trimmed;
  if (looksLikeBase64(trimmed) && !PROXY_LINE_RE.test(trimmed)) {
    try {
      const decoded = atob(trimmed.replace(/[\r\n]/g, ''));
      if (PROXY_LINE_RE.test(decoded.trim())) {
        encoded = true;
        body = decoded;
      }
    } catch {
      /* not base64 */
    }
  }
  const lines = body.split('\n').map((l) => l.trim());
  const templateSet = new Set(input.templateRemarks);
  const templateByRemark = new Map<string, string>();
  const out: string[] = [];
  let replacedAny = false;
  for (const line of lines) {
    if (!line) continue;
    const remark = PROXY_LINE_RE.test(line) ? remarkOf(line) : null;
    if (remark && templateSet.has(remark)) {
      if (!templateByRemark.has(remark)) templateByRemark.set(remark, line);
      // Emit the endpoints at the position of the FIRST template line.
      if (!replacedAny) {
        replacedAny = true;
        out.push('__RELAY_ENDPOINTS__');
      }
      if (!input.rule.dropTemplateEntries) out.push(line);
      continue;
    }
    out.push(line);
  }
  if (templateByRemark.size === 0) {
    return { body: input.body, applied: false, reason: 'no_template_lines', emitted: 0 };
  }
  const emitted: string[] = [];
  for (const ep of orderEndpoints(input.endpoints, input.rule)) {
    const tpl = templateByRemark.get(ep.slotRemark);
    if (!tpl) continue;
    const line = rewriteVlessLine(tpl, {
      address: ep.address,
      port: ep.port,
      sni: ep.sni,
      label: ep.label,
    });
    if (line) emitted.push(line);
  }
  if (emitted.length === 0) {
    return { body: input.body, applied: false, reason: 'no_endpoints_rendered', emitted: 0 };
  }
  const joined = out.flatMap((l) => (l === '__RELAY_ENDPOINTS__' ? emitted : [l])).join('\n');
  return { body: encoded ? btoa(joined) : joined, applied: true, emitted: emitted.length };
}
