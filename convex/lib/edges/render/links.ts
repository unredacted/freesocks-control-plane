/**
 * Link-list renderer (vless:// lines, optionally base64-wrapped): the format
 * plain VLESS clients import. The template line for a slot is found by its
 * `#remark`; each assigned endpoint becomes a copy of that line with the edge
 * address/port, the selected SNI and a friendly label. Everything else in the
 * list (other transports, comments) passes through untouched.
 */
import { bracketIfV6 } from '../ip';
import { decodeBase64Loose, encodeBase64 } from './base64';
import { orderEndpoints, type RenderInput, type RenderOutput } from './types';

const PROXY_LINE_RE = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//i;

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
 * Rewrite one proxy line's host, port, remark, SNI and HTTP Host. Returns null
 * if unparseable: the `user@host:port?query` schemes only, so a `vmess://`
 * base64 blob (whose whole payload is one encoded JSON object, address
 * included) is never touched and is dropped instead of handed out.
 *
 * A null `sni` leaves the line's own TLS parameters alone (a non-REALITY slot
 * terminates TLS on the node with its real name). `hostHeader` is the HTTP Host
 * the transport must carry: it is written to `host=` for an HTTP transport
 * (always for `type=ws|httpupgrade`, otherwise only when the template already
 * carried the parameter) and to `authority=` for `type=grpc` when the template
 * carried one. `path`, `serviceName`, `pbk`, `sid`, `spx`, `fp`, `security` and
 * `flow` are never touched: they are the node's own credentials and routing.
 */
export function rewriteVlessLine(
  line: string,
  target: {
    address: string;
    port: number;
    sni: string | null;
    hostHeader?: string | null;
    label: string;
  },
): string | null {
  const hashIdx = line.indexOf('#');
  const main = hashIdx >= 0 ? line.slice(0, hashIdx) : line;
  const m = /^((?:vless|trojan|ss):\/\/)([^@]+)@(\[[^\]]+\]|[^:/?#]+):(\d+)(\?[^#]*)?$/i.exec(main);
  if (!m) return null;
  const [, scheme, user, , , query] = m;
  const params = new URLSearchParams(query ? query.slice(1) : '');
  const hostHeader = target.hostHeader ?? null;
  if (target.sni !== null) {
    params.set('sni', target.sni);
    // A protocol with no Host of its own (REALITY / plain TLS) must still not
    // keep the template's `host=`: it would carry the origin's name.
    if (hostHeader === null && params.has('host')) params.set('host', target.sni);
  }
  if (hostHeader !== null) {
    const type = (params.get('type') ?? '').toLowerCase();
    if (params.has('host') || type === 'ws' || type === 'httpupgrade')
      params.set('host', hostHeader);
    // gRPC carries the name in `:authority`; only keep an existing one in step,
    // never invent one (Xray defaults it to the address, which is correct here).
    if (type === 'grpc' && params.has('authority')) params.set('authority', hostHeader);
  }
  const q = params.toString();
  return `${scheme}${user}@${bracketIfV6(target.address)}:${target.port}${q ? `?${q}` : ''}#${encodeURIComponent(target.label)}`;
}

export function renderLinks(input: RenderInput): RenderOutput {
  const trimmed = input.body.trim();
  if (!trimmed) return { body: input.body, applied: false, reason: 'empty', emitted: 0 };
  let encoded = false;
  let body = trimmed;
  if (!PROXY_LINE_RE.test(trimmed)) {
    // Either alphabet, padded or not (mirrors and some panels emit URL-safe,
    // unpadded bodies); anything that does not decode to a link list is text.
    const decoded = decodeBase64Loose(trimmed);
    if (decoded !== null && PROXY_LINE_RE.test(decoded.trim())) {
      encoded = true;
      body = decoded;
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
      // With drop on, the template line goes whatever its scheme: it carries
      // the origin/index-0 address, and an unrewritable scheme (vmess blob)
      // is no reason to hand it out.
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
      hostHeader: ep.hostHeader,
      label: ep.label,
    });
    if (line) emitted.push(line);
  }
  if (emitted.length === 0 && !input.rule.dropTemplateEntries) {
    // Endpoints were assigned but none could be rendered from this template
    // and the operator keeps templates: nothing to change.
    return { body: input.body, applied: false, reason: 'no_endpoints_rendered', emitted: 0 };
  }
  // Drop-only (no endpoints, templates dropped): the marker expands to nothing.
  const joined = out.flatMap((l) => (l === '__RELAY_ENDPOINTS__' ? emitted : [l])).join('\n');
  return {
    body: encoded ? encodeBase64(joined) : joined,
    applied: true,
    ...(emitted.length === 0 ? { reason: 'templates_dropped' } : {}),
    emitted: emitted.length,
  };
}
