/**
 * Link-list renderer (share-link lines, optionally base64-wrapped): the format
 * plain clients import. Each listener's template line is found by its matcher
 * (`#remark`, or the origin address:port, or the whole single-entry body) and
 * verified against what the listener speaks (render/uri.ts); each assigned
 * endpoint becomes a copy of that line with the edge address/port, the
 * selected SNI and a friendly label. Everything else in the list (other
 * transports, comments) passes through untouched.
 */
import { sameAddress } from '../hosts';
import { decodeBase64Loose, encodeBase64 } from './base64';
import {
  orderEndpoints,
  resolveMatchers,
  templateIdentities,
  type MatchableEntry,
  type RenderInput,
  type RenderMatcher,
  type RenderOutput,
} from './types';
import {
  fragmentText,
  parseProxyUri,
  rewriteProxyUri,
  uriAgrees,
  uriSupported,
  type ParsedUri,
} from './uri';

const PROXY_LINE_RE = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//i;

export function remarkOf(line: string): string | null {
  const u = parseProxyUri(line);
  if (u) return fragmentText(u);
  const i = line.indexOf('#');
  if (i < 0 || i === line.length - 1) return null;
  try {
    return decodeURIComponent(line.slice(i + 1));
  } catch {
    return null;
  }
}

/** Decode a possibly base64-wrapped link list into its lines. */
export function decodeLinkList(body: string): { lines: string[]; encoded: boolean } | null {
  const trimmed = body.trim();
  if (!trimmed) return null;
  let encoded = false;
  let text = trimmed;
  if (!PROXY_LINE_RE.test(trimmed)) {
    const decoded = decodeBase64Loose(trimmed);
    if (decoded !== null && PROXY_LINE_RE.test(decoded.trim())) {
      encoded = true;
      text = decoded;
    }
  }
  return { lines: text.split('\n').map((l) => l.trim()), encoded };
}

interface LineEntry {
  line: string;
  parsed: ParsedUri | null;
}

function entriesOf(lines: readonly string[]): MatchableEntry<LineEntry>[] {
  const out: MatchableEntry<LineEntry>[] = [];
  for (const line of lines) {
    if (!line || !PROXY_LINE_RE.test(line)) continue;
    const parsed = parseProxyUri(line);
    out.push({
      entry: { line, parsed },
      identity: parsed ? fragmentText(parsed) : remarkOf(line),
      address: parsed?.host ?? null,
      port: parsed?.port ?? null,
      supported: (proto) => !!parsed && uriSupported(parsed, proto),
      agrees: (proto) => !!parsed && uriAgrees(parsed, proto),
    });
  }
  return out;
}

/** Which listeners resolve in this body (the pipeline's eligibility pass). */
export function matchLinks(body: string, matchers: readonly RenderMatcher[]) {
  const decoded = decodeLinkList(body);
  if (!decoded) return null;
  return resolveMatchers(entriesOf(decoded.lines), matchers, sameAddress);
}

export function renderLinks(input: RenderInput): RenderOutput {
  const decoded = decodeLinkList(input.body);
  if (!decoded) return { body: input.body, applied: false, reason: 'empty', emitted: 0 };
  const entries = entriesOf(decoded.lines);
  const { templates, matches } = resolveMatchers(entries, input.matchers, sameAddress);
  if (templates.size === 0) {
    return {
      body: input.body,
      applied: false,
      reason: 'no_template_lines',
      emitted: 0,
      listeners: matches,
    };
  }
  const templateLines = new Set([...templates.values()].map((t) => t.line));
  const templateIds = templateIdentities(entries, templates);
  const out: string[] = [];
  let replacedAny = false;
  for (const line of decoded.lines) {
    if (!line) continue;
    const isTemplate =
      templateLines.has(line) ||
      (PROXY_LINE_RE.test(line) &&
        (() => {
          const r = remarkOf(line);
          return r !== null && templateIds.has(r);
        })());
    if (isTemplate) {
      if (!replacedAny) {
        replacedAny = true;
        out.push('__RELAY_ENDPOINTS__');
      }
      // With drop on, the template line goes: it carries the origin / former
      // index-0 address, and that is no reason to hand it out.
      if (!input.rule.dropTemplateEntries) out.push(line);
      continue;
    }
    out.push(line);
  }
  const emitted: string[] = [];
  for (const ep of orderEndpoints(input.endpoints, input.rule)) {
    const tpl = templates.get(ep.listenerKey);
    if (!tpl || !tpl.parsed) continue;
    emitted.push(
      rewriteProxyUri(tpl.parsed, {
        address: ep.address,
        port: ep.port,
        sni: ep.sni,
        hostHeader: ep.hostHeader,
        label: ep.label,
      }),
    );
  }
  if (emitted.length === 0 && !input.rule.dropTemplateEntries) {
    return {
      body: input.body,
      applied: false,
      reason: 'no_endpoints_rendered',
      emitted: 0,
      listeners: matches,
    };
  }
  const joined = out.flatMap((l) => (l === '__RELAY_ENDPOINTS__' ? emitted : [l])).join('\n');
  return {
    body: decoded.encoded ? encodeBase64(joined) : joined,
    applied: true,
    ...(emitted.length === 0 ? { reason: 'templates_dropped' } : {}),
    emitted: emitted.length,
    listeners: matches,
  };
}

/** Every proxy line's address in a (decoded) link list: the leak check's input. */
export function linkAddresses(body: string): Array<{ address: string; port: number }> {
  const decoded = decodeLinkList(body);
  if (!decoded) return [];
  const out: Array<{ address: string; port: number }> = [];
  for (const line of decoded.lines) {
    const u = parseProxyUri(line);
    if (u) out.push({ address: u.host, port: u.port });
  }
  return out;
}
