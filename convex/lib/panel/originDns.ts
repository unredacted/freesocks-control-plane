/**
 * Origin names for front nodes (pure). FCP makes the A/AAAA record a front
 * node's Caddy obtains its certificate for, in a Cloudflare zone the operator
 * chose at setup. Every record FCP writes carries an ownership marker in its
 * comment, and nothing at that name is touched unless FCP wrote it: a record
 * with a foreign comment, foreign content, or a CNAME at the name is a
 * conflict for the operator, never something to replace.
 *
 * The label is the node name made a DNS label; the hostname is ONE label
 * under the zone apex (a Cloudflare Universal SSL rule the edges share).
 */
export const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** The default label for a node name: lowercase, separators to hyphens, collapsed, trimmed. */
export function originLabel(name: string): string | null {
  const label = name
    .toLowerCase()
    .replace(/[ ._]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
    .replace(/-+$/g, '');
  return LABEL_RE.test(label) ? label : null;
}

export function originHostname(label: string, zoneName: string): string {
  return `${label}.${zoneName.toLowerCase().replace(/\.$/, '')}`;
}

export const originMarker = (backendSlug: string, nodeName: string): string =>
  `fcp-origin:${backendSlug}:${nodeName}`;

export interface DnsRecordLike {
  id: string;
  type: 'A' | 'AAAA' | 'CNAME' | string;
  name: string;
  content: string;
  proxied: boolean;
  comment?: string;
}

export interface DesiredRecord {
  type: 'A' | 'AAAA';
  name: string;
  content: string;
}

export type RecordPlan =
  | { action: 'create' }
  | { action: 'keep'; id: string }
  /** FCP's own record with other content: delete it, then create the desired one. */
  | { action: 'replace'; deleteId: string }
  | { action: 'conflict'; reason: 'cname' | 'foreign' | 'proxied' | 'several' };

/** Decide what to do about ONE desired record given everything at its name. */
export function planRecord(
  existing: readonly DnsRecordLike[],
  desired: DesiredRecord,
  marker: string,
): RecordPlan {
  const name = desired.name.toLowerCase();
  const atName = existing.filter((r) => r.name.toLowerCase() === name);
  if (atName.some((r) => r.type === 'CNAME')) return { action: 'conflict', reason: 'cname' };
  const sameType = atName.filter((r) => r.type === desired.type);
  if (sameType.length === 0) return { action: 'create' };
  const foreign = sameType.filter((r) => r.comment !== marker);
  if (foreign.length > 0) return { action: 'conflict', reason: 'foreign' };
  if (sameType.length > 1) return { action: 'conflict', reason: 'several' };
  const mine = sameType[0]!;
  if (mine.proxied) return { action: 'conflict', reason: 'proxied' };
  if (mine.content.toLowerCase() === desired.content.toLowerCase())
    return { action: 'keep', id: mine.id };
  return { action: 'replace', deleteId: mine.id };
}

/** Whether public resolution shows exactly the intended addresses (per family that is intended). */
export function verifyResolution(
  answers: { v4: readonly string[]; v6: readonly string[] },
  expected: { v4?: string | null; v6?: string | null },
): boolean {
  const same = (got: readonly string[], want: string | null | undefined) =>
    want ? got.length === 1 && got[0]!.toLowerCase() === want.toLowerCase() : got.length === 0;
  return same(answers.v4, expected.v4) && same(answers.v6, expected.v6);
}
