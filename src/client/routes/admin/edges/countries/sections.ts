/**
 * The country page's sections and the Summary's one-line digests (pure;
 * unit-tested). The page shows one section at a time, picked by `?section=`
 * (Summary when it is missing or unknown).
 *
 * Exports:
 *   COUNTRY_SECTIONS / CountrySection      the sections, in bar order, with their labels
 *   countrySectionOf(raw)                  `?section=` -> a section (Summary by default)
 *   markableAddresses(origins, marks, cc)  the addresses that can be marked for this country
 *   addressesDigest / snisDigest / checksDigest / exitDigest
 *                                          one line per section for the Summary
 */
import type {
  CountryMarkRow,
  CountryViewMeantFor,
  CountryViewOrigin,
  CountryViewTotals,
} from '../../../../../shared/contracts/edges';
import { protocolLine } from '../lib/format';

export const COUNTRY_SECTIONS = [
  { id: 'summary', label: 'Summary' },
  { id: 'addresses', label: 'Addresses for this country' },
  { id: 'snis', label: 'SNIs' },
  { id: 'lists', label: 'Lists' },
  { id: 'probes', label: 'Probes' },
  { id: 'checks', label: 'Checks from here' },
  { id: 'exit', label: 'Exit' },
] as const;
export type CountrySection = (typeof COUNTRY_SECTIONS)[number]['id'];

export function countrySectionOf(raw: string | null | undefined): CountrySection {
  const hit = COUNTRY_SECTIONS.find((s) => s.id === raw);
  return hit ? hit.id : 'summary';
}

export interface MarkableAddress {
  edgeId: string;
  address: string;
  /** "<node> · <transport>", for the picker. */
  where: string;
  /** This address's own mark for this country (null: none). */
  mark: 'proven' | 'blocked' | null;
}

/**
 * Every edge address on the page, once each (an address can serve several
 * transports of its node), in page order. The node itself is never marked here:
 * a mark is an operator's word about an edge or a location.
 */
export function markableAddresses(
  origins: readonly CountryViewOrigin[],
  marks: readonly CountryMarkRow[],
  country: string,
): MarkableAddress[] {
  const out: MarkableAddress[] = [];
  const seen = new Set<string>();
  for (const o of origins) {
    const node = o.label ?? o.nodeName ?? o.slug;
    for (const l of o.listeners) {
      for (const a of l.addresses) {
        if (!a.edgeId || a.kind !== 'edge' || seen.has(a.edgeId)) continue;
        seen.add(a.edgeId);
        const own = marks.find(
          (m) => m.scope === 'edge' && m.edgeId === a.edgeId && m.country === country,
        );
        out.push({
          edgeId: a.edgeId,
          address: a.address,
          where: `${node} · ${protocolLine(l)}`,
          mark: own?.state ?? null,
        });
      }
    }
  }
  return out;
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

export function addressesDigest(
  totals: CountryViewTotals,
  meantFor: readonly CountryViewMeantFor[],
): string {
  const parts: string[] = [];
  const atRisk = totals.originsAtRisk;
  if (atRisk > 0)
    parts.push(
      atRisk === 1
        ? 'One node has no working address here.'
        : `${atRisk} nodes have no working address here.`,
    );
  const blocked = meantFor.filter((l) => l.blocked).length;
  if (meantFor.length === 0) parts.push('No location is set for this country.');
  else if (blocked > 0)
    parts.push(
      `${blocked} of ${meantFor.length} ${plural(meantFor.length, 'location', 'locations')} set for it ${plural(blocked, 'is', 'are')} blocked here.`,
    );
  else
    parts.push(
      `${meantFor.length} ${plural(meantFor.length, 'location is', 'locations are')} set for it.`,
    );
  return parts.join(' ');
}

export function snisDigest(totals: CountryViewTotals): string {
  const n = totals.names;
  const all = n.proven + n.blocked + n.unknown;
  if (all === 0) return 'No SNI in use.';
  return `${n.proven} ${n.proven === 1 ? 'works' : 'work'} here, ${n.blocked} blocked, ${n.unknown} not judged.`;
}

export function checksDigest(
  listed: { checkEdges: boolean; checkNamesInside: boolean; nameChecksRun?: boolean } | null,
): string {
  if (!listed) return 'Not on the censored-country list, so nothing is checked from here.';
  const edges = listed.checkEdges
    ? 'Edges are checked from here.'
    : 'Edges are not checked from here.';
  const snis = !listed.checkNamesInside
    ? 'SNIs are not checked from inside.'
    : listed.nameChecksRun === false
      ? 'SNI checks from inside are on, but none runs now.'
      : 'SNIs are checked from inside.';
  return `${edges} ${snis}`;
}

export function exitDigest(labels: readonly string[], steering: boolean): string {
  if (labels.length === 0) return 'Least-loaded location.';
  const list = labels.join(', then ');
  return steering ? `${list}.` : `${list} (not used: ordering by country is off).`;
}
