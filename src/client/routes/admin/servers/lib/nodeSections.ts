/**
 * The sections of a node's page (pure; unit-tested in nodeSections.test.ts).
 *
 * A backend node (`/admin/servers/nodes/:uuid`) and an origin added by hand
 * (`/admin/servers/origins/:slug`) share one layout: a section bar over one
 * scroll, and a "Technical details" fold, closed by default, holding the
 * whole origin page (its tabs, drawers and actions). An origin added by hand
 * has no Transports, SNIs or Modes.
 *
 * URL state: `?section=` (summary | addresses | transports | snis | modes |
 * activity | details) scrolls to a section; `details` opens the fold, and so
 * does any of the origin page's own params (`?tab=`, `?edge=`, `?rotation=`,
 * `?listener=`). `?run=<id>` shows a fronting run's progress in Summary,
 * `?front=1` opens the protect sheet for this node.
 *
 * The old origin details address (`/admin/servers/origins/:slug/details`,
 * before that `/admin/edges/relays/:slug`) needs the node lookup to know
 * where to go, so its page component redirects (../../edges/RelayPage.svelte),
 * with `detailsSearch` mapping its query: the Overview tab lands on Summary
 * (its quarantine resolver and running-rotation notice live there now), any
 * other tab on the fold at that tab, no tab on the fold.
 */
import { RELAY_TABS } from '../../edges/lib/routes';

export const NODE_SECTIONS = [
  'summary',
  'addresses',
  'transports',
  'snis',
  'modes',
  'activity',
  'details',
] as const;
export type NodeSection = (typeof NODE_SECTIONS)[number];

export const SECTION_LABELS: Record<NodeSection, string> = {
  summary: 'Summary',
  addresses: 'Addresses',
  transports: 'Transports',
  snis: 'SNIs',
  modes: 'Modes',
  activity: 'Activity',
  details: 'Technical details',
};

/** The sections an origin added by hand has (it serves no transport of its own). */
export const ORIGIN_SECTIONS: readonly NodeSection[] = [
  'summary',
  'addresses',
  'activity',
  'details',
];

export const parseSection = (raw: string | null | undefined): NodeSection | null =>
  (NODE_SECTIONS as readonly string[]).includes(raw ?? '') ? (raw as NodeSection) : null;

/** The origin page's own params: any of them opens the Technical details fold. */
const DETAILS_PARAMS = ['tab', 'edge', 'rotation', 'listener'] as const;

/** Whether the Technical details fold starts open for this query. */
export function detailsOpenFor(search: string): boolean {
  const params = new URLSearchParams(search);
  return params.get('section') === 'details' || DETAILS_PARAMS.some((k) => !!params.get(k));
}

/**
 * The old origin details query as the node page's: `tab=overview` becomes
 * `section=summary`, any other known tab `section=details&tab=T`, no tab (or
 * an unknown one) `section=details`. `edge`, `rotation`, `listener`, `test`
 * and anything else are kept, in order.
 */
export function detailsSearch(search: string): string {
  const params = new URLSearchParams(search);
  const tab = params.get('tab');
  const out = new URLSearchParams();
  if (tab === 'overview') out.set('section', 'summary');
  else {
    out.set('section', 'details');
    if (tab && (RELAY_TABS as readonly string[]).includes(tab)) out.set('tab', tab);
  }
  for (const [k, v] of params) {
    if (k === 'tab' || k === 'section') continue;
    out.append(k, v);
  }
  return `?${out.toString()}`;
}

/** `path` with `search` (a `?a=b` string, or empty) joined onto any query it already has. */
export function joinSearch(path: string, search: string): string {
  const extra = search.replace(/^\?/, '');
  if (!extra) return path;
  return `${path}${path.includes('?') ? '&' : '?'}${extra}`;
}

/** `path` with `search` changed by `patch` (a value sets, null removes); other params kept, in order. */
export function patchSearch(
  path: string,
  search: string,
  patch: Record<string, string | null>,
): string {
  const params = new URLSearchParams(search);
  for (const [k, v] of Object.entries(patch)) {
    if (v === null || v === '') params.delete(k);
    else params.set(k, v);
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

/**
 * The section to scroll to when the address names `current` and `last` was
 * the one handled before: each change is handled once, a section named again
 * after it was cleared is handled again, and Summary (the top) never scrolls.
 * Null: nothing to do.
 */
export function sectionToScroll(
  last: NodeSection | null | undefined,
  current: NodeSection | null,
): NodeSection | null {
  if (current === last) return null;
  return current && current !== 'summary' ? current : null;
}
