/**
 * Families too thin to last (docs/edges.md "Finding names"): a family on a
 * network, bound to a transport, with fewer than three active names that
 * qualify. Counting means reading names, so the `sni-hunt` cron counts the
 * families in turn within a read budget and keeps the answer in `appState`;
 * the attention list only reads that answer.
 */

/** The `appState` key of the answer. */
export const THIN_FAMILIES_KEY = 'sni:hunt:thin';

/** Fewer qualifying names than this is thin. */
export const THIN_BELOW = 3;

export interface ThinFamilies {
  /** The family counted last (`_id`); the next tick goes on after it. */
  after: string | null;
  /** Thin families by id: their slug and how many names qualify. */
  thin: Record<string, { slug: string; qualifying: number }>;
}
