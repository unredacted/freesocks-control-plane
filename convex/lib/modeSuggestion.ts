/**
 * Which connection mode the picker highlights for a member (pure; unit-tested).
 *
 * The country is the one the CDN reports for the request (transient, never
 * stored). Elsewhere, or with no country, the suggestion is the default. In a
 * country on the censored list, the status page's availability matrix decides:
 * the modes available on the member's backend are ranked by that country's
 * cell (`available` before `partial`; `blocked` and no cell never win), ties go
 * to the censorship-recommended mode, then the default, then catalog order. A
 * listed country with no matrix row (or no usable cell) gets the
 * censorship-recommended mode when one is available, else the default.
 *
 * Only the verdict leaves the server: the list and the matrix stay with it.
 */
import type { CensorshipCell } from './statusPage';

export interface SuggestibleMode {
  id: string;
  isCensorshipRecommended: boolean;
  /** The member's backend serves it (enabled, applicable, bound, a node in the pool). */
  available: boolean;
}

const CELL_RANK: Record<CensorshipCell, number | null> = {
  available: 0,
  partial: 1,
  blocked: null,
};

export function suggestModeFor(args: {
  country: string | null;
  listed: readonly string[];
  /** The matrix row for `country`, when the operator wrote one. */
  cells: Readonly<Record<string, CensorshipCell>> | null;
  /** Catalog order. */
  modes: readonly SuggestibleMode[];
  defaultId: string;
}): string {
  const { country, listed, cells, modes, defaultId } = args;
  if (!country || !listed.includes(country)) return defaultId;
  const available = modes.filter((m) => m.available);
  const recommended = available.find((m) => m.isCensorshipRecommended)?.id;
  const ranked = available
    .map((m, order) => ({ m, order, rank: cells?.[m.id] ? CELL_RANK[cells[m.id]] : null }))
    .filter((x): x is { m: SuggestibleMode; order: number; rank: number } => x.rank !== null)
    .sort(
      (a, b) =>
        a.rank - b.rank ||
        Number(b.m.isCensorshipRecommended) - Number(a.m.isCensorshipRecommended) ||
        Number(b.m.id === defaultId) - Number(a.m.id === defaultId) ||
        a.order - b.order,
    );
  return ranked[0]?.m.id ?? recommended ?? defaultId;
}
