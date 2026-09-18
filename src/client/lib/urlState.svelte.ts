/**
 * URL search-param state for pages that keep their view state in the query
 * string (`?tab=`, `?edge=`, `?filter=`). Reads are reactive through
 * `router.searchParams`; writes go through `router.navigate(url, { replace:
 * true, scroll: false })`, which is a SEARCH-ONLY change: `App.svelte` keys the
 * route on `pathname`, so the page is not remounted and a drawer opened via
 * `?edge=<id>` keeps its place.
 *
 * Exports:
 *   searchParam(name, fallback) -> { get value; set value }
 *     value === fallback (or '' / null) removes the param from the URL, so the
 *     default view has a clean address.
 *   setSearchParams(patch) -> write several params at once (one history write).
 */
import { router } from '../stores/router.svelte';

export interface SearchParamAccessor {
  get value(): string;
  set value(v: string | null);
}

function writeParams(mutate: (params: URLSearchParams) => void): void {
  const params = new URLSearchParams(router.search);
  mutate(params);
  const qs = params.toString();
  router.navigate(`${router.pathname}${qs ? `?${qs}` : ''}`, { replace: true, scroll: false });
}

export function searchParam(name: string, fallback = ''): SearchParamAccessor {
  return {
    get value(): string {
      return router.searchParams.get(name) ?? fallback;
    },
    set value(v: string | null) {
      writeParams((params) => {
        if (v === null || v === '' || v === fallback) params.delete(name);
        else params.set(name, v);
      });
    },
  };
}

/** Set (string) or remove (null / '') several params in one history write. */
export function setSearchParams(patch: Record<string, string | null | undefined>): void {
  writeParams((params) => {
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === undefined || v === '') params.delete(k);
      else params.set(k, v);
    }
  });
}
