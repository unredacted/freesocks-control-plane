/**
 * Tiny client-side router. Tracks `window.location.pathname` reactively so
 * the routing tree in `App.svelte` re-renders when the path changes.
 *
 * No external library: for our 9 routes a custom router is ~30 lines and
 * avoids pulling in another runtime dependency.
 */
function createRouter() {
  let pathname = $state(typeof window !== 'undefined' ? window.location.pathname : '/');
  let search = $state(typeof window !== 'undefined' ? window.location.search : '');

  // Back/forward scroll restoration. The browser's native 'auto' restoration
  // fires BEFORE Svelte has remounted the target route (the {#key} wrapper
  // tears the old content down), so it restores against the wrong document
  // height and long pages land at the top. Track positions per history entry
  // ourselves and restore after the remount settles.
  let entrySeq = 0;
  // Per-load nonce so entry ids never collide with ids minted by a previous
  // page load that are still sitting in older history entries.
  const loadNonce = typeof window !== 'undefined' ? Date.now().toString(36) : '0';
  let entryId = 'init';
  const scrollPositions = new Map<string, number>();

  if (typeof window !== 'undefined') {
    history.scrollRestoration = 'manual';
    const initialState = history.state as { fsEntry?: string } | null;
    if (initialState?.fsEntry) {
      entryId = initialState.fsEntry;
    } else {
      history.replaceState({ fsEntry: entryId }, '', window.location.href);
    }

    window.addEventListener('popstate', (e) => {
      scrollPositions.set(entryId, window.scrollY);
      entryId = (e.state as { fsEntry?: string } | null)?.fsEntry ?? 'init';
      pathname = window.location.pathname;
      search = window.location.search;
      const y = scrollPositions.get(entryId) ?? 0;
      // Double-rAF: the route content remounts on the next flush; restoring
      // before it exists clamps the scroll to the interim (shorter) page.
      requestAnimationFrame(() => requestAnimationFrame(() => window.scrollTo(0, y)));
    });
  }

  function navigate(to: string, opts: { replace?: boolean } = {}) {
    if (opts.replace) {
      history.replaceState({ fsEntry: entryId }, '', to);
    } else {
      scrollPositions.set(entryId, window.scrollY);
      entryId = `${loadNonce}-${++entrySeq}`;
      history.pushState({ fsEntry: entryId }, '', to);
    }
    const url = new URL(to, window.location.origin);
    pathname = url.pathname;
    search = url.search;
    // Reset scroll, like a normal navigation would.
    window.scrollTo(0, 0);
  }

  return {
    get pathname() {
      return pathname;
    },
    get search() {
      return search;
    },
    get searchParams() {
      return new URLSearchParams(search);
    },
    navigate,
  };
}

export const router = createRouter();
