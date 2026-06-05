/**
 * Tiny client-side router. Tracks `window.location.pathname` reactively so
 * the routing tree in `App.svelte` re-renders when the path changes.
 *
 * No external library — for our 9 routes a custom router is ~30 lines and
 * avoids pulling in another runtime dependency.
 */
function createRouter() {
  let pathname = $state(typeof window !== 'undefined' ? window.location.pathname : '/');
  let search = $state(typeof window !== 'undefined' ? window.location.search : '');

  if (typeof window !== 'undefined') {
    window.addEventListener('popstate', () => {
      pathname = window.location.pathname;
      search = window.location.search;
    });
  }

  function navigate(to: string, opts: { replace?: boolean } = {}) {
    if (opts.replace) {
      history.replaceState(null, '', to);
    } else {
      history.pushState(null, '', to);
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
