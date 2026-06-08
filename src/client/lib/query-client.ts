import { MutationCache, QueryCache, QueryClient } from '@tanstack/svelte-query';
import { ApiCallError } from './api';

/**
 * When an admin query or mutation returns 401, bounce the user to `/admin`
 * (the entry page that renders the login form when an admin exists, or the
 * bootstrap form otherwise). Without this, a deep-link to a page like
 * `/admin/settings` after the session expires just shows a raw "auth.invalid"
 * error inline, confusing for the operator who expects to be prompted to
 * sign in again.
 *
 * We discriminate "admin" requests via the query-key prefix (`['admin', …]`,
 * shared via `queryKeys.admin*` in queries.ts) for queries, and via the
 * mutation's failure path for mutations. The redirect is suppressed when
 * the user is already on `/admin` (the login page itself) so we don't loop.
 */
function isAdminQueryKey(key: readonly unknown[]): boolean {
  return key.length > 0 && key[0] === 'admin';
}

function redirectToAdminLoginIfNeeded(): void {
  if (typeof window === 'undefined') return;
  if (window.location.pathname === '/admin') return; // already there
  window.location.href = '/admin';
}

/**
 * Singleton QueryClient. Mounted once at the SPA root via QueryClientProvider
 * in App.svelte; every `createQuery` / `createMutation` call site uses this
 * same client implicitly via context.
 *
 * Defaults tuned for our app:
 *   - staleTime: 30s        most of our data (account, tiers, users) doesn't
 *                           change second-to-second; suppress thrashing on
 *                           component remount.
 *   - gcTime: 5min          keep stale data around so navigating back to a
 *                           page shows it instantly while a refetch runs.
 *   - retry: 1              retry once on network blips, don't keep hammering
 *                           on a real 4xx/5xx (TanStack defaults to 3).
 *   - refetchOnWindowFocus  true by default; this is exactly what we want
 *                           for the post-payment "I just paid, refresh my
 *                           tier" UX.
 *
 * The query- and mutation-cache `onError` hooks centralize admin session-
 * expired handling so every admin page (current and future) gets the right
 * redirect behavior without per-page boilerplate.
 */
export const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error, query) => {
      if (
        error instanceof ApiCallError &&
        error.status === 401 &&
        isAdminQueryKey(query.queryKey)
      ) {
        redirectToAdminLoginIfNeeded();
      }
    },
  }),
  mutationCache: new MutationCache({
    onError: (error, _vars, _ctx, mutation) => {
      if (!(error instanceof ApiCallError) || error.status !== 401) return;
      // Mutations don't have a query-key, but they sit on admin pages whose
      // queries do. Use the page path as the discriminator instead.
      if (typeof window !== 'undefined' && window.location.pathname.startsWith('/admin')) {
        redirectToAdminLoginIfNeeded();
      }
      // `mutation` is referenced for future per-mutation discrimination if
      // we ever need it (e.g. exempt specific mutations from auto-redirect).
      void mutation;
    },
  }),
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      retry: 1,
      refetchOnWindowFocus: true,
    },
    mutations: {
      retry: 0,
    },
  },
});
