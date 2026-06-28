import { MutationCache, QueryCache, QueryClient } from '@tanstack/svelte-query';
import { ApiCallError } from './api';
import { clearSessionKey } from './pop';

/**
 * When an admin query or mutation returns 401, sign the admin out and bounce to
 * `/admin` (the entry page that renders the login form). Without this, a
 * deep-link after the session expires just shows a raw "auth.invalid" inline.
 *
 * Why a full sign-out and not a bare redirect: the `/admin` entry decides
 * "already signed in?" from the COOKIE-ONLY status probe (no PoP, by design).
 * A 401 here can mean the cookie expired OR the session is PoP-bound but the
 * client can't satisfy it (e.g. a stale IndexedDB key after a deploy). A bare
 * redirect to `/admin` would see the still-valid cookie, bounce back into the
 * app, 401 again → an infinite loop. Clearing the cookie (logout endpoint) +
 * the local PoP key/token makes the probe report signed-out, so the loop breaks
 * and a fresh passkey login re-binds a new key + token.
 *
 * We discriminate "admin" requests via the query-key prefix (`['admin', …]`,
 * shared via `queryKeys.admin*` in queries.ts) for queries, and via the
 * mutation's failure path for mutations. Suppressed when already on `/admin`.
 */
function isAdminQueryKey(key: readonly unknown[]): boolean {
  return key.length > 0 && key[0] === 'admin';
}

let adminSignOutInFlight = false;
async function signOutAdminAndRedirect(): Promise<void> {
  if (typeof window === 'undefined') return;
  if (window.location.pathname === '/admin') return; // already at the login entry
  if (adminSignOutInFlight) return; // several admin queries can 401 at once
  adminSignOutInFlight = true;
  try {
    // Clear the cookie server-side so the cookie-only status probe flips to
    // signed-out (best effort — proceed even if it fails).
    await fetch('/api/admin/auth/logout', { method: 'POST', credentials: 'include' }).catch(
      () => {},
    );
    // Clear the local PoP key + per-session token so the next login binds fresh.
    await clearSessionKey('admin').catch(() => {});
  } finally {
    window.location.href = '/admin';
  }
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
        void signOutAdminAndRedirect();
      }
    },
  }),
  mutationCache: new MutationCache({
    onError: (error, _vars, _ctx, mutation) => {
      if (!(error instanceof ApiCallError) || error.status !== 401) return;
      // Mutations don't have a query-key, but they sit on admin pages whose
      // queries do. Use the page path as the discriminator instead.
      if (typeof window !== 'undefined' && window.location.pathname.startsWith('/admin')) {
        void signOutAdminAndRedirect();
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
