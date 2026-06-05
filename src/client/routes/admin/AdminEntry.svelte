<script lang="ts">
  import { Card, CardHeader, CardTitle, CardDescription } from '@client/components/ui/card';
  import AdminLogin from './AdminLogin.svelte';
  import AdminBootstrap from './AdminBootstrap.svelte';
  import { adminAuthStatusQuery, queryKeys } from '../../lib/queries';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { router } from '../../stores/router.svelte';

  /**
   * Smart entry point for `/admin`. Calls the unauthenticated status endpoint
   * on mount and renders one of:
   *   - Redirect to `/admin/tiers`, if the caller already has a valid admin
   *     session (`signedIn: true`). No reason to show the login form when
   *     the user is already authenticated; bouncing them straight to the
   *     admin app is what they expect.
   *   - Bootstrap form, if no admin has a registered passkey yet
   *   - Login form, if at least one admin exists
   *   - Locked-out message, if no admin exists AND ADMIN_BOOTSTRAP_SECRET isn't set
   */
  const status = adminAuthStatusQuery();
  const qc = useQueryClient();

  // Auto-redirect signed-in admins. Use the router's navigate (pushState)
  // rather than window.location so the SPA's transition fades the new
  // route in instead of doing a hard reload. `replace: true` rewrites the
  // history entry so the back button doesn't bounce the user to /admin
  // again (which would just redirect once more).
  $effect(() => {
    if (status.data?.signedIn && router.pathname === '/admin') {
      router.navigate('/admin/tiers', { replace: true });
    }
  });

  // After bootstrap completes, AdminBootstrap calls onComplete — we
  // invalidate the status query so it re-fetches and the SPA flips to the
  // login screen automatically.
  function refresh() {
    void qc.invalidateQueries({ queryKey: queryKeys.adminAuthStatus });
  }
</script>

{#if status.isError}
  <div class="max-w-md mx-auto py-12">
    <Card>
      <CardHeader>
        <CardTitle>Admin unavailable</CardTitle>
        <CardDescription class="text-destructive">
          {status.error instanceof Error ? status.error.message : String(status.error)}
        </CardDescription>
      </CardHeader>
    </Card>
  </div>
{:else if status.isPending || !status.data || status.data.signedIn}
  <!--
    Render a neutral loading state while:
      a) the initial status fetch is in flight, or
      b) the caller is already signed in and the $effect above is about to
         navigate them to /admin/tiers — showing the login form for the few
         frames before the redirect lands would be jarring.
  -->
  <div class="max-w-md mx-auto py-12 text-muted-foreground text-center">Loading…</div>
{:else if status.data.hasAdmins}
  <AdminLogin />
{:else if status.data.bootstrapAvailable}
  <AdminBootstrap onComplete={refresh} />
{:else}
  <div class="max-w-md mx-auto py-12">
    <Card>
      <CardHeader>
        <CardTitle>Admin not configured</CardTitle>
        <CardDescription>
          No admin account exists yet, and <code>ADMIN_BOOTSTRAP_SECRET</code> isn't set on this
          deployment. Set the secret with
          <code>wrangler secret put ADMIN_BOOTSTRAP_SECRET</code>{' '}and reload this page.
        </CardDescription>
      </CardHeader>
    </Card>
  </div>
{/if}
