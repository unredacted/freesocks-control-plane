<script lang="ts">
  /**
   * P1-18: all admin routes live behind this single component, which App.svelte
   * lazy-loads (dynamic import) only when the path starts with /admin. That keeps
   * the entire admin CMS out of the public entry bundle — public visitors on
   * slow/censored links never download admin code.
   */
  import { router } from '../../stores/router.svelte';
  import AdminEntry from './AdminEntry.svelte';
  import AdminDashboard from './AdminDashboard.svelte';
  import AdminRegister from './AdminRegister.svelte';
  import AdminAdmins from './AdminAdmins.svelte';
  import AdminTiers from './AdminTiers.svelte';
  import AdminUsers from './AdminUsers.svelte';
  import AdminTokens from './AdminTokens.svelte';
  import AdminAudit from './AdminAudit.svelte';
  import AdminSettings from './AdminSettings.svelte';
  import AdminBackendServers from './AdminBackendServers.svelte';
  import AdminStorage from './AdminStorage.svelte';
  import AdminClients from './AdminClients.svelte';
  import AdminMembershipCodes from './AdminMembershipCodes.svelte';
  import AdminBilling from './AdminBilling.svelte';
  import AdminRateLimits from './AdminRateLimits.svelte';
  import AdminTheme from './AdminTheme.svelte';
  import Link from '../../components/Link.svelte';
  import { adminAuthStatusQuery } from '../../lib/queries';

  // Routes that don't require an admin session: /admin (the smart entry point,
  // which shows login/bootstrap itself) and /admin/register (the invite landing,
  // gated by its own token). Everything else renders authed chrome + fires
  // authed queries, so we probe the auth-status query first and hold a neutral
  // loading state until `signedIn` is known.
  //
  // Before this gate, deep-linking to /admin/users while signed out rendered the
  // full AdminLayout, fired authed queries, then bounced on the reactive 401
  // (query-client.ts) — a chrome-flash. The bounce there stays as the backstop
  // (e.g. an expired session mid-session); this just avoids the flash on the
  // common signed-out deep-link path.
  const PUBLIC_ADMIN_PATHS = new Set(['/admin', '/admin/register']);
  let needsAuth = $derived(!PUBLIC_ADMIN_PATHS.has(router.pathname));

  const authStatus = adminAuthStatusQuery();

  // Bounce signed-out deep-links to /admin (which renders the login/bootstrap
  // flow). `replace: true` so the back button doesn't re-enter the guarded path.
  $effect(() => {
    if (needsAuth && authStatus.data && !authStatus.data.signedIn) {
      router.navigate('/admin', { replace: true });
    }
  });
</script>

{#if needsAuth && (authStatus.isPending || !authStatus.data)}
  <!--
    Hold a neutral loading state until the auth-status probe resolves, so a
    signed-out deep-link never flashes the authed chrome before bouncing.
  -->
  <div class="max-w-md mx-auto py-12 text-muted-foreground text-center">Loading…</div>
{:else if needsAuth && !authStatus.data?.signedIn}
  <!-- Signed out: the $effect above is navigating to /admin; render the entry meanwhile. -->
  <AdminEntry />
{:else if router.pathname === '/admin'}
  <AdminEntry />
{:else if router.pathname === '/admin/dashboard'}
  <AdminDashboard />
{:else if router.pathname === '/admin/register'}
  <!-- Invite landing: no session yet, gated by the invite token in the URL. -->
  <AdminRegister />
{:else if router.pathname === '/admin/admins'}
  <AdminAdmins />
{:else if router.pathname === '/admin/tiers'}
  <AdminTiers />
{:else if router.pathname === '/admin/users'}
  <AdminUsers />
{:else if router.pathname === '/admin/tokens'}
  <AdminTokens />
{:else if router.pathname === '/admin/backend-servers'}
  <AdminBackendServers />
{:else if router.pathname === '/admin/storage'}
  <AdminStorage />
{:else if router.pathname === '/admin/clients'}
  <AdminClients />
{:else if router.pathname === '/admin/membership-codes'}
  <AdminMembershipCodes />
{:else if router.pathname === '/admin/billing'}
  <AdminBilling />
{:else if router.pathname === '/admin/rate-limits'}
  <AdminRateLimits />
{:else if router.pathname === '/admin/audit'}
  <AdminAudit />
{:else if router.pathname === '/admin/settings'}
  <AdminSettings />
{:else if router.pathname === '/admin/theme'}
  <AdminTheme />
{:else}
  <div class="text-center py-16">
    <h1 class="text-3xl font-display font-bold mb-2">Not found</h1>
    <Link href="/admin" class="text-primary underline">Admin home</Link>
  </div>
{/if}
