<script lang="ts">
  /**
   * P1-18: all admin routes live behind this single component, which App.svelte
   * lazy-loads (dynamic import) only when the path starts with /admin. That keeps
   * the entire admin CMS out of the public entry bundle - public visitors on
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
  import AdminRemnawave from './AdminRemnawave.svelte';
  import AdminConnectionModes from './AdminConnectionModes.svelte';
  import AdminStatus from './AdminStatus.svelte';
  import AdminStorage from './AdminStorage.svelte';
  import AdminClients from './AdminClients.svelte';
  import AdminMembershipCodes from './AdminMembershipCodes.svelte';
  import AdminBilling from './AdminBilling.svelte';
  import AdminRateLimits from './AdminRateLimits.svelte';
  import AdminTelemetry from './AdminTelemetry.svelte';
  import AdminTheme from './AdminTheme.svelte';
  import Link from '../../components/Link.svelte';
  import { adminAuthStatusQuery, adminStatusQuery } from '../../lib/queries';

  // Routes that don't require an admin session: /admin (the smart entry point,
  // which shows login/bootstrap itself) and /admin/register (the invite landing,
  // gated by its own token). Everything else renders authed chrome + fires
  // authed queries, so we probe the auth-status query first and hold a neutral
  // loading state until `signedIn` is known.
  //
  // Before this gate, deep-linking to /admin/users while signed out rendered the
  // full AdminLayout, fired authed queries, then bounced on the reactive 401
  // (query-client.ts) - a chrome-flash. The bounce there stays as the backstop
  // (e.g. an expired session mid-session); this just avoids the flash on the
  // common signed-out deep-link path.
  const PUBLIC_ADMIN_PATHS = new Set(['/admin', '/admin/register']);
  let needsAuth = $derived(!PUBLIC_ADMIN_PATHS.has(router.pathname));

  const authStatus = adminAuthStatusQuery();
  // PoP-signed probe: the auth-status check is cookie-only, so a signed-in-
  // but-PoP-broken session (Workers blocked, POP_REQUIRED on) would otherwise
  // flash the full CMS chrome + fire authed queries until the 401 backstop.
  // Hold until the signed read resolves; a 401 here bounces via the global
  // admin handler in query-client.ts (same backstop, no flash).
  const popProbe = adminStatusQuery();
  let holdForPop = $derived(needsAuth && !!authStatus.data?.signedIn && popProbe.isPending);

  // Admin -> Edges: one prefix branch, its own lazy chunk. EdgesRouter dispatches
  // the sub-paths with matchRoute.
  const EdgesSection = () => import('./edges/EdgesSection.svelte');
  let onEdgesRoute = $derived(
    router.pathname === '/admin/edges' || router.pathname.startsWith('/admin/edges/'),
  );

  // Probes moved from Telemetry into the Edges section; keep old links working.
  $effect(() => {
    if (router.pathname === '/admin/telemetry/probes') {
      router.navigate(`/admin/edges/probes${router.search}`, { replace: true });
    }
  });

  // Bounce signed-out deep-links to /admin (which renders the login/bootstrap
  // flow). `replace: true` so the back button doesn't re-enter the guarded path.
  $effect(() => {
    if (needsAuth && authStatus.data && !authStatus.data.signedIn) {
      router.navigate('/admin', { replace: true });
    }
  });
</script>

{#if needsAuth && (authStatus.isPending || !authStatus.data || holdForPop)}
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
{:else if router.pathname === '/admin/remnawave'}
  <AdminRemnawave />
{:else if router.pathname === '/admin/connection-modes'}
  <AdminConnectionModes />
{:else if onEdgesRoute}
  <!-- Admin -> Edges is its own lazy chunk (section shell + every edges page). -->
  {#await EdgesSection()}
    <div class="max-w-md mx-auto py-12 text-muted-foreground text-center">Loading Edges…</div>
  {:then mod}
    {@const Edges = mod.default}
    <Edges />
  {:catch}
    <div class="text-center py-16 space-y-3">
      <h1 class="text-xl font-display font-bold">The Edges section did not load</h1>
      <p class="text-sm text-muted-foreground">
        The connection dropped or a new version was deployed. Reload to try again.
      </p>
      <button type="button" class="text-primary underline" onclick={() => window.location.reload()}>
        Reload
      </button>
    </div>
  {/await}
{:else if router.pathname === '/admin/status'}
  <AdminStatus />
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
{:else if router.pathname === '/admin/telemetry'}
  <AdminTelemetry view="reports" />
{:else if router.pathname === '/admin/telemetry/probes'}
  <!-- Moved: the $effect above is replacing the URL with /admin/edges/probes. -->
  <div class="max-w-md mx-auto py-12 text-muted-foreground text-center">Loading…</div>
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
