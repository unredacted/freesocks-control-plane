<script lang="ts">
  /**
   * P1-18: all admin routes live behind this single component, which App.svelte
   * lazy-loads (dynamic import) only when the path starts with /admin. That keeps
   * the entire admin CMS out of the public entry bundle — public visitors on
   * slow/censored links never download admin code.
   */
  import { router } from '../../stores/router.svelte';
  import AdminEntry from './AdminEntry.svelte';
  import AdminRegister from './AdminRegister.svelte';
  import AdminAdmins from './AdminAdmins.svelte';
  import AdminTiers from './AdminTiers.svelte';
  import AdminUsers from './AdminUsers.svelte';
  import AdminTokens from './AdminTokens.svelte';
  import AdminAudit from './AdminAudit.svelte';
  import AdminSettings from './AdminSettings.svelte';
  import AdminBackendServers from './AdminBackendServers.svelte';
  import AdminMembershipCodes from './AdminMembershipCodes.svelte';
  import AdminBilling from './AdminBilling.svelte';
  import AdminRateLimits from './AdminRateLimits.svelte';
  import Link from '../../components/Link.svelte';
</script>

{#if router.pathname === '/admin'}
  <AdminEntry />
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
{:else}
  <div class="text-center py-16">
    <h1 class="text-3xl font-display font-bold mb-2">Not found</h1>
    <Link href="/admin" class="text-primary underline">Admin home</Link>
  </div>
{/if}
