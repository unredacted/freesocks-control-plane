<script lang="ts">
  /**
   * Admin -> Servers section shell: the admin chrome, the tab bar
   * (components/ServersNav.svelte) and the page. AdminRouter lazy-imports this
   * file for every `/admin/servers` path (and first replaces any moved address,
   * lib/legacyRoutes.ts), so the section is one chunk outside the main admin
   * bundle. The section's own pages are picked here; the pages that came from
   * the old Edges section are picked by ../edges/EdgesPages.svelte.
   * Routes: lib/routes.ts and ../edges/lib/routes.ts.
   */
  import { serverSummaryQuery } from '@client/lib/serversApi';
  import { router } from '@client/stores/router.svelte';
  import AdminLayout from '../AdminLayout.svelte';
  import EdgesPages from '../edges/EdgesPages.svelte';
  import BackendsPage from './BackendsPage.svelte';
  import NodePage from './NodePage.svelte';
  import PoolsPage from './PoolsPage.svelte';
  import ServersHome from './ServersHome.svelte';
  import ServersNav from './components/ServersNav.svelte';
  import SettingsNav from './components/SettingsNav.svelte';
  import { backendOf, resolveSectionRoute, tabOf } from './lib/routes';

  const section = $derived(resolveSectionRoute(router.pathname));
  const summary = serverSummaryQuery();
  // The Nodes tab keeps the backend server the URL names (none: every backend).
  const backend = $derived(backendOf(router.search, summary.data?.instances ?? []) ?? undefined);
</script>

<AdminLayout>
  <ServersNav current={tabOf(section)} {backend} />
  <!-- Every control 44px tall on a phone (globals.css `.touch-44`). -->
  <div class="touch-44">
    {#if section.from === 'edges'}
      <EdgesPages route={section.route} />
    {:else if section.route.page === 'node'}
      <NodePage uuid={section.route.uuid} />
    {:else if section.route.page === 'backends'}
      <SettingsNav current="backends" />
      <BackendsPage />
    {:else if section.route.page === 'pools'}
      <SettingsNav current="pools" />
      <PoolsPage />
    {:else}
      <ServersHome />
    {/if}
  </div>
</AdminLayout>
