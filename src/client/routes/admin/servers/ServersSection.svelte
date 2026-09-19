<script lang="ts">
  /**
   * Admin -> Servers section shell: the admin chrome plus the section's page.
   * AdminRouter lazy-imports this file for every `/admin/servers` path, so the
   * section is one chunk outside the main admin bundle. Routes: lib/routes.ts.
   */
  import { router } from '@client/stores/router.svelte';
  import AdminLayout from '../AdminLayout.svelte';
  import NodePage from './NodePage.svelte';
  import ServersHome from './ServersHome.svelte';
  import { resolveServersRoute } from './lib/routes';

  const route = $derived(resolveServersRoute(router.pathname));
</script>

<AdminLayout>
  {#if route.page === 'node'}
    <NodePage uuid={route.uuid} />
  {:else}
    <ServersHome />
  {/if}
</AdminLayout>
