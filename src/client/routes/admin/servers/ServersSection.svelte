<script lang="ts">
  /**
   * Admin -> Servers section shell: the admin chrome, the tabs
   * (Backends | Nodes | Mode pools) and the section's page. AdminRouter
   * lazy-imports this file for every `/admin/servers` path (and redirects the
   * old Backend servers and Remnawave addresses here), so the section is one
   * chunk outside the main admin bundle. Routes: lib/routes.ts.
   */
  import Link from '@client/components/Link.svelte';
  import * as Card from '@client/components/ui/card';
  import { serverSummaryQuery } from '@client/lib/serversApi';
  import { router } from '@client/stores/router.svelte';
  import AdminLayout from '../AdminLayout.svelte';
  import BackendsPage from './BackendsPage.svelte';
  import NodePage from './NodePage.svelte';
  import PoolsPage from './PoolsPage.svelte';
  import ServersHome from './ServersHome.svelte';
  import ServersNav from './components/ServersNav.svelte';
  import { pickInstance, resolveServersRoute, serversPaths, serversTabOf } from './lib/routes';

  const route = $derived(resolveServersRoute(router.pathname));
  const summary = serverSummaryQuery();
  // The Nodes tab keeps the backend server the URL selects.
  const instance = $derived(
    pickInstance(router.search, summary.data?.instances ?? []) ?? undefined,
  );
</script>

<AdminLayout>
  <ServersNav current={serversTabOf(route)} {instance} />
  <!-- Every control 44px tall on a phone (globals.css `.touch-44`). -->
  <div class="touch-44">
    {#if route.page === 'node'}
      <NodePage uuid={route.uuid} />
    {:else if route.page === 'backends'}
      <BackendsPage />
    {:else if route.page === 'pools'}
      <PoolsPage />
    {:else if route.page === 'home'}
      <ServersHome />
    {:else}
      <Card.Root class="mx-auto mt-10 max-w-md">
        <Card.Header>
          <Card.Title>Page not found</Card.Title>
          <Card.Description>
            There is no Servers page at this address. It may have moved, or the link is incomplete.
          </Card.Description>
        </Card.Header>
        <Card.Content>
          <Link
            href={serversPaths.home()}
            class="text-primary text-sm underline underline-offset-4"
          >
            Back to the nodes
          </Link>
        </Card.Content>
      </Card.Root>
    {/if}
  </div>
</AdminLayout>
