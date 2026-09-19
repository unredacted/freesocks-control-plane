<script lang="ts">
  /**
   * Dispatches `/admin/edges/...` to its page with `matchRoute`. App.svelte keys
   * the route on the pathname, so a path change remounts the page and a
   * search-only change (`?tab=`, `?edge=`) does not: pages keep their view state
   * in the query string through `searchParam` (lib/urlState.svelte.ts).
   *
   * Every page sits under the in-page header (Nodes | Providers | Advanced).
   * Routes: see EDGES_ROUTES in ./lib/routes.ts (the single list of patterns).
   */
  import { router } from '../../../stores/router.svelte';
  import Link from '../../../components/Link.svelte';
  import * as Card from '@client/components/ui/card';
  import { resolveEdgesRoute, edgesPaths, sectionTabOf } from './lib/routes';
  import SectionNav from './components/SectionNav.svelte';
  import EdgesHome from './simple/EdgesHome.svelte';
  import NodePage from './simple/NodePage.svelte';
  import EdgesAdvanced from './simple/EdgesAdvanced.svelte';
  import EdgesOverview from './EdgesOverview.svelte';
  import EdgesSetup from './EdgesSetup.svelte';
  import RelayPage from './RelayPage.svelte';
  import EdgesProviders from './EdgesProviders.svelte';
  import ProviderAccountPage from './ProviderAccountPage.svelte';
  import EdgesTemplates from './EdgesTemplates.svelte';
  import EdgesProbes from './EdgesProbes.svelte';
  import EdgesSettings from './EdgesSettings.svelte';
  import NamesHome from './names/NamesHome.svelte';
  import FamilyPage from './names/FamilyPage.svelte';

  const route = $derived(resolveEdgesRoute(router.pathname));
</script>

<SectionNav current={sectionTabOf(route)} />

{#if route.page === 'home'}
  <EdgesHome />
{:else if route.page === 'node'}
  <NodePage slug={route.slug} />
{:else if route.page === 'advanced'}
  <EdgesAdvanced />
{:else if route.page === 'overview'}
  <EdgesOverview />
{:else if route.page === 'setup'}
  <EdgesSetup />
{:else if route.page === 'relay'}
  <RelayPage slug={route.slug} />
{:else if route.page === 'providers'}
  <EdgesProviders />
{:else if route.page === 'provider'}
  <ProviderAccountPage id={route.id} />
{:else if route.page === 'templates'}
  <EdgesTemplates />
{:else if route.page === 'probes'}
  <EdgesProbes />
{:else if route.page === 'settings'}
  <EdgesSettings />
{:else if route.page === 'names'}
  <NamesHome />
{:else if route.page === 'family'}
  <FamilyPage slug={route.slug} />
{:else}
  <Card.Root class="mx-auto mt-10 max-w-md">
    <Card.Header>
      <Card.Title>Page not found</Card.Title>
      <Card.Description>
        There is no Edges page at this address. It may have been renamed, or the link is incomplete.
      </Card.Description>
    </Card.Header>
    <Card.Content>
      <Link href={edgesPaths.home()} class="text-primary text-sm underline underline-offset-4">
        Back to the nodes
      </Link>
    </Card.Content>
  </Card.Root>
{/if}
