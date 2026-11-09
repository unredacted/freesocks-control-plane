<script lang="ts">
  /**
   * The pages that came from the old Edges section, picked by their route
   * (../servers/ServersSection.svelte resolves it and draws the tab bar).
   * App.svelte keys the route on the pathname, so a path change remounts the
   * page and a search-only change (`?tab=`, `?edge=`) does not: pages keep
   * their view state in the query string through `searchParam`
   * (lib/urlState.svelte.ts). Routes: EDGES_ROUTES in ./lib/routes.ts.
   */
  import Link from '../../../components/Link.svelte';
  import * as Card from '@client/components/ui/card';
  import { edgesPaths, type EdgesRoute } from './lib/routes';
  import SettingsNav from '../servers/components/SettingsNav.svelte';
  import EdgesHome from './simple/EdgesHome.svelte';
  import NodePage from './simple/NodePage.svelte';
  import EdgesOverview from './EdgesOverview.svelte';
  import RelayPage from './RelayPage.svelte';
  import EdgesProviders from './EdgesProviders.svelte';
  import ProviderAccountPage from './ProviderAccountPage.svelte';
  import EdgesTemplates from './EdgesTemplates.svelte';
  import EdgesProbes from './EdgesProbes.svelte';
  import EdgesSettings from './EdgesSettings.svelte';
  import NamesHome from './names/NamesHome.svelte';
  import FamilyPage from './names/FamilyPage.svelte';
  import NamesAdvanced from './names/NamesAdvanced.svelte';
  import FindNetwork from './names/FindNetwork.svelte';
  import SnisNav from './names/SnisNav.svelte';
  import CountryChecksCard from './names/CountryChecksCard.svelte';
  import SniSettings from './names/SniSettings.svelte';
  import CountriesPage from './countries/CountriesPage.svelte';
  import CountryPage from './countries/CountryPage.svelte';
  import ListsPage from './countries/ListsPage.svelte';
  import ListPage from './countries/ListPage.svelte';

  interface Props {
    route: EdgesRoute;
  }
  let { route }: Props = $props();
</script>

{#if route.page === 'home'}
  <EdgesHome />
{:else if route.page === 'node'}
  <NodePage slug={route.slug} />
{:else if route.page === 'overview'}
  <EdgesOverview />
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
  <SettingsNav current="settings" />
  <EdgesSettings />
{:else if route.page === 'names'}
  <SnisNav current="lists" />
  <NamesHome />
{:else if route.page === 'family'}
  <FamilyPage slug={route.slug} />
{:else if route.page === 'findNames'}
  <SnisNav current="find" />
  <NamesAdvanced />
{:else if route.page === 'findNetwork'}
  {#key route.slug}<FindNetwork slug={route.slug} />{/key}
{:else if route.page === 'sniChecks'}
  <SnisNav current="checks" />
  <CountryChecksCard />
{:else if route.page === 'sniSettings'}
  <SnisNav current="settings" />
  <SniSettings />
{:else if route.page === 'countries'}
  <CountriesPage />
{:else if route.page === 'country'}
  {#key route.code}<CountryPage code={route.code} />{/key}
{:else if route.page === 'lists'}
  <ListsPage />
{:else if route.page === 'list'}
  {#key route.id}<ListPage id={route.id} />{/key}
{:else}
  <Card.Root class="mx-auto mt-10 max-w-md">
    <Card.Header>
      <Card.Title>Page not found</Card.Title>
      <Card.Description>
        There is no Servers page at this address. It may have moved, or the link is incomplete.
      </Card.Description>
    </Card.Header>
    <Card.Content>
      <Link href={edgesPaths.home()} class="text-primary text-sm underline underline-offset-4">
        Back to Overview
      </Link>
    </Card.Content>
  </Card.Root>
{/if}
