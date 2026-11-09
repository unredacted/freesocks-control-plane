<script lang="ts">
  /**
   * The old origin details address (`/admin/servers/origins/:slug/details`;
   * `/admin/edges/relays/:slug` lands here first, servers/lib/legacyRoutes.ts).
   * An origin's technical details live in the "Technical details" fold of its
   * node's page now (relay/TechnicalDetails.svelte), so this page only finds
   * that page and goes there:
   *
   *   a backend node        -> /admin/servers/nodes/:uuid?backend=<slug>&section=...
   *   an origin added by hand -> /admin/servers/origins/:slug?section=...
   *
   * The query is mapped by `detailsSearch` (servers/lib/nodeSections.ts):
   * `?tab=overview` lands on Summary, any other tab on the fold at that tab,
   * no tab on the fold; `?edge=`, `?rotation=`, `?listener=` are kept.
   *
   * Where the node is depends on the origin (its backend, its node uuid, or
   * for an origin made before uuids were recorded its node name in the
   * backend's tree), so the redirect needs these lookups at runtime and lives
   * here, not in the pure legacy table (as simple/NodePage.svelte does for
   * `/admin/servers/origins/:slug`). A backend node whose page cannot be found
   * (its backend is gone) keeps its technical details here, so nothing is lost.
   */
  import { untrack } from 'svelte';
  import { ApiCallError } from '@client/lib/api';
  import * as Card from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { relayLookupQuery } from '@client/lib/edgesApi';
  import { serverSummaryQuery, serverTreeQuery } from '@client/lib/serversApi';
  import { setSearchParams } from '@client/lib/urlState.svelte';
  import { router } from '@client/stores/router.svelte';
  import { instanceSlugOf, nodeHomeOf, serversPaths } from '../servers/lib/routes';
  import { detailsSearch, joinSearch } from '../servers/lib/nodeSections';
  import SectionHeader from './components/SectionHeader.svelte';
  import { edgesPaths } from './lib/routes';
  import OriginNotices from './relay/OriginNotices.svelte';
  import TechnicalDetails from './relay/TechnicalDetails.svelte';

  interface Props {
    /** The origin slug from the route (`/admin/servers/origins/:slug/details`). */
    slug: string;
  }
  let { slug }: Props = $props();

  const relayQ = relayLookupQuery(() => slug);
  const relay = $derived(relayQ.data ?? null);
  const notFound = $derived(relayQ.error instanceof ApiCallError && relayQ.error.status === 404);
  const panelNode = $derived(relay?.origin.kind === 'panel-node' ? relay.origin : null);
  const summary = serverSummaryQuery();
  // An origin made before node uuids were recorded: its node is found by name.
  const tree = serverTreeQuery(() =>
    panelNode && !panelNode.nodeUuid
      ? instanceSlugOf(summary.data?.instances, panelNode.backendServerId)
      : null,
  );
  const home = $derived(
    !relay
      ? null
      : panelNode
        ? nodeHomeOf(relay.origin, summary.data?.instances, tree.data?.nodes)
        : edgesPaths.node(relay.slug),
  );
  // Still finding out where the node lives (or about to move there).
  const resolving = $derived(
    !relay ||
      !!home ||
      (!!panelNode && (summary.isPending || (!panelNode.nodeUuid && tree.isLoading))),
  );
  // Once: the move changes the address this page would read again.
  let moved = false;
  $effect(() => {
    if (!home || moved) return;
    moved = true;
    router.navigate(joinSearch(home, detailsSearch(untrack(() => router.search))), {
      replace: true,
    });
  });
  const back = { href: serversPaths.nodes(), label: 'Nodes' };
</script>

{#if notFound}
  <SectionHeader title="Origin not found" {back} />
  <Card.Root>
    <Card.Header>
      <Card.Title>There is no origin called "{slug}"</Card.Title>
      <Card.Description>It may have been deleted, or the address is mistyped.</Card.Description>
    </Card.Header>
    <Card.Content class="flex flex-wrap gap-4 text-sm">
      <Link href={serversPaths.nodes()} class="text-primary font-medium hover:underline">
        Go to Nodes
      </Link>
      <Link
        href={edgesPaths.overview({ new: '1' })}
        class="text-primary font-medium hover:underline"
      >
        Add an origin by hand
      </Link>
    </Card.Content>
  </Card.Root>
{:else if relayQ.error && !relay}
  <SectionHeader title={`Origin ${slug}`} {back} />
  <TechnicalDetails {slug} />
{:else if resolving || !relay}
  <SectionHeader title={`Origin ${slug}`} {back} />
  <div class="space-y-3">
    <Skeleton class="h-9 w-80" />
    <Skeleton class="h-40 w-full" />
  </div>
{:else}
  <!-- A backend node whose page is not known: its technical details stay here. -->
  <SectionHeader
    title={relay.label ? `${relay.label} (${relay.slug})` : `Origin ${relay.slug}`}
    description="Its node's page could not be found, so its technical details are shown here."
    {back}
  />
  <div class="mb-6 space-y-4">
    <OriginNotices
      {relay}
      onOpenEdge={(edgeId) => setSearchParams({ edge: edgeId, rotation: null })}
      onOpenRotation={(rotationId) => setSearchParams({ rotation: rotationId, edge: null })}
    />
  </div>
  <TechnicalDetails {slug} />
{/if}
