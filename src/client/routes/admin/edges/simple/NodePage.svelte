<script lang="ts">
  /**
   * `/admin/edges/nodes/:slug`. A backend node has ONE page, its Servers node
   * page (machine, activation and these edges together): this address
   * redirects there, keeping `?test=<edgeId>` (`nodeHomeOf`). An origin that is
   * not a backend node (manual, a whole Outline server) has no Servers page,
   * so its edges panel is shown here.
   */
  import { ApiCallError } from '@client/lib/api';
  import { countryName } from '@client/lib/countries';
  import { relayLookupQuery } from '@client/lib/edgesApi';
  import { serverSummaryQuery, serverTreeQuery } from '@client/lib/serversApi';
  import { router } from '@client/stores/router.svelte';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { instanceSlugOf, nodeHomeOf } from '../../servers/lib/routes';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import NodeEdgesPanel from './NodeEdgesPanel.svelte';

  interface Props {
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
  const target = $derived(
    relay
      ? nodeHomeOf(
          relay.origin,
          summary.data?.instances,
          tree.data?.nodes,
          new URLSearchParams(router.search).get('test') ?? undefined,
        )
      : null,
  );
  // Still finding out where a backend node lives (or about to move there).
  const resolving = $derived(
    !!panelNode && (!!target || summary.isPending || (!panelNode.nodeUuid && tree.isLoading)),
  );
  $effect(() => {
    if (target) router.navigate(target, { replace: true });
  });
  const back = { href: edgesPaths.home(), label: 'Edges' };
</script>

{#if notFound}
  <SectionHeader title="Node not found" {back} />
  <p class="text-muted-foreground text-sm">
    There is no protected node called "{slug}". It may have been removed, or the link is old.
  </p>
{:else if !relay || resolving}
  <SectionHeader title={slug} {back} />
  {#if relayQ.error}
    <NodeEdgesPanel {slug} />
  {:else}
    <div class="space-y-3"><Skeleton class="h-6 w-72" /><Skeleton class="h-32 w-full" /></div>
  {/if}
{:else}
  <SectionHeader
    title={relay.label ?? (panelNode ? panelNode.nodeName : relay.slug)}
    description={relay.locationCode ? countryName(relay.locationCode, 'en') : undefined}
    {back}
  />
  <NodeEdgesPanel {slug} />
{/if}
