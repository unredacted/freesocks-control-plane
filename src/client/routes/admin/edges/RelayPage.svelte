<script lang="ts">
  /**
   * One relay (`/admin/edges/relays/:slug`). URL state: `?tab`
   * overview|edges|listeners|rotations|probes, `?edge` (edge drawer), `?rotation`
   * (rotation drawer), `?listener` (the listener card to scroll to / edit).
   *
   * The page resolves the slug to the relay (id) once and hands the relay, its
   * listeners, its edges and the provider accounts to the tabs in `relay/`.
   * Both drawers live here so every tab can open them through the URL.
   */
  import { ApiCallError } from '@client/lib/api';
  import { Badge } from '@client/components/ui/badge';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as Tabs from '@client/components/ui/tabs';
  import * as Card from '@client/components/ui/card';
  import Link from '@client/components/Link.svelte';
  import {
    providersQuery,
    relayEdgesQuery,
    relayListenersQuery,
    relayLookupQuery,
  } from '@client/lib/edgesApi';
  import { searchParam, setSearchParams } from '@client/lib/urlState.svelte';
  import type { EdgeLayer } from '@shared/contracts/edges';
  import AdminListState from '../AdminListState.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import StatusBadge from './components/StatusBadge.svelte';
  import LayerBadge from './components/LayerBadge.svelte';
  import EdgeDetailDrawer from './components/EdgeDetailDrawer.svelte';
  import RotationDrawer from './components/RotationDrawer.svelte';
  import { edgesPaths, RELAY_TABS, type RelayTab } from './lib/routes';
  import { suspicionChip } from './relay/relayLogic';
  import RelayActionsMenu from './relay/RelayActionsMenu.svelte';
  import OverviewTab from './relay/OverviewTab.svelte';
  import EdgesTab from './relay/EdgesTab.svelte';
  import ListenersTab from './relay/ListenersTab.svelte';
  import RotationsTab from './relay/RotationsTab.svelte';
  import ProbesTab from './relay/ProbesTab.svelte';
  import EdgeActionsMenu from './relay/EdgeActionsMenu.svelte';

  interface Props {
    /** The relay slug from the route (`/admin/edges/relays/:slug`). */
    slug: string;
  }
  let { slug }: Props = $props();

  const relayQ = relayLookupQuery(() => slug);
  const relay = $derived(relayQ.data ?? null);
  const ref = {
    slug: () => slug,
    id: () => relay?.id ?? null,
    rotating: () => !!relay?.activeRotationId,
  };
  const listenersQ = relayListenersQuery(ref);
  const edgesQ = relayEdgesQuery(ref);
  const providersQ = providersQuery();

  const listeners = $derived(listenersQ.data?.listeners ?? []);
  const edges = $derived(edgesQ.data ?? []);
  const accounts = $derived(providersQ.data?.accounts ?? []);

  const tabParam = searchParam('tab', 'overview');
  const edgeParam = searchParam('edge');
  const rotationParam = searchParam('rotation');
  const tab = $derived<RelayTab>(
    (RELAY_TABS as readonly string[]).includes(tabParam.value)
      ? (tabParam.value as RelayTab)
      : 'overview',
  );

  const notFound = $derived(relayQ.error instanceof ApiCallError && relayQ.error.status === 404);

  const layers = $derived.by((): EdgeLayer[] => {
    const set = new Set<EdgeLayer>();
    for (const l of listeners) if (!l.retired) for (const layer of l.layers) set.add(layer);
    for (const e of edges) if (e.publication !== 'unpublished') set.add(e.layer);
    return (['l4', 'l7'] as const).filter((l) => set.has(l));
  });

  const relayState = $derived.by(
    (): { value: string; label: string; tone: 'success' | 'danger' | 'info' | 'muted' } => {
      if (!relay) return { value: 'unknown', label: 'Loading', tone: 'muted' };
      if (relay.deleting) return { value: 'deleting', label: 'Being deleted', tone: 'danger' };
      if (relay.quarantine) return { value: 'quarantined', label: 'Quarantined', tone: 'danger' };
      if (relay.activeRotationId)
        return { value: 'rotating', label: 'Rotation running', tone: 'info' };
      if (!relay.enabled) return { value: 'disabled', label: 'Disabled', tone: 'muted' };
      return { value: 'enabled', label: 'Enabled', tone: 'success' };
    },
  );
  const chip = $derived(suspicionChip(relay?.suspicion));

  const openEdge = (edgeId: string): void => setSearchParams({ edge: edgeId, rotation: null });
  const openRotation = (rotationId: string): void =>
    setSearchParams({ rotation: rotationId, edge: null });
</script>

{#if notFound}
  <SectionHeader
    title="Relay not found"
    back={{ href: edgesPaths.overview(), label: 'Edges overview' }}
  />
  <Card.Root>
    <Card.Header>
      <Card.Title>There is no relay called "{slug}"</Card.Title>
      <Card.Description>
        It may have been deleted, or the address was mistyped. The overview lists every relay, and
        the guided setup registers a new one.
      </Card.Description>
    </Card.Header>
    <Card.Content class="flex flex-wrap gap-4 text-sm">
      <Link href={edgesPaths.overview()} class="font-medium text-primary hover:underline">
        Go to the Edges overview
      </Link>
      <Link href={edgesPaths.setup()} class="font-medium text-primary hover:underline">
        Start the guided setup
      </Link>
    </Card.Content>
  </Card.Root>
{:else if relayQ.error && !relay}
  <SectionHeader
    title={`Relay ${slug}`}
    back={{ href: edgesPaths.overview(), label: 'Edges overview' }}
  />
  <AdminListState error={relayQ.error} onRetry={() => void relayQ.refetch()} />
{:else if !relay}
  <SectionHeader
    title={`Relay ${slug}`}
    back={{ href: edgesPaths.overview(), label: 'Edges overview' }}
  />
  <div class="space-y-3">
    <Skeleton class="h-9 w-80" />
    <Skeleton class="h-40 w-full" />
    <Skeleton class="h-40 w-full" />
  </div>
{:else}
  <SectionHeader
    title={relay.label ? `${relay.label} (${relay.slug})` : `Relay ${relay.slug}`}
    description="One origin behind edges: its pool, its listeners, its rotations and how reachable it is."
    back={{ href: edgesPaths.overview(), label: 'Edges overview' }}
  >
    {#snippet badges()}
      <StatusBadge
        kind="status"
        value={relayState.value}
        label={relayState.label}
        tone={relayState.tone}
      />
      {#each layers as layer (layer)}
        <LayerBadge {layer} />
      {/each}
      {#if !relay.autoRotate}
        <Badge variant="muted" title="The block detector never rotates this relay on its own."
          >Auto rotate off</Badge
        >
      {/if}
      {#if chip}
        <Badge variant={chip.tone} title={chip.title}>{chip.label}</Badge>
      {/if}
    {/snippet}
    {#snippet actions()}
      <RelayActionsMenu
        {relay}
        {listeners}
        edgeCount={edges.filter((e) => e.status !== 'destroyed').length}
        onRotationStarted={openRotation}
      />
    {/snippet}
  </SectionHeader>

  <Tabs.Root value={tab} onValueChange={(v) => (tabParam.value = v)}>
    <Tabs.List>
      <Tabs.Trigger value="overview">Overview</Tabs.Trigger>
      <Tabs.Trigger value="edges">Edges ({edges.length})</Tabs.Trigger>
      <Tabs.Trigger value="listeners">
        Listeners ({listeners.filter((l) => !l.retired).length})
      </Tabs.Trigger>
      <Tabs.Trigger value="rotations">Rotations</Tabs.Trigger>
      <Tabs.Trigger value="probes">Probes</Tabs.Trigger>
    </Tabs.List>

    <!-- Only the active tab is mounted: each one owns queries that should not poll in the background. -->
    {#if tab === 'overview'}
      <OverviewTab
        {relay}
        {edges}
        {listeners}
        connectionPlan={listenersQ.data?.connectionPlan ?? []}
        onOpenEdge={openEdge}
        onOpenRotation={openRotation}
      />
    {:else if tab === 'edges'}
      <EdgesTab
        {relay}
        {edges}
        {listeners}
        {accounts}
        loading={edgesQ.isPending}
        error={edgesQ.error}
        onRetry={() => void edgesQ.refetch()}
        onOpenEdge={openEdge}
        onRotationStarted={openRotation}
      />
    {:else if tab === 'listeners'}
      <ListenersTab
        {relay}
        {listeners}
        {edges}
        hostsPlan={listenersQ.data?.hostsPlan ?? null}
        loading={listenersQ.isPending}
        error={listenersQ.error}
        onRetry={() => void listenersQ.refetch()}
      />
    {:else if tab === 'rotations'}
      <RotationsTab {relay} onOpenRotation={openRotation} />
    {:else}
      <ProbesTab {relay} {edges} />
    {/if}
  </Tabs.Root>

  <EdgeDetailDrawer edgeId={edgeParam.value || null} onClose={() => (edgeParam.value = null)}>
    {#snippet actions(edge)}
      <EdgeActionsMenu {relay} {edge} variant="drawer" onRotationStarted={openRotation} />
    {/snippet}
  </EdgeDetailDrawer>
  <RotationDrawer
    rotationId={rotationParam.value || null}
    relaySlug={relay.slug}
    relayId={relay.id}
    onClose={() => (rotationParam.value = null)}
    onOpenEdge={openEdge}
  />
{/if}
