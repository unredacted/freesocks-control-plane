<script lang="ts">
  /**
   * An origin's technical details: everything the old origin page held, now
   * inside the "Technical details" fold of the node's page (a backend node's
   * `/admin/servers/nodes/:uuid`, an origin added by hand's
   * `/admin/servers/origins/:slug`). URL state: `?tab`
   * overview|edges|listeners|rotations|probes, `?edge` (edge drawer),
   * `?rotation` (rotation drawer), `?listener` (the listener card to scroll to /
   * edit). The node page opens the fold whenever one of them is set.
   *
   * One row of badges (state, layers, auto rotate, the detector) with the
   * Actions menu, the first-edge card for an origin that is not a backend node
   * and has no edge yet (FirstEdgeCard), then the tabs in `./`. The Overview
   * tab leaves out the quarantine resolver and the deleting and rotation
   * notices: the node page shows them in Summary (OriginNotices.svelte). Both
   * drawers live here so every tab can open them through the URL.
   *
   * Props: slug (the origin's)
   */
  import { Badge } from '@client/components/ui/badge';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AdminListState from '../../AdminListState.svelte';
  import * as Tabs from '@client/components/ui/tabs';
  import {
    providersQuery,
    relayEdgesQuery,
    relayListenersQuery,
    relayLookupQuery,
  } from '@client/lib/edgesApi';
  import { originBusy } from '@client/lib/livePoll';
  import { searchParam, setSearchParams } from '@client/lib/urlState.svelte';
  import type { EdgeLayer } from '@shared/contracts/edges';
  import StatusBadge from '../components/StatusBadge.svelte';
  import LayerBadge from '../components/LayerBadge.svelte';
  import EdgeDetailDrawer from '../components/EdgeDetailDrawer.svelte';
  import RotationDrawer from '../components/RotationDrawer.svelte';
  import { RELAY_TABS, type RelayTab } from '../lib/routes';
  import { suspicionChip } from './relayLogic';
  import RelayActionsMenu from './RelayActionsMenu.svelte';
  import OverviewTab from './OverviewTab.svelte';
  import EdgesTab from './EdgesTab.svelte';
  import ListenersTab from './ListenersTab.svelte';
  import RotationsTab from './RotationsTab.svelte';
  import ProbesTab from './ProbesTab.svelte';
  import EdgeActionsMenu from './EdgeActionsMenu.svelte';
  import FirstEdgeCard from './FirstEdgeCard.svelte';

  interface Props {
    /** The origin's slug. */
    slug: string;
  }
  let { slug }: Props = $props();

  const relayQ = relayLookupQuery(() => slug);
  const relay = $derived(relayQ.data ?? null);
  const ref = {
    slug: () => slug,
    id: () => relay?.id ?? null,
    rotating: () => !!relay && originBusy(relay),
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

  // A manual or whole-server origin with no edge yet: its first edge is given here.
  const needsFirstEdge = $derived(
    !!relay &&
      relay.origin.kind !== 'panel-node' &&
      !relay.deleting &&
      // Only a SUCCESSFUL read that lists nothing: a failed one says nothing about the edges.
      edgesQ.isSuccess &&
      edges.every((e) => e.status === 'destroyed'),
  );
  const openEdge = (edgeId: string): void => setSearchParams({ edge: edgeId, rotation: null });
  const openRotation = (rotationId: string): void =>
    setSearchParams({ rotation: rotationId, edge: null });
</script>

{#if relayQ.error && !relay}
  <AdminListState error={relayQ.error} onRetry={() => void relayQ.refetch()} />
{:else if !relay}
  <Skeleton class="h-40 w-full" />
{:else}
  <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
    <div class="flex min-w-0 flex-wrap items-center gap-2">
      <span class="font-mono text-sm">{relay.slug}</span>
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
        <Badge variant="muted" title="The block detector never rotates this origin on its own."
          >Auto rotate off</Badge
        >
      {/if}
      {#if chip}
        <Badge variant={chip.tone} title={chip.title}>{chip.label}</Badge>
      {/if}
    </div>
    <RelayActionsMenu
      {relay}
      {listeners}
      edgeCount={edges.filter((e) => e.status !== 'destroyed').length}
      onRotationStarted={openRotation}
    />
  </div>

  {#if needsFirstEdge}
    <div class="mb-6">
      <FirstEdgeCard
        {relay}
        {listeners}
        {accounts}
        onStarted={openRotation}
        onImported={openEdge}
      />
    </div>
  {/if}

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
        notices={false}
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
