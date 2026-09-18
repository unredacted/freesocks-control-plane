<script lang="ts">
  /**
   * The Overview tab: the quarantine resolver first when the relay is
   * quarantined, a live rotation banner, then origin / pool / delivery /
   * detector cards and the merged timeline.
   *
   * Props: relay; edges; listeners; connectionPlan; onOpenEdge; onOpenRotation
   */
  import type { z } from 'zod';
  import type {
    EdgeAdmin,
    RelayAdmin,
    RelayConnectionPlanEntry,
    RelayListenerAdmin,
  } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { relayTimelineQuery } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import Timeline from '../components/Timeline.svelte';
  import { edgesPaths } from '../lib/routes';
  import type { TimelineRow } from '../lib/types';
  import DeliveryCard from './DeliveryCard.svelte';
  import DetectorCard from './DetectorCard.svelte';
  import OriginCard from './OriginCard.svelte';
  import PoolCard from './PoolCard.svelte';
  import QuarantineResolver from './QuarantineResolver.svelte';
  import { timelineLinkParams } from './relayLogic';

  interface Props {
    relay: RelayAdmin;
    edges: EdgeAdmin[];
    listeners: RelayListenerAdmin[];
    connectionPlan: Array<z.infer<typeof RelayConnectionPlanEntry>>;
    onOpenEdge: (edgeId: string) => void;
    onOpenRotation: (rotationId: string) => void;
  }
  let { relay, edges, listeners, connectionPlan, onOpenEdge, onOpenRotation }: Props = $props();

  const timelineQ = relayTimelineQuery({
    slug: () => relay.slug,
    id: () => relay.id,
    rotating: () => !!relay.activeRotationId,
  });

  function hrefFor(entry: TimelineRow): string | null {
    const params = timelineLinkParams(entry);
    return params ? edgesPaths.relay(relay.slug, params) : null;
  }
</script>

<div class="space-y-4">
  {#if relay.quarantine}
    <QuarantineResolver {relay} {onOpenEdge} {onOpenRotation} />
  {/if}

  {#if relay.deleting}
    <div class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
      This relay is being deleted. Its edges are destroyed in the background and the page disappears
      once the last one is confirmed gone.
    </div>
  {/if}

  {#if relay.activeRotationId}
    <div
      class="flex flex-wrap items-center justify-between gap-3 rounded-md border border-sky-500/40 bg-sky-500/10 p-3 text-sm"
      role="status"
    >
      <span>
        <span class="font-medium">A rotation is running.</span>
        Other pool changes wait until it finishes. This page refreshes every ten seconds meanwhile.
      </span>
      <Button
        size="sm"
        onclick={() => relay.activeRotationId && onOpenRotation(relay.activeRotationId)}
      >
        Watch it
      </Button>
    </div>
  {/if}

  <div class="grid items-start gap-4 xl:grid-cols-2">
    <div class="space-y-4">
      <DeliveryCard {relay} />
      <PoolCard {relay} {edges} {onOpenEdge} />
    </div>
    <div class="space-y-4">
      <OriginCard {relay} {listeners} {connectionPlan} />
      <DetectorCard {relay} {edges} {onOpenEdge} onRotationStarted={onOpenRotation} />
    </div>
  </div>

  <Card.Root>
    <Card.Header>
      <Card.Title>Timeline</Card.Title>
      <Card.Description>
        Everything that happened to this relay, its listeners, its edges and its rotations, newest
        first.
      </Card.Description>
    </Card.Header>
    <Card.Content>
      {#if timelineQ.isPending}
        <Skeleton class="h-24 w-full" />
      {:else if timelineQ.error}
        <AdminListState error={timelineQ.error} onRetry={() => void timelineQ.refetch()} />
      {:else}
        <Timeline
          entries={timelineQ.data?.entries ?? []}
          truncated={timelineQ.data?.truncated ?? false}
          emptyText="Nothing has happened yet. Provision an edge from the Actions menu to get started."
          {hrefFor}
          max={20}
        />
      {/if}
    </Card.Content>
  </Card.Root>
</div>
