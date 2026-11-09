<script lang="ts">
  /**
   * The Overview tab: the quarantine resolver first when the origin is
   * quarantined, a live rotation banner, then origin / pool / delivery /
   * detector cards and the merged timeline.
   *
   * Props: origin; edges; listeners; connectionPlan; onOpenEdge; onOpenRotation;
   *   notices? (default true): the quarantine resolver, deleting and rotation
   *   notices (OriginNotices.svelte) first; a node's page shows them in Summary
   *   and passes false
   */
  import type { z } from 'zod';
  import type {
    EdgeAdmin,
    OriginAdmin,
    RelayConnectionPlanEntry,
    RelayListenerAdmin,
  } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { relayTimelineQuery } from '@client/lib/edgesApi';
  import { originBusy } from '@client/lib/livePoll';
  import AdminListState from '../../AdminListState.svelte';
  import Timeline from '../components/Timeline.svelte';
  import { edgesPaths } from '../lib/routes';
  import type { TimelineRow } from '../lib/types';
  import DeliveryCard from './DeliveryCard.svelte';
  import DetectorCard from './DetectorCard.svelte';
  import OriginCard from './OriginCard.svelte';
  import PoolCard from './PoolCard.svelte';
  import OriginNotices from './OriginNotices.svelte';
  import { timelineLinkParams } from './relayLogic';

  interface Props {
    relay: OriginAdmin;
    edges: EdgeAdmin[];
    listeners: RelayListenerAdmin[];
    connectionPlan: Array<z.infer<typeof RelayConnectionPlanEntry>>;
    onOpenEdge: (edgeId: string) => void;
    onOpenRotation: (rotationId: string) => void;
    notices?: boolean;
  }
  let {
    relay,
    edges,
    listeners,
    connectionPlan,
    onOpenEdge,
    onOpenRotation,
    notices = true,
  }: Props = $props();

  const timelineQ = relayTimelineQuery({
    slug: () => relay.slug,
    id: () => relay.id,
    rotating: () => originBusy(relay),
  });

  function hrefFor(entry: TimelineRow): string | null {
    const params = timelineLinkParams(entry);
    return params ? edgesPaths.relay(relay.slug, params) : null;
  }
</script>

<div class="space-y-4">
  {#if notices}
    <OriginNotices {relay} {onOpenEdge} {onOpenRotation} />
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
        Changes to this origin, its listeners, edges and rotations, newest first.
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
          emptyText="Nothing yet. Provision an edge from the Actions menu."
          {hrefFor}
          max={20}
        />
      {/if}
    </Card.Content>
  </Card.Root>
</div>
