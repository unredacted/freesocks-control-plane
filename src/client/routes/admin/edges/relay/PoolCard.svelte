<script lang="ts">
  /**
   * The published pool of a relay: the strip, the epoch, the rotation limits and
   * where they stand today.
   *
   * Props: relay; edges; onOpenEdge(edgeId)
   */
  import type { EdgeAdmin, RelayAdmin } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import KeyValue from '../components/KeyValue.svelte';
  import PoolStrip from '../components/PoolStrip.svelte';
  import { relativeTime } from '../lib/time';
  import type { KeyValueRow, PoolEntry } from '../lib/types';

  interface Props {
    relay: RelayAdmin;
    edges: EdgeAdmin[];
    onOpenEdge: (edgeId: string) => void;
  }
  let { relay, edges, onOpenEdge }: Props = $props();

  const entries = $derived.by((): PoolEntry[] =>
    edges
      .filter((e) => e.publication === 'published' && e.poolIndex !== null)
      .map((e) => ({
        poolIndex: e.poolIndex!,
        edgeId: e.id,
        provider: e.provider,
        managed: e.managed,
        addresses: e.addresses,
        layer: e.layer,
        listenerId: e.listenerId,
        health: e.health,
        status: e.status,
        unreachableIn: (e.reachability?.byCountry ?? [])
          .filter((c) => c.verdict === 'unreachable')
          .map((c) => c.country),
        mixedIn: (e.reachability?.byCountry ?? [])
          .filter((c) => c.verdict === 'mixed')
          .map((c) => c.country),
      })),
  );
  const draining = $derived(edges.filter((e) => e.publication === 'draining').length);
  const coolingDown = $derived(
    relay.cooldownUntil !== null && new Date(relay.cooldownUntil).getTime() > Date.now(),
  );

  const rows = $derived.by((): KeyValueRow[] => [
    {
      label: 'Published',
      value: `${relay.publishedCount} of ${relay.desiredPublished} wanted`,
      tone:
        relay.publishedCount === 0
          ? 'danger'
          : relay.publishedCount < relay.desiredPublished
            ? 'warning'
            : 'success',
    },
    {
      label: 'Standbys',
      value: `${relay.standbyEdgeIds.length} of ${relay.standbyPerRelay} wanted`,
    },
    { label: 'Draining', value: draining > 0 ? draining : '' },
    {
      label: 'Publication epoch',
      value: relay.publicationEpoch,
      hint: 'Goes up whenever what members should receive changes.',
    },
    {
      label: 'Last rotation',
      value: relay.lastRotatedAt ? relativeTime(relay.lastRotatedAt) : 'Never',
    },
    {
      label: 'Cooldown',
      value: coolingDown
        ? `Automatic rotations wait until ${relativeTime(relay.cooldownUntil)}`
        : `${relay.cooldownMinutes} min after each rotation, not running now`,
    },
    {
      label: 'Rotations today',
      value: `${relay.rotationsToday} of ${relay.maxRotationsPerDay} allowed`,
      tone: relay.rotationsToday >= relay.maxRotationsPerDay ? 'warning' : undefined,
    },
    { label: 'Drain time', value: `${relay.drainMinutes} min` },
  ]);
</script>

<Card.Root>
  <Card.Header>
    <Card.Title>Pool</Card.Title>
    <Card.Description>
      The published edges members are spread over, by pool position. Select one to open it.
    </Card.Description>
  </Card.Header>
  <Card.Content class="space-y-4">
    <PoolStrip
      publishedEdgeIds={relay.publishedEdgeIds}
      desired={relay.desiredPublished}
      standbys={relay.standbyEdgeIds}
      {draining}
      {entries}
      onSelect={onOpenEdge}
      showCaption
    />
    <KeyValue {rows} hideEmpty />
  </Card.Content>
</Card.Root>
