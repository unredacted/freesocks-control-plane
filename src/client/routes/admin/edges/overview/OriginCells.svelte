<script lang="ts">
  /**
   * The origin columns of one Nodes table row with "Technical columns" on
   * (the old All origins table; headings in OriginHeads.svelte): the origin
   * (its slug opens its technical details, its kind, Disabled / Being deleted
   * / Quarantined / a running rotation), layers, pool, provider check,
   * qualification, delivery, detector and the row menu. Layers, health and
   * delivery are the server's status of the origin, worded in ./derive.ts.
   * A row with no origin (a direct node) shows empty cells.
   *
   * Props:
   *   row: OriginRow | null
   *   status: OriginStatus | null              the server's status of it
   *   busy?: boolean                           its action is in flight
   *   onProvision: (row: OriginRow) => void    the page confirms (billable) and calls
   *   onProbe: (row: OriginRow) => void
   */
  import Ellipsis from '@lucide/svelte/icons/ellipsis';
  import * as Table from '@client/components/ui/table';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import * as Tooltip from '@client/components/ui/tooltip';
  import { Badge } from '@client/components/ui/badge';
  import { buttonVariants } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import { router } from '@client/stores/router.svelte';
  import LayerBadge from '../components/LayerBadge.svelte';
  import PoolStrip from '../components/PoolStrip.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import { edgesPaths } from '../lib/routes';
  import { phaseLabel } from '@client/lib/edgeCodes';
  import type { OriginStatus } from '@shared/contracts/edges';
  import {
    DELIVERY_LABELS,
    DELIVERY_TONES,
    ORIGIN_KIND_LABELS,
    suspicionChip,
    type OriginRow,
  } from './derive';

  interface Props {
    row: OriginRow | null;
    status: OriginStatus | null;
    busy?: boolean;
    onProvision: (row: OriginRow) => void;
    onProbe: (row: OriginRow) => void;
  }
  let { row, status, busy = false, onProvision, onProbe }: Props = $props();

  const layers = $derived(status?.layers ?? []);
  const health = $derived(status?.worstHealth ?? null);
  const delivery = $derived(status?.delivery.kind ?? null);
  const chip = $derived(row ? suspicionChip(row) : null);
</script>

{#if !row}
  <Table.Cell colspan={8} class="text-muted-foreground text-sm"
    >No origin: members connect directly.</Table.Cell
  >
{:else}
  {@const relay = row.relay}
  <Table.Cell>
    <Link
      href={edgesPaths.relay(relay.slug)}
      class="focus-visible:ring-ring/50 rounded-sm font-mono text-xs underline-offset-4 outline-none hover:underline focus-visible:ring-3"
    >
      {relay.slug}
    </Link>
    <div class="text-muted-foreground text-xs">{ORIGIN_KIND_LABELS[relay.origin.kind]}</div>
    <div class="mt-1 flex flex-wrap gap-1">
      {#if !relay.enabled}<Badge variant="muted">Disabled</Badge>{/if}
      {#if relay.deleting}<Badge variant="warning">Being deleted</Badge>{/if}
      {#if relay.quarantine}<Badge variant="danger">Quarantined</Badge>{/if}
      {#if row.rotation}
        <Badge variant="info">
          {phaseLabel(row.rotation.phase)}, {Math.round(row.rotation.percent)}%
        </Badge>
      {/if}
    </div>
  </Table.Cell>
  <Table.Cell>
    {#if layers.length === 0}
      <span class="text-muted-foreground text-sm">None published</span>
    {:else}
      <div class="flex gap-1">
        {#each layers as layer (layer)}<LayerBadge {layer} />{/each}
      </div>
    {/if}
  </Table.Cell>
  <Table.Cell>
    <div class="text-sm tabular-nums">{relay.publishedCount}/{relay.desiredPublished}</div>
    <PoolStrip
      publishedEdgeIds={relay.publishedEdgeIds}
      desired={relay.desiredPublished}
      standbys={relay.standbyEdgeIds}
      draining={row.draining}
      entries={row.pool}
      onSelect={(edgeId) =>
        router.navigate(edgesPaths.relay(relay.slug, { tab: 'edges', edge: edgeId }))}
    />
  </Table.Cell>
  <Table.Cell>
    {#if health}
      <StatusBadge kind="health" value={health} />
    {:else}
      <span class="text-muted-foreground text-sm">No edge yet</span>
    {/if}
  </Table.Cell>
  <Table.Cell class="text-sm">
    {#if relay.qualificationCredential}
      <Badge variant="success">Credential ready</Badge>
    {:else if layers.includes('l7')}
      <Badge variant="warning">No credential</Badge>
    {:else}
      <span class="text-muted-foreground">Not set up</span>
    {/if}
  </Table.Cell>
  <Table.Cell>
    {#if delivery}
      <Badge variant={DELIVERY_TONES[delivery]}>{DELIVERY_LABELS[delivery]}</Badge>
    {/if}
    {#if row.needsOperator > 0}
      <div class="text-muted-foreground mt-1 text-xs">
        {row.needsOperator}
        {row.needsOperator === 1 ? 'edge needs' : 'edges need'} a decision
      </div>
    {/if}
  </Table.Cell>
  <Table.Cell>
    {#if chip}
      <Tooltip.Root>
        <Tooltip.Trigger
          class="focus-visible:ring-ring/50 rounded-md outline-none focus-visible:ring-3"
        >
          <Badge variant={chip.tone}>{chip.label}</Badge>
        </Tooltip.Trigger>
        <Tooltip.Content>{chip.hint}</Tooltip.Content>
      </Tooltip.Root>
    {:else if relay.suspicion}
      <span class="text-muted-foreground text-sm">Clear</span>
    {:else}
      <span class="text-muted-foreground text-sm">Not evaluated</span>
    {/if}
  </Table.Cell>
  <Table.Cell>
    <DropdownMenu.Root>
      <DropdownMenu.Trigger
        class={buttonVariants({ variant: 'ghost', size: 'icon-sm' })}
        aria-label={`Actions for origin ${relay.slug}`}
        disabled={busy}
      >
        <Ellipsis aria-hidden="true" />
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="end">
        <DropdownMenu.Item onSelect={() => router.navigate(edgesPaths.relay(relay.slug))}>
          Technical details
        </DropdownMenu.Item>
        <DropdownMenu.Separator />
        <DropdownMenu.Item
          disabled={relay.deleting || relay.quarantine !== null}
          onSelect={() => onProvision(row)}
        >
          Provision an edge
        </DropdownMenu.Item>
        <DropdownMenu.Item onSelect={() => onProbe(row)}>Probe now</DropdownMenu.Item>
        <DropdownMenu.Separator />
        <DropdownMenu.Item
          variant="destructive"
          onSelect={() => router.navigate(edgesPaths.relay(relay.slug))}
        >
          Delete in technical details
        </DropdownMenu.Item>
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  </Table.Cell>
{/if}
