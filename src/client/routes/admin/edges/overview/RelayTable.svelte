<script lang="ts">
  /**
   * The origin table of the overview. Rows come from `EdgeSummary.origins`
   * (already filtered by the page); every derived cell is computed in
   * overview/derive.ts.
   *
   * Props:
   *   rows: RelayRow[]
   *   dark: ReadonlySet<string>               slugs the server reports as members dark
   *   busySlug?: string | null                a row whose action is in flight
   *   onProvision: (row: RelayRow) => void    the page confirms (billable) and calls
   *   onProbe: (row: RelayRow) => void
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
  import {
    DELIVERY_LABELS,
    DELIVERY_TONES,
    ORIGIN_KIND_LABELS,
    deliveryState,
    relayLayers,
    suspicionChip,
    worstHealth,
    type RelayRow,
  } from './derive';

  interface Props {
    rows: RelayRow[];
    dark: ReadonlySet<string>;
    busySlug?: string | null;
    onProvision: (row: RelayRow) => void;
    onProbe: (row: RelayRow) => void;
  }
  let { rows, dark, busySlug = null, onProvision, onProbe }: Props = $props();

  function originLine(row: RelayRow): string {
    const o = row.relay.origin;
    return o.kind === 'panel-node'
      ? `${ORIGIN_KIND_LABELS[o.kind]}: ${o.nodeName}`
      : ORIGIN_KIND_LABELS[o.kind];
  }
</script>

<Table.Root>
  <Table.Header>
    <Table.Row>
      <Table.Head>Origin</Table.Head>
      <Table.Head>Origin</Table.Head>
      <Table.Head>Layers</Table.Head>
      <Table.Head>Pool</Table.Head>
      <Table.Head>Health</Table.Head>
      <Table.Head>Qualification</Table.Head>
      <Table.Head>Delivery</Table.Head>
      <Table.Head>Detector</Table.Head>
      <Table.Head class="w-10"><span class="sr-only">Actions</span></Table.Head>
    </Table.Row>
  </Table.Header>
  <Table.Body>
    {#each rows as row (row.relay.id)}
      {@const relay = row.relay}
      {@const layers = relayLayers(row)}
      {@const health = worstHealth(row)}
      {@const delivery = deliveryState(row, dark)}
      {@const chip = suspicionChip(row)}
      <Table.Row>
        <Table.Cell>
          <Link
            href={edgesPaths.relay(relay.slug)}
            class="focus-visible:ring-ring/50 rounded-sm font-medium underline-offset-4 outline-none hover:underline focus-visible:ring-3"
          >
            {relay.slug}
          </Link>
          {#if relay.label}
            <div class="text-muted-foreground text-xs">{relay.label}</div>
          {/if}
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
        <Table.Cell class="text-sm">{originLine(row)}</Table.Cell>
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
          <Badge variant={DELIVERY_TONES[delivery]}>{DELIVERY_LABELS[delivery]}</Badge>
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
              aria-label={`Actions for relay ${relay.slug}`}
              disabled={busySlug === relay.slug}
            >
              <Ellipsis aria-hidden="true" />
            </DropdownMenu.Trigger>
            <DropdownMenu.Content align="end">
              <DropdownMenu.Item onSelect={() => router.navigate(edgesPaths.relay(relay.slug))}>
                Open
              </DropdownMenu.Item>
              <DropdownMenu.Item
                onSelect={() => router.navigate(edgesPaths.setup({ relay: relay.slug }))}
              >
                Setup
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
                Delete on the origin page
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Root>
        </Table.Cell>
      </Table.Row>
    {/each}
  </Table.Body>
</Table.Root>
