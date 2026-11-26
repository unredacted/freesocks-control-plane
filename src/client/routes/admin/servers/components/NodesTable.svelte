<script lang="ts">
  /**
   * The Nodes table: one row per node of every backend and per origin added by
   * hand (rows from ../lib/nodesTable.ts). Columns: Name (dot, name, machine
   * name, the backend when there is more than one), Country, Modes, Addresses,
   * Users online, Status. "Technical columns" adds the old All origins columns
   * (../../edges/overview/OriginCells.svelte). A row opens the node (its name
   * is the link, the rest of the row is a shortcut).
   *
   * Props:
   *   rows: NodeRow[]
   *   technical: boolean                        the origin columns
   *   showBackend: boolean                      more than one backend: a heading row before
   *                                             each backend's nodes (rows come grouped)
   *   canAdopt: (row: NodeRow) => boolean       offer "Adopt" on a row without an enrolled node
   *   onAdopt: (row: NodeRow) => void
   *   onOpenRun: (runId: string) => void        a live (or stopped) fronting run's progress
   *   busySlug?: string | null                  an origin whose row action is in flight
   *   onProvision / onProbe                     the origin row actions
   */
  import * as Table from '@client/components/ui/table';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import { router } from '@client/stores/router.svelte';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import OriginCells from '../../edges/overview/OriginCells.svelte';
  import OriginHeads from '../../edges/overview/OriginHeads.svelte';
  import type { OriginRow } from '../../edges/overview/derive';
  import { splitLead } from '@client/lib/splitLead';
  import { addressesWords, rowHref, type NodeRow } from '../lib/nodesTable';
  import { countryLabel } from '../lib/words';

  interface Props {
    rows: NodeRow[];
    technical: boolean;
    showBackend: boolean;
    canAdopt: (row: NodeRow) => boolean;
    onAdopt: (row: NodeRow) => void;
    onOpenRun: (runId: string) => void;
    busySlug?: string | null;
    onProvision: (row: OriginRow) => void;
    onProbe: (row: OriginRow) => void;
  }
  let {
    rows,
    technical,
    showBackend,
    canAdopt,
    onAdopt,
    onOpenRun,
    busySlug = null,
    onProvision,
    onProbe,
  }: Props = $props();

  /** OriginHeads' columns (Origin through the actions column). */
  const TECHNICAL_COLUMNS = 8;
  /** Six columns, and the origin ones with Technical columns on. */
  const columns = $derived(technical ? 6 + TECHNICAL_COLUMNS : 6);

  // The whole row is a shortcut to the node; its controls keep their own clicks.
  function openRow(e: MouseEvent, href: string | null) {
    if (!href) return;
    const target = e.target as HTMLElement | null;
    if (target?.closest('a,button,[role="menuitem"],[data-slot="dropdown-menu-trigger"]')) return;
    router.navigate(href);
  }
</script>

<Table.Root>
  <Table.Header>
    <Table.Row>
      <Table.Head>Node</Table.Head>
      <Table.Head>Country</Table.Head>
      <Table.Head>Modes</Table.Head>
      <Table.Head>Addresses</Table.Head>
      <Table.Head class="text-end">Users online</Table.Head>
      <Table.Head>Status</Table.Head>
      {#if technical}<OriginHeads />{/if}
    </Table.Row>
  </Table.Header>
  <Table.Body>
    {#each rows as row, i (row.key)}
      {@const href = rowHref(row)}
      {@const sentence = splitLead(row.sentence)}
      {#if showBackend && (i === 0 || rows[i - 1]?.backend?.slug !== row.backend?.slug)}
        <!-- More than one backend: its nodes under one heading row, not a badge on each. -->
        <Table.Row class="bg-muted/40 hover:bg-muted/40">
          <Table.Cell colspan={columns} class="text-muted-foreground py-1.5 text-xs font-medium">
            {row.backend?.name ?? 'Added by hand'}
          </Table.Cell>
        </Table.Row>
      {/if}
      {@const country = countryLabel(row.countryCode)}
      <Table.Row class={href ? 'cursor-pointer' : undefined} onclick={(e) => openRow(e, href)}>
        <Table.Cell>
          <div class="flex items-start gap-2">
            <StatusDot dot={row.dot} class="mt-1.5" />
            <div class="min-w-0">
              {#if href}
                <Link
                  {href}
                  class="focus-visible:ring-ring/50 rounded-sm font-medium whitespace-nowrap underline-offset-4 outline-none hover:underline focus-visible:ring-3"
                >
                  {row.name}
                </Link>
              {:else}
                <span class="font-medium whitespace-nowrap">{row.name}</span>
              {/if}
              {#if row.machine}
                <div class="text-muted-foreground font-mono text-xs" title="Machine name">
                  {row.machine}
                </div>
              {/if}
              {#if row.byHand}
                <div class="mt-0.5"><Badge variant="muted">Added by hand</Badge></div>
              {/if}
            </div>
          </div>
        </Table.Cell>
        <Table.Cell class="text-sm">{country ?? ''}</Table.Cell>
        <Table.Cell class="text-sm">{row.modes.join(', ')}</Table.Cell>
        <Table.Cell class="text-sm whitespace-nowrap">
          {addressesWords(row.origin, row.status)}
        </Table.Cell>
        <Table.Cell class="text-end text-sm tabular-nums">
          {#if row.usersOnline !== null}{row.usersOnline}{/if}
        </Table.Cell>
        <Table.Cell class="min-w-56 text-sm">
          <!-- One sentence; the node page says the rest. -->
          <span class="text-muted-foreground" title={sentence.rest ? row.sentence : undefined}>
            {sentence.lead}
          </span>
          {#if row.runId || (row.adoptable && canAdopt(row))}
            <div class="mt-1 flex flex-wrap gap-2">
              {#if row.runId}
                <Button size="sm" variant="outline" onclick={() => onOpenRun(row.runId!)}>
                  Show progress
                </Button>
              {/if}
              {#if row.adoptable && canAdopt(row)}
                <Button size="sm" variant="ghost" onclick={() => onAdopt(row)}>
                  Adopt as an enrolled node
                </Button>
              {/if}
            </div>
          {/if}
        </Table.Cell>
        {#if technical}
          <OriginCells
            row={row.origin}
            status={row.status}
            busy={!!row.origin && busySlug === row.origin.relay.slug}
            {onProvision}
            {onProbe}
          />
        {/if}
      </Table.Row>
    {/each}
  </Table.Body>
</Table.Root>
