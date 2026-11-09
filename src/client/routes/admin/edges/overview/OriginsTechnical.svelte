<script lang="ts">
  /**
   * The rest of the old All origins page, shown on Nodes while "Technical
   * columns" is on (the origin table itself is the Nodes table's origin
   * columns, OriginCells.svelte): the "New edge work is paused" banner with
   * Resume, the fleet tiles (a problem tile filters the table), Needs attention,
   * Readiness (each step links to where it is done, `setupStepTarget`) and the
   * Reachability chart.
   *
   * Each origin's status is the server's one projection (the attention
   * response's `origins[]`); figures the `EdgeSummary` contract does not carry
   * are counted in ./derive.ts.
   *
   * Props:
   *   part: 'top' | 'bottom'        top: banner, tiles, Needs attention, Readiness;
   *                                 bottom: Reachability (below the table)
   *   activeFilter: string          the table's filter (a tile shows pressed when it is its own)
   *   onFilter: (filter: OverviewFilter) => void
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import {
    attentionQuery,
    edgeConfigQuery,
    edgeSummaryQuery,
    invalidateConfig,
    invalidateOverview,
    maintenanceQuery,
    probeSummaryQuery,
    setupStatusQuery,
    thawMaintenance,
    type ProbeRange,
  } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import AttentionList from '../components/AttentionList.svelte';
  import ReadinessChecklist from '../components/ReadinessChecklist.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import ProbeTimeChart from '../components/ProbeTimeChart.svelte';
  import FleetTiles from './FleetTiles.svelte';
  import { edgesPaths } from '../lib/routes';
  import { runAttentionCall } from '../lib/attentionCalls';
  import { attentionCallDeps } from '../lib/attentionCallDeps';
  import { relativeTime } from '../lib/time';
  import { fleetTiles, parseFilter, statusIndex, type OverviewFilter } from './derive';
  import type { AttentionItem } from '../lib/attention';

  interface Props {
    part: 'top' | 'bottom';
    activeFilter: string;
    onFilter: (filter: OverviewFilter) => void;
  }
  let { part, activeFilter, onFilter }: Props = $props();

  const qc = useQueryClient();
  const summary = edgeSummaryQuery();
  const attention = attentionQuery();
  const setup = setupStatusQuery(() => null);
  const maintenance = maintenanceQuery();
  const config = edgeConfigQuery();
  const HOUR: ProbeRange = { kind: 'window', windowMs: 3_600_000 };
  const probeHour = probeSummaryQuery(() => HOUR);

  const items = $derived(attention.data?.items ?? []);
  const statuses = $derived(statusIndex(attention.data?.origins));
  const tiles = $derived(
    summary.data
      ? fleetTiles(summary.data, statuses, {
          usedLastHour: probeHour.data?.totals.runs ?? null,
          hourlyBudget: config.data?.config.probe.hourlyBudget ?? null,
          enabled: config.data?.config.probe.enabled ?? null,
        })
      : [],
  );

  /** The server-call attention actions (AttentionList has already confirmed the disruptive ones). */
  const attentionDeps = attentionCallDeps(qc, { plain: false });
  const onAction = (item: AttentionItem) => runAttentionCall(item, attentionDeps);

  let thawOpen = $state(false);
  async function thaw(): Promise<void> {
    await thawMaintenance();
    toast.success('New edge work is allowed again.');
    invalidateConfig(qc);
    invalidateOverview(qc);
  }
</script>

{#if part === 'top'}
  {#if maintenance.data?.frozen}
    <div
      class="flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/50 bg-amber-500/10 px-3 py-2.5 text-sm"
      role="status"
    >
      <div class="min-w-0 flex-1 basis-64">
        <p class="font-medium">New edge work is paused</p>
        <p class="text-muted-foreground">
          Running rotations finish, nothing new starts.
          {#if maintenance.data.reason}Reason: {maintenance.data.reason}.{/if}
          {#if maintenance.data.since}Paused {relativeTime(maintenance.data.since)}.{/if}
        </p>
      </div>
      <Button size="sm" variant="outline" onclick={() => (thawOpen = true)}>Resume new work</Button>
    </div>
  {/if}

  <section aria-label="Fleet">
    {#if summary.isPending}
      <div class="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
        {#each Array.from({ length: 9 }, (_, i) => i) as i (i)}<Skeleton class="h-20" />{/each}
      </div>
    {:else if summary.isError}
      <AdminListState error={summary.error} onRetry={() => summary.refetch()} />
    {:else}
      <FleetTiles {tiles} activeFilter={parseFilter(activeFilter)} {onFilter} />
    {/if}
  </section>

  <section>
    <SectionHeader
      level={2}
      title="Needs attention"
      description="Ranked by urgency. Each row offers the one action that moves it forward."
    />
    {#if attention.isPending}
      <Skeleton class="h-16" />
    {:else if attention.isError}
      <AdminListState error={attention.error} onRetry={() => attention.refetch()} />
    {:else}
      <AttentionList {items} {onAction} max={6} />
    {/if}
  </section>

  <section>
    <SectionHeader
      level={2}
      title="Readiness"
      description="What the fleet needs before edges can run on their own."
    />
    {#if setup.isPending}
      <Skeleton class="h-24" />
    {:else if setup.isError}
      <AdminListState error={setup.error} onRetry={() => setup.refetch()} />
    {:else if setup.data}
      <ReadinessChecklist status={setup.data} compact />
    {/if}
  </section>

  <ConfirmDialog
    bind:open={thawOpen}
    title="Resume new edge work?"
    body="Provisioning, publishing and automatic rotation are allowed again for the whole fleet."
    confirmLabel="Resume new work"
    onConfirm={thaw}
  />
{:else}
  <section>
    <SectionHeader
      level={2}
      title="Reachability"
      description="Whether published addresses answer from the countries you watch."
    >
      {#snippet actions()}
        <Link
          href={edgesPaths.probes()}
          class="text-primary focus-visible:ring-ring/50 rounded-sm text-sm underline underline-offset-4 outline-none focus-visible:ring-3"
        >
          Open the Probes page
        </Link>
      {/snippet}
    </SectionHeader>
    <ProbeTimeChart />
  </section>
{/if}
