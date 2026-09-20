<script lang="ts">
  /**
   * Admin -> Edges overview (`/admin/edges`).
   * URL state: `?filter` = all | attention | dark | quarantined | unpublished,
   *            `?layer`  = all | l4 | l7   (both filter the origin table client-side).
   *
   * Figures the `EdgeSummary` contract does not carry (published per layer,
   * standbys, members dark, probe budget) are derived in overview/derive.ts from
   * the summary rows, the attention list, the probe summary and the config.
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { router } from '@client/stores/router.svelte';
  import { searchParam } from '@client/lib/urlState.svelte';
  import { codeLabel } from '@client/lib/edgeCodes';
  import {
    attentionQuery,
    edgeConfigQuery,
    edgeSummaryQuery,
    invalidateConfig,
    invalidateOverview,
    invalidateProbes,
    invalidateProviders,
    invalidateRelay,
    maintenanceQuery,
    probeRelay,
    probeSummaryQuery,
    provisionRelay,
    publishRelayEdge,
    qualifyEdge,
    rotateRelayEdge,
    setupStatusQuery,
    testProviderCredentials,
    thawMaintenance,
    type ProbeRange,
  } from '@client/lib/edgesApi';
  import AdminListState from '../AdminListState.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import AttentionList from './components/AttentionList.svelte';
  import ReadinessChecklist from './components/ReadinessChecklist.svelte';
  import ConfirmDialog from './components/ConfirmDialog.svelte';
  import ProbeTimeChart from './components/ProbeTimeChart.svelte';
  import FleetTiles from './overview/FleetTiles.svelte';
  import RelayTable from './overview/RelayTable.svelte';
  import { edgesPaths } from './lib/routes';
  import { edgeErrorMessage } from './lib/edgeErrors';
  import { ATTENTION_ACTION_PLAN, attentionTarget } from './lib/attention';
  import { relativeTime } from './lib/time';
  import {
    FILTER_LABELS,
    LAYER_FILTER_LABELS,
    OVERVIEW_FILTERS,
    OVERVIEW_LAYERS,
    attentionRelaySlugs,
    darkRelaySlugs,
    filterRelays,
    fleetTiles,
    parseFilter,
    parseLayer,
    type AttentionItem,
    type OverviewFilter,
    type RelayRow,
  } from './overview/derive';

  const qc = useQueryClient();
  const summary = edgeSummaryQuery();
  const attention = attentionQuery();
  const setup = setupStatusQuery(() => null);
  const maintenance = maintenanceQuery();
  const config = edgeConfigQuery();
  const HOUR: ProbeRange = { kind: 'window', windowMs: 3_600_000 };
  const probeHour = probeSummaryQuery(() => HOUR);

  const filterParam = searchParam('filter', 'all');
  const layerParam = searchParam('layer', 'all');
  const filter = $derived(parseFilter(filterParam.value));
  const layer = $derived(parseLayer(layerParam.value));

  const items = $derived(attention.data?.items ?? []);
  const dark = $derived(darkRelaySlugs(items));
  const flagged = $derived(attentionRelaySlugs(items));
  const allRows = $derived(summary.data?.relays ?? []);
  const rows = $derived(filterRelays(allRows, filter, layer, { dark, attention: flagged }));
  const tiles = $derived(
    summary.data
      ? fleetTiles(summary.data, items, {
          usedLastHour: probeHour.data?.totals.runs ?? null,
          hourlyBudget: config.data?.config.probe.hourlyBudget ?? null,
          enabled: config.data?.config.probe.enabled ?? null,
        })
      : [],
  );

  function setFilter(next: OverviewFilter) {
    filterParam.value = next;
  }

  const openRotation = (slug: string | null, rotationId: string) => {
    if (slug) router.navigate(edgesPaths.relay(slug, { tab: 'rotations', rotation: rotationId }));
  };

  /** The server-call attention actions (AttentionList has already confirmed the disruptive ones). */
  async function onAction(item: AttentionItem): Promise<void> {
    try {
      switch (item.action) {
        case 'publish':
        case 'rotate': {
          if (!item.relayId || !item.edgeId) {
            router.navigate(attentionTarget(item));
            return;
          }
          const call = item.action === 'publish' ? publishRelayEdge : rotateRelayEdge;
          const res = await call(item.relayId, { edgeId: item.edgeId });
          toast.success(
            item.action === 'publish'
              ? 'Publishing started. Follow the run on the origin page.'
              : 'Replacement started. Follow the run on the origin page.',
          );
          if (item.relaySlug) invalidateRelay(qc, item.relaySlug);
          else invalidateOverview(qc);
          openRotation(item.relaySlug, res.rotationId);
          return;
        }
        case 'provision': {
          if (!item.relayId) {
            router.navigate(attentionTarget(item));
            return;
          }
          const res = await provisionRelay(item.relayId);
          toast.success('Provisioning started. Follow the run on the origin page.');
          if (item.relaySlug) invalidateRelay(qc, item.relaySlug);
          else invalidateOverview(qc);
          openRotation(item.relaySlug, res.rotationId);
          return;
        }
        case 'thaw': {
          await thawMaintenance();
          toast.success('New edge work is allowed again.');
          invalidateConfig(qc);
          invalidateOverview(qc);
          return;
        }
        case 'qualify_front': {
          if (!item.edgeId) {
            router.navigate(attentionTarget(item));
            return;
          }
          const res = await qualifyEdge(item.edgeId);
          if (res.ok) toast.success('The front passed qualification.');
          else
            toast.error(
              res.code
                ? `The front did not qualify: ${codeLabel(res.code)}.`
                : 'The front did not qualify.',
            );
          if (item.relaySlug) invalidateRelay(qc, item.relaySlug);
          else invalidateOverview(qc);
          return;
        }
        case 'test_credentials': {
          if (!item.accountId) {
            router.navigate(attentionTarget(item));
            return;
          }
          const res = await testProviderCredentials(item.accountId);
          if (res.ok) toast.success('The provider accepted the credentials.');
          else
            toast.error(
              res.code
                ? `The credential test failed: ${codeLabel(res.code)}.`
                : 'The credential test failed.',
            );
          invalidateProviders(qc);
          invalidateOverview(qc);
          return;
        }
        default:
          router.navigate(attentionTarget(item));
      }
    } catch (e) {
      // A confirmed action fails inside its dialog (which shows the reason); the rest toast.
      const plan = ATTENTION_ACTION_PLAN[item.action];
      if (plan.type !== 'call' || !plan.confirm) toast.error(edgeErrorMessage(e));
      throw e;
    }
  }

  // Row actions.
  let provisionRow = $state<RelayRow | null>(null);
  let provisionOpen = $state(false);
  const provision = createMutation(() => ({
    mutationFn: (row: RelayRow) => provisionRelay(row.relay.id),
    onSuccess: (res, row) => {
      toast.success('Provisioning started. Follow the run on the origin page.');
      invalidateRelay(qc, row.relay.slug);
      openRotation(row.relay.slug, res.rotationId);
    },
  }));
  const probe = createMutation(() => ({
    mutationFn: (row: RelayRow) => probeRelay(row.relay.id),
    onSuccess: (res, row) => {
      const started = res.runIds.length;
      const skipped = res.skipped.length;
      if (started === 0) {
        toast.message(
          skipped > 0
            ? `No probe started for ${row.relay.slug}: ${skipped} ${skipped === 1 ? 'target was' : 'targets were'} skipped (budget, spacing or probes switched off).`
            : `No probe started for ${row.relay.slug}: it has nothing to probe yet.`,
        );
      } else {
        toast.success(
          `${started} ${started === 1 ? 'probe' : 'probes'} started for ${row.relay.slug}${skipped > 0 ? `, ${skipped} skipped` : ''}.`,
        );
      }
      invalidateProbes(qc);
    },
    onError: (e) => toast.error(edgeErrorMessage(e)),
  }));

  let thawOpen = $state(false);
  async function thaw(): Promise<void> {
    await thawMaintenance();
    toast.success('New edge work is allowed again.');
    invalidateConfig(qc);
    invalidateOverview(qc);
  }

  const busySlug = $derived(
    provision.isPending
      ? (provision.variables?.relay.slug ?? null)
      : probe.isPending
        ? (probe.variables?.relay.slug ?? null)
        : null,
  );
  const CHIP =
    'rounded-md border px-2 py-1 text-xs outline-none focus-visible:ring-3 focus-visible:ring-ring/50';
</script>

<SectionHeader
  title="Edges"
  description="Relays, the edges that front them, and what needs your attention."
>
  {#snippet actions()}
    <Button onclick={() => router.navigate(edgesPaths.setup())}>
      <Plus aria-hidden="true" />
      Set up an origin
    </Button>
  {/snippet}
</SectionHeader>

{#if maintenance.data?.frozen}
  <div
    class="mb-6 flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/50 bg-amber-500/10 px-3 py-2.5 text-sm"
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

<div class="space-y-8">
  <section aria-label="Fleet">
    {#if summary.isPending}
      <div class="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
        {#each Array.from({ length: 9 }, (_, i) => i) as i (i)}<Skeleton class="h-20" />{/each}
      </div>
    {:else if summary.isError}
      <AdminListState error={summary.error} onRetry={() => summary.refetch()} />
    {:else}
      <FleetTiles {tiles} activeFilter={filter} onFilter={setFilter} />
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

  <section>
    <SectionHeader level={2} title="Relays">
      {#snippet actions()}
        <div class="flex flex-wrap items-center gap-1" role="group" aria-label="Filter relays">
          {#each OVERVIEW_FILTERS as f (f)}
            <button
              type="button"
              class={[
                CHIP,
                filter === f ? 'bg-primary text-primary-foreground border-transparent' : '',
              ]}
              aria-pressed={filter === f}
              onclick={() => setFilter(f)}
            >
              {FILTER_LABELS[f]}
            </button>
          {/each}
          <span class="bg-border mx-1 h-4 w-px" aria-hidden="true"></span>
          {#each OVERVIEW_LAYERS as l (l)}
            <button
              type="button"
              class={[
                CHIP,
                layer === l ? 'bg-primary text-primary-foreground border-transparent' : '',
              ]}
              aria-pressed={layer === l}
              onclick={() => (layerParam.value = l)}
            >
              {LAYER_FILTER_LABELS[l]}
            </button>
          {/each}
        </div>
      {/snippet}
    </SectionHeader>
    {#if summary.isPending}
      <Skeleton class="h-32" />
    {:else if summary.isError}
      <AdminListState error={summary.error} onRetry={() => summary.refetch()} />
    {:else if allRows.length === 0}
      <div class="rounded-lg border border-dashed p-8 text-center">
        <p class="font-medium">No origins yet</p>
        <p class="text-muted-foreground mx-auto mt-1 max-w-prose text-sm">
          An origin is a place members should never reach directly: a backend node, a backend server
          or an address you enter by hand. The control plane puts provider-managed edges in front of
          it and replaces them when they stop working.
        </p>
        <Button class="mt-4" onclick={() => router.navigate(edgesPaths.setup())}>
          <Plus aria-hidden="true" />
          Set up an origin
        </Button>
      </div>
    {:else if rows.length === 0}
      <div class="text-muted-foreground rounded-lg border border-dashed p-6 text-center text-sm">
        No origin matches this filter.
        <Button
          variant="link"
          size="sm"
          onclick={() => router.navigate(edgesPaths.overview(), { replace: true })}
        >
          Show all origins
        </Button>
      </div>
    {:else}
      <RelayTable
        {rows}
        {dark}
        {busySlug}
        onProvision={(row) => {
          provisionRow = row;
          provision.reset();
          provisionOpen = true;
        }}
        onProbe={(row) => probe.mutate(row)}
      />
    {/if}
  </section>

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
</div>

<ConfirmDialog
  bind:open={provisionOpen}
  title="Provision a new edge?"
  body="This creates a billable resource at the provider and counts against the account budget for today. The run opens on the relay page."
  confirmLabel="Provision"
  onConfirm={() => (provisionRow ? provision.mutateAsync(provisionRow) : undefined)}
>
  {#if provisionRow}
    <p class="text-muted-foreground">Relay {provisionRow.relay.slug}</p>
  {/if}
</ConfirmDialog>

<ConfirmDialog
  bind:open={thawOpen}
  title="Resume new edge work?"
  body="Provisioning, publishing and automatic rotation are allowed again for the whole fleet."
  confirmLabel="Resume new work"
  onConfirm={thaw}
/>
