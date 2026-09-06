<script lang="ts">
  import AdminLayout from './AdminLayout.svelte';
  import * as Tabs from '@client/components/ui/tabs';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AdminListState from './AdminListState.svelte';
  import RelaysPanel from './RelaysPanel.svelte';
  import EdgeProvidersPanel from './EdgeProvidersPanel.svelte';
  import EdgeTemplatesPanel from './EdgeTemplatesPanel.svelte';
  import RealityProfilesPanel from './RealityProfilesPanel.svelte';
  import RelayConfigPanel from './RelayConfigPanel.svelte';
  import { adminRelaySummaryQuery } from '../../lib/queries';

  /**
   * Admin → Relays (docs/relays.md): provider-managed L4 load balancers (edges) in
   * front of relay nodes. Relays (published pool, rotations, edges),
   * provider accounts, edge templates, camouflage profiles, and the rendering /
   * probe / detector configuration. Every request on this page is HPKE-sealed
   * by the shared route policy. English-only (admin CMS convention).
   */
  const summary = adminRelaySummaryQuery();
  let tab = $state('origins');
</script>

<AdminLayout>
  <div class="mb-6 flex flex-wrap items-end justify-between gap-3">
    <div>
      <h1 class="text-2xl font-bold">Relays and edges</h1>
      <p class="mt-1 text-sm text-muted-foreground">
        Provider-managed L4 edges in front of relay nodes: published pools, rotations, REALITY
        profiles and the block detector. Probe telemetry lives under Telemetry.
      </p>
    </div>
    {#if summary.data}
      {@const c = summary.data.counts}
      <div class="flex flex-wrap gap-2 text-xs">
        <span class="rounded-full border px-2.5 py-1">{c.relays} relays</span>
        <span class="rounded-full border px-2.5 py-1">{c.published} published</span>
        {#if c.rotating > 0}
          <span class="rounded-full border border-sky-500/40 bg-sky-500/10 px-2.5 py-1"
            >{c.rotating} rotating</span
          >
        {/if}
        {#if c.suspected > 0}
          <span class="rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1"
            >{c.suspected} suspected</span
          >
        {/if}
        {#if c.unreachableEdges > 0}
          <span class="rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1"
            >{c.unreachableEdges} edge{c.unreachableEdges === 1 ? '' : 's'} unreachable</span
          >
        {/if}
        {#if c.quarantined > 0}
          <span class="rounded-full border border-destructive/40 bg-destructive/10 px-2.5 py-1"
            >{c.quarantined} quarantined</span
          >
        {/if}
        {#if c.needsOperator > 0}
          <span class="rounded-full border border-destructive/40 bg-destructive/10 px-2.5 py-1"
            >{c.needsOperator} need an operator</span
          >
        {/if}
      </div>
    {/if}
  </div>

  {#if summary.isPending}
    <Skeleton class="h-40 w-full" />
  {:else if summary.isError}
    <AdminListState error={summary.error} onRetry={() => void summary.refetch()} />
  {:else}
    <Tabs.Root bind:value={tab} class="gap-6">
      <Tabs.List class="w-full min-w-max sm:w-fit">
        <Tabs.Trigger value="origins">Relays</Tabs.Trigger>
        <Tabs.Trigger value="providers">Providers</Tabs.Trigger>
        <Tabs.Trigger value="templates">Templates</Tabs.Trigger>
        <Tabs.Trigger value="profiles">REALITY profiles</Tabs.Trigger>
        <Tabs.Trigger value="config">Rendering and detector</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content value="origins">
        <RelaysPanel summary={summary.data ?? null} />
      </Tabs.Content>
      <Tabs.Content value="providers"><EdgeProvidersPanel /></Tabs.Content>
      <Tabs.Content value="templates"><EdgeTemplatesPanel /></Tabs.Content>
      <Tabs.Content value="profiles"><RealityProfilesPanel /></Tabs.Content>
      <Tabs.Content value="config">
        <RelayConfigPanel relays={(summary.data?.relays ?? []).map((o) => o.relay)} />
      </Tabs.Content>
    </Tabs.Root>
  {/if}
</AdminLayout>
