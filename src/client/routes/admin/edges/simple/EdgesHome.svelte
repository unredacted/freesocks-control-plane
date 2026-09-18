<script lang="ts">
  /**
   * Edges home (`/admin/edges`): one status sentence, what needs you, one row
   * per protected node, "Protect a node". URL state: `?protect=1` opens the
   * protect sheet, `?run=<id>` opens a run's progress.
   *
   * The technical dashboard this replaced lives on under Advanced (All relays).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import { Label } from '@client/components/ui/label';
  import Link from '@client/components/Link.svelte';
  import { router } from '@client/stores/router.svelte';
  import { searchParam, setSearchParams } from '@client/lib/urlState.svelte';
  import {
    attentionQuery,
    edgeConfigQuery,
    edgeSummaryQuery,
    invalidateConfig,
    invalidateOverview,
    invalidateRelay,
    providersQuery,
    rebalanceRelay,
    requireRelayEdges,
    retrySetupRun,
    setEdgeAutomation,
    setupRunsQuery,
    thawMaintenance,
  } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import AttentionList from '../components/AttentionList.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import type { AttentionItem } from '../lib/attention';
  import { attentionTarget } from '../lib/attention';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import EndpointTestCard from './EndpointTestCard.svelte';
  import NodeRow from './NodeRow.svelte';
  import ProtectSheet from './ProtectSheet.svelte';
  import StatusDot from './StatusDot.svelte';
  import { fleetSentence, liveRunFor, nodeStatus } from './nodeStatus';
  import { automationOn } from './runWords';

  const qc = useQueryClient();
  const summary = edgeSummaryQuery();
  const attention = attentionQuery();
  const runs = setupRunsQuery();
  const config = edgeConfigQuery();
  const providers = providersQuery();

  const protectParam = searchParam('protect');
  const runParam = searchParam('run');
  const sheetOpen = $derived(protectParam.value === '1' || runParam.value !== '');

  const items = $derived(attention.data?.items ?? []);
  const runList = $derived(runs.data?.runs ?? []);
  const rows = $derived(
    [...(summary.data?.relays ?? [])].sort((a, b) => a.relay.slug.localeCompare(b.relay.slug)),
  );
  const ctx = $derived({ attention: items, runs: runList });
  const statuses = $derived(rows.map((r) => nodeStatus(r, ctx)));
  const headline = $derived(fleetSentence(statuses));
  const automation = $derived(config.data ? automationOn(config.data.config) : null);
  const hasAccount = $derived((providers.data?.accounts.length ?? 0) > 0);

  // The test card opened from a "Needs you" row (a spare, a retest, a go-live check).
  let testEdgeIds = $state<string[]>([]);
  let testRelayId = $state<string | null>(null);
  let testRunId = $state<string | null>(null);

  async function goLive(relayId: string, slug: string | null): Promise<void> {
    const res = await requireRelayEdges(relayId);
    if (res.pending.length > 0) {
      // The server already opened the activation run (needs_you: try_it): the
      // ticks go to that run, never to a second require-edges call.
      testEdgeIds = res.pending.map((p) => p.edgeId);
      testRelayId = relayId;
      testRunId = res.runId;
      toast.message('Test each address first. Going live continues once every one works.');
      return;
    }
    testEdgeIds = [];
    testRelayId = null;
    testRunId = null;
    toast.success('Going live.');
    if (slug) invalidateRelay(qc, slug);
    else invalidateOverview(qc);
    runParam.value = res.runId;
  }

  /** Server-call attention actions; the rest navigate to the page that does it by hand. */
  async function onAction(item: AttentionItem): Promise<void> {
    try {
      switch (item.action) {
        case 'verify_endpoint':
          if (!item.edgeId) break;
          testEdgeIds = [item.edgeId];
          testRelayId = null;
          return;
        case 'require_edges':
          if (!item.relayId) break;
          await goLive(item.relayId, item.relaySlug);
          return;
        case 'rebalance':
          if (!item.relayId) break;
          await rebalanceRelay(item.relayId);
          toast.success('Made room. The uncovered inbound gets its address next.');
          invalidateOverview(qc);
          return;
        case 'thaw':
          await thawMaintenance();
          toast.success('New work is allowed again.');
          invalidateConfig(qc);
          invalidateOverview(qc);
          return;
        default:
          break;
      }
      router.navigate(attentionTarget(item));
    } catch (e) {
      toast.error(edgeErrorMessage(e));
      throw e;
    }
  }

  let automationBusy = $state(false);
  async function setAutomation(on: boolean): Promise<void> {
    automationBusy = true;
    try {
      await setEdgeAutomation(on);
      toast.success(on ? 'Automatic protection is on.' : 'Automatic protection is off.');
      invalidateConfig(qc);
    } catch (e) {
      toast.error(edgeErrorMessage(e));
    } finally {
      automationBusy = false;
    }
  }

  function openProtect() {
    setSearchParams({ protect: '1', run: null });
  }
  function closeSheet() {
    setSearchParams({ protect: null, run: null });
    invalidateOverview(qc);
  }
</script>

<SectionHeader title="Nodes">
  {#snippet actions()}
    {#if rows.length > 0}
      <Button onclick={openProtect}>
        <Plus aria-hidden="true" />
        Protect a node
      </Button>
    {/if}
  {/snippet}
</SectionHeader>

<div class="space-y-8">
  {#if summary.isPending || runs.isPending}
    <Skeleton class="h-6 w-64" />
  {:else if summary.isError}
    <AdminListState error={summary.error} onRetry={() => void summary.refetch()} />
  {:else}
    <p class="flex items-center gap-2 text-lg font-medium" role="status">
      <StatusDot dot={headline.dot} class="size-3" />
      {headline.text}
    </p>
  {/if}

  {#if attention.isError}
    <AdminListState error={attention.error} onRetry={() => void attention.refetch()} />
  {:else if items.length > 0 || testEdgeIds.length > 0}
    <section aria-labelledby="needs-you">
      <h2 id="needs-you" class="mb-3 text-base font-semibold">Needs you</h2>
      <div class="space-y-3">
        {#if testEdgeIds.length > 0}
          <EndpointTestCard
            edgeIds={testEdgeIds}
            onClose={() => (testEdgeIds = [])}
            onAllDone={() => {
              const relayId = testRelayId;
              const runId = testRunId;
              testEdgeIds = [];
              testRelayId = null;
              testRunId = null;
              // Every address ticked: resume the activation run the server opened
              // (it re-checks the confirmations and carries on to go-live).
              if (runId)
                void retrySetupRun(runId, {})
                  .then(() => {
                    toast.success('Going live.');
                    invalidateOverview(qc);
                    runParam.value = runId;
                  })
                  .catch((e) => toast.error(edgeErrorMessage(e)));
              else if (relayId)
                void goLive(relayId, null).catch((e) => toast.error(edgeErrorMessage(e)));
            }}
          />
        {/if}
        <AttentionList {items} {onAction} max={5} plain />
      </div>
    </section>
  {/if}

  {#if summary.data && rows.length === 0}
    <div class="rounded-lg border border-dashed p-8 text-center">
      <p class="text-muted-foreground mx-auto max-w-prose text-sm">
        A protected node hands members an address at a provider instead of its own, and FCP replaces
        that address when it stops working. Nothing changes for members until the new address has
        been tested.
      </p>
      <Button class="mt-4" onclick={openProtect}>
        <Plus aria-hidden="true" />
        Protect a node
      </Button>
    </div>
  {:else if rows.length > 0}
    <section aria-label="Protected nodes">
      <ul class="space-y-2">
        {#each rows as row, i (row.relay.id)}
          {@const run = liveRunFor(runList, row.relay.slug)}
          <li>
            <NodeRow
              {row}
              status={statuses[i]!}
              runId={run?.id ?? null}
              onOpenRun={(id) => setSearchParams({ run: id, protect: null })}
            />
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if automation === false}
    <section class="rounded-lg border p-4" aria-labelledby="auto-title">
      <h2 id="auto-title" class="font-semibold">Turn on automatic protection</h2>
      <p class="text-muted-foreground mt-1 max-w-prose text-sm">
        FCP watches every protected node and replaces an address that looks blocked. It keeps one
        spare address per listener, which your provider bills.
      </p>
      <p class="text-muted-foreground mt-2 max-w-prose text-sm">
        Automatic replacement switches to a spare address you have already tested. FCP asks you to
        test each new spare address at the top of this page before it can be used.
      </p>
      <Button class="mt-3" disabled={automationBusy} onclick={() => setAutomation(true)}>
        Turn on
      </Button>
    </section>
  {/if}

  <footer
    class="text-muted-foreground flex flex-wrap items-center justify-between gap-3 border-t pt-4 text-sm"
  >
    {#if automation !== null}
      <div class="flex items-center gap-3">
        <Switch
          id="automation-switch"
          checked={automation}
          disabled={automationBusy}
          onCheckedChange={(v) => void setAutomation(v)}
        />
        <Label for="automation-switch" class="font-normal">
          Automatic protection is {automation ? 'on' : 'off'}
        </Label>
      </div>
    {:else}
      <span></span>
    {/if}
    <Link href={edgesPaths.advanced()} class="hover:text-foreground underline underline-offset-4">
      Advanced
    </Link>
  </footer>
</div>

<!-- Mounted once the accounts are known: the sheet decides its first step from them. -->
{#if sheetOpen && (providers.isSuccess || providers.isError)}
  <ProtectSheet
    open={sheetOpen}
    runId={runParam.value || null}
    startAtAccount={!hasAccount}
    onRunCreated={(id) => setSearchParams({ run: id, protect: null })}
    onClose={closeSheet}
  />
{/if}
