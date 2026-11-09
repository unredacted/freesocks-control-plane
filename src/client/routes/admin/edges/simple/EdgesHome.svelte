<script lang="ts">
  /**
   * Overview (`/admin/servers`, the first tab of the Servers tab bar): "Is
   * anything wrong, and what do I do?" One status sentence, ONE Action needed
   * list, readiness while setup is incomplete, the Automatic work switches,
   * four tiles, the fronted nodes, and recent activity. URL state: `?protect=1`
   * opens the protect sheet (`&server=<slug>&node=<uuid>` preselect a node, as
   * the Nodes page links to it), `?run=<id>` opens a run's progress.
   *
   * Nothing here is asked of the server for this page alone: it reads what the
   * other tabs read (edge attention and summary, each backend's tree, intents,
   * setup, SNI transports, port changes and changes, the countries summary,
   * the provider accounts, the last hour of probes) and
   * ../../servers/overview/overviewModel.ts merges it (pure, unit-tested). Each
   * backend's queries and each fronted node's timeline run in a component that
   * draws nothing (BackendFeed, TimelineFeed) and hands its data up.
   *
   * Edge statuses (each fronted node's row) are the server's ONE judgement: the
   * attention response's `origins[]`, worded by lib/statusWords.ts. A backend
   * node's row opens its Servers node page (its one page).
   *
   * The "Turn on automatic replacement" offer appears once a node is live (and
   * on the Live card of a run), never on the empty home. The switch reads ON
   * when a blocked address can be replaced on its own (the master switch and
   * automatic rotation); a line under it says when spares or probes are left to
   * you (a test deployment keeps spares by hand), so turning it "on" never
   * undoes that.
   *
   * The headline and the rows keep themselves current (lib/livePoll.ts);
   * "Updated N s ago" beside the headline reads them again now.
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { router } from '@client/stores/router.svelte';
  import { searchParam, setSearchParams } from '@client/lib/urlState.svelte';
  import {
    attentionQuery,
    clientCheckStatusQuery,
    countryViewSummaryQuery,
    edgeConfigQuery,
    edgeKeys,
    edgeSummaryQuery,
    invalidateConfig,
    invalidateOverview,
    invalidateRelay,
    probeSummaryQuery,
    providersQuery,
    requireRelayEdges,
    retrySetupRun,
    setEdgeAutomation,
    setupStatusQuery,
    type ProbeRange,
  } from '@client/lib/edgesApi';
  import { serverKeys, serverSummaryQuery } from '@client/lib/serversApi';
  import { nodeHomeOf } from '../../servers/lib/routes';
  import ActionNeeded from '../../servers/overview/ActionNeeded.svelte';
  import AutomaticWork from '../../servers/overview/AutomaticWork.svelte';
  import BackendFeed, { type BackendReport } from '../../servers/overview/BackendFeed.svelte';
  import OverviewTiles from '../../servers/overview/OverviewTiles.svelte';
  import RecentActivity from '../../servers/overview/RecentActivity.svelte';
  import TimelineFeed from '../../servers/overview/TimelineFeed.svelte';
  import {
    mergeActivity,
    mergeAttention,
    overviewTiles,
    atRiskCount,
    frontedCount,
    oldestRead,
    statusSentence,
    type TimelineEntryInput,
  } from '../../servers/overview/overviewModel';
  import AdminListState from '../../AdminListState.svelte';
  import UpdatedAgo from '../../UpdatedAgo.svelte';
  import ReadinessChecklist from '../components/ReadinessChecklist.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import type { AttentionItem } from '../lib/attention';
  import { runAttentionCall } from '../lib/attentionCalls';
  import { attentionCallDeps } from '../lib/attentionCallDeps';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import { statusOf } from '../lib/statusWords';
  import EndpointTestCard from './EndpointTestCard.svelte';
  import NodeRow from './NodeRow.svelte';
  import ProtectSheet from './ProtectSheet.svelte';
  import StatusDot from './StatusDot.svelte';
  import { automationNote, automationState } from './runWords';

  const qc = useQueryClient();
  const summary = edgeSummaryQuery();
  const attention = attentionQuery();
  const config = edgeConfigQuery();
  const servers = serverSummaryQuery();
  const setup = setupStatusQuery(() => null);
  const countries = countryViewSummaryQuery();
  const providers = providersQuery();
  const HOUR: ProbeRange = { kind: 'window', windowMs: 3_600_000 };
  const probeHour = probeSummaryQuery(() => HOUR);

  const protectParam = searchParam('protect');
  const runParam = searchParam('run');
  const serverParam = searchParam('server');
  const nodeParam = searchParam('node');
  const sheetOpen = $derived(protectParam.value === '1' || runParam.value !== '');

  const rows = $derived(
    [...(summary.data?.relays ?? [])].sort((a, b) => a.relay.slug.localeCompare(b.relay.slug)),
  );
  const statuses = $derived(rows.map((r) => statusOf(attention.data?.origins, r.relay.slug)));
  // The server's fleet counts only plain `protected` origins; a fronted node with a
  // warning is still fronted (its warning is "at risk" and Action needed).
  const fleet = $derived(
    attention.data?.fleet
      ? { ...attention.data.fleet, protected: frontedCount(attention.data.origins ?? []) }
      : null,
  );

  // Each observable backend's own queries (BackendFeed) and each fronted node's
  // timeline (TimelineFeed) hand their data up here, keyed by slug.
  const feedBackends = $derived((servers.data?.instances ?? []).filter((i) => i.observable));
  const reports = $state<Record<string, BackendReport>>({});
  function onBackendReport(slug: string, report: BackendReport | null) {
    if (report) reports[slug] = report;
    else delete reports[slug];
  }
  const timelines = $state<Record<string, readonly TimelineEntryInput[]>>({});
  function onTimeline(slug: string, entries: readonly TimelineEntryInput[] | null) {
    if (entries) timelines[slug] = entries;
    else delete timelines[slug];
  }
  const backendReports = $derived(
    feedBackends.map((i) => reports[i.slug]).filter((r): r is BackendReport => !!r),
  );

  const actionRows = $derived(
    mergeAttention({
      // A failed read shows inline in Action needed; its stale items are not listed.
      edge: attention.isError ? [] : (attention.data?.items ?? []),
      backends: backendReports.map((r) => r.input),
      countries: countries.data?.countries ?? [],
      providers: providers.data?.accounts ?? [],
      now: Date.now(),
    }),
  );
  const nodeCounts = $derived.by(() => {
    const read = backendReports.flatMap((r) => (r.nodes ? [r.nodes] : []));
    if (read.length === 0) return null;
    return {
      online: read.reduce((a, n) => a + n.online, 0),
      total: read.reduce((a, n) => a + n.total, 0),
    };
  });
  const headline = $derived(
    statusSentence({
      nodes: nodeCounts,
      fleet,
      rows: actionRows,
      incomplete: attention.isError,
      nodesUnread: backendReports.some((r) => r.input.readFailed),
    }),
  );
  const tiles = $derived(
    overviewTiles({
      nodes: nodeCounts,
      fleet,
      atRisk: attention.data ? atRiskCount(attention.data.origins) : null,
      countries: countries.data?.countries ?? null,
      providers: providers.data?.accounts ?? null,
      probe: {
        usedLastHour: probeHour.data?.totals.runs ?? null,
        hourlyBudget: config.data?.config.probe.hourlyBudget ?? null,
        enabled: config.data?.config.probe.enabled ?? null,
      },
    }),
  );
  const autoState = $derived(config.data ? automationState(config.data.config) : null);
  const automation = $derived(autoState ? autoState.replaces : null);
  const autoNote = $derived(autoState ? automationNote(autoState) : null);
  // FCP's own client check is set up and answering: the switch then turns on
  // replacement without spares (edgeAdmin.setAutomation).
  const clientCheckStatus = clientCheckStatusQuery();
  const clientCheckReady = $derived(
    clientCheckStatus.data?.configured === true && clientCheckStatus.data.health?.ok === true,
  );
  // The oldest read of everything shown, so the line never claims fresher data.
  const updatedAt = $derived(
    oldestRead([
      summary.dataUpdatedAt,
      attention.dataUpdatedAt,
      countries.dataUpdatedAt,
      providers.dataUpdatedAt,
      ...backendReports.map((r) => r.updatedAt),
    ]),
  );
  const refreshNow = () =>
    Promise.all([
      qc.refetchQueries({ queryKey: edgeKeys.summary, type: 'active' }),
      qc.refetchQueries({ queryKey: edgeKeys.attention, type: 'active' }),
      qc.refetchQueries({ queryKey: serverKeys.all, type: 'active' }),
      qc.refetchQueries({ queryKey: edgeKeys.countryViewSummary, type: 'active' }),
      qc.refetchQueries({ queryKey: edgeKeys.providersList, type: 'active' }),
    ]);
  const anyLive = $derived(statuses.some((s) => s?.kind === 'protected'));
  /** A backend node's one page (Servers), else the edges page of the origin. */
  const rowHref = (row: (typeof rows)[number]) =>
    nodeHomeOf(row.relay.origin, servers.data?.instances) ?? edgesPaths.node(row.relay.slug);
  const rowName = (row: (typeof rows)[number]) =>
    row.relay.label ??
    (row.relay.origin.kind === 'panel-node' ? row.relay.origin.nodeName : row.relay.slug);
  const activity = $derived(
    mergeActivity({
      timelines: rows.flatMap((r) => {
        const entries = timelines[r.relay.slug];
        return entries ? [{ slug: r.relay.slug, name: rowName(r), href: rowHref(r), entries }] : [];
      }),
      backends: feedBackends.flatMap((i) => {
        const r = reports[i.slug];
        return r ? [{ slug: i.slug, name: i.name, ops: r.ops }] : [];
      }),
      max: 10,
    }),
  );

  // The test card opened from a "Needs you" row (a spare, a retest, a go-live check).
  let testEdgeIds = $state<string[]>([]);
  let testRelayId = $state<string | null>(null);
  let testRelaySlug = $state<string | null>(null);
  let testRunId = $state<string | null>(null);
  function closeTest() {
    testEdgeIds = [];
    testRelayId = null;
    testRelaySlug = null;
    testRunId = null;
  }

  async function goLive(relayId: string, slug: string | null): Promise<void> {
    const res = await requireRelayEdges(relayId);
    if (res.pending.length > 0) {
      // The server already opened the activation run (needs_you: try_it): the
      // ticks go to that run, never to a second require-edges call.
      testEdgeIds = res.pending.map((p) => p.edgeId);
      testRelayId = relayId;
      testRelaySlug = slug;
      testRunId = res.runId;
      toast.message('Test each address first. Going live continues once every one works.');
      return;
    }
    closeTest();
    toast.success('Going live.');
    if (slug) invalidateRelay(qc, slug);
    else invalidateOverview(qc);
    runParam.value = res.runId;
  }

  /**
   * Server-call attention actions (lib/attentionCalls.ts): a publish puts the
   * named spare in use and opens its run, the test card and go-live open here.
   */
  const attentionDeps = attentionCallDeps(qc, {
    plain: true,
    openTest: (item) => {
      testEdgeIds = item.edgeId ? [item.edgeId] : [];
      testRelayId = null;
      testRelaySlug = item.relaySlug;
      testRunId = null;
    },
    goLive: (item) => goLive(item.relayId!, item.relaySlug),
  });
  const onAction = (item: AttentionItem) => runAttentionCall(item, attentionDeps);

  let automationBusy = $state(false);
  async function setAutomation(on: boolean): Promise<void> {
    automationBusy = true;
    try {
      await setEdgeAutomation(on);
      toast.success(on ? 'Automatic replacement is on.' : 'Automatic replacement is off.');
      invalidateConfig(qc);
    } catch (e) {
      toast.error(edgeErrorMessage(e));
    } finally {
      automationBusy = false;
    }
  }

  // The preset node (`server`, `node`) belongs to one opening of the sheet only.
  function openProtect() {
    setSearchParams({ protect: '1', run: null, server: null, node: null });
  }
  function closeSheet() {
    setSearchParams({ protect: null, run: null, server: null, node: null });
    invalidateOverview(qc);
  }
</script>

{#each feedBackends as b (b.slug)}
  <BackendFeed
    slug={b.slug}
    name={b.name}
    writable={b.writable}
    setUp={b.setUp}
    manageOn={servers.data?.config['manage.enabled'] ?? false}
    onReport={onBackendReport}
  />
{/each}
{#each rows as r (r.relay.id)}
  <TimelineFeed id={r.relay.id} slug={r.relay.slug} onReport={onTimeline} />
{/each}

<SectionHeader title="Overview" description="What needs you, and the switches that run the fleet.">
  {#snippet actions()}
    {#if rows.length > 0}
      <Button onclick={openProtect}>
        <Plus aria-hidden="true" />
        Front a node
      </Button>
    {/if}
  {/snippet}
</SectionHeader>

<div class="space-y-8">
  {#if summary.isPending || attention.isPending}
    <Skeleton class="h-6 w-64" />
  {:else if summary.isError}
    <AdminListState error={summary.error} onRetry={() => void summary.refetch()} />
  {:else}
    <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
      <p class="flex items-center gap-2 text-lg font-medium" role="status">
        <StatusDot dot={headline.dot} class="size-3" />
        {headline.text}
      </p>
      <UpdatedAgo at={updatedAt} onRefresh={refreshNow} />
    </div>
  {/if}

  {#if !attention.isPending}
    <!-- A failed edge attention read shows inline; the other sources' rows still list. -->
    <ActionNeeded
      rows={actionRows}
      {onAction}
      edgeError={attention.isError ? attention.error : null}
      onEdgeRetry={() => void attention.refetch()}
    >
      {#snippet top()}
        {#if testEdgeIds.length > 0}
          <EndpointTestCard
            edgeIds={testEdgeIds}
            runId={testRunId}
            onClose={closeTest}
            onRetried={(id) => {
              closeTest();
              setSearchParams({ run: id, protect: null, server: null, node: null });
            }}
            onDoesNotWork={testRelaySlug
              ? (edgeId) => {
                  // The node page knows what the address is (in use or a spare) and how to replace it.
                  const slug = testRelaySlug!;
                  closeTest();
                  router.navigate(edgesPaths.node(slug, { test: edgeId }));
                }
              : undefined}
            onAllDone={() => {
              const relayId = testRelayId;
              const runId = testRunId;
              closeTest();
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
      {/snippet}
    </ActionNeeded>
  {/if}

  {#if setup.data && !setup.data.complete}
    <section aria-labelledby="readiness">
      <h2 id="readiness" class="mb-1 text-base font-semibold">Readiness</h2>
      <p class="text-muted-foreground mb-3 text-sm">
        What is left before addresses can be replaced on their own.
      </p>
      <ReadinessChecklist status={setup.data} compact />
    </section>
  {/if}

  <AutomaticWork
    {automation}
    automationNote={autoNote}
    {automationBusy}
    onAutomation={(v) => void setAutomation(v)}
  />

  <OverviewTiles {tiles} />

  {#if summary.data && rows.length === 0}
    <div class="rounded-lg border border-dashed p-8 text-center">
      <p class="text-muted-foreground mx-auto max-w-prose text-sm">
        A fronted node gives members a provider address instead of its own, and FCP replaces it when
        it stops working. Members see no change until the new address is tested.
      </p>
      <Button class="mt-4" onclick={openProtect}>
        <Plus aria-hidden="true" />
        Front a node
      </Button>
    </div>
  {:else if rows.length > 0}
    <section aria-labelledby="fronted-nodes">
      <h2 id="fronted-nodes" class="mb-3 text-base font-semibold">Fronted nodes</h2>
      <ul class="space-y-2">
        {#each rows as row, i (row.relay.id)}
          <li>
            <NodeRow
              {row}
              status={statuses[i] ?? null}
              href={rowHref(row)}
              onOpenRun={(id) =>
                setSearchParams({ run: id, protect: null, server: null, node: null })}
            />
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if automation === false && anyLive}
    <section class="rounded-lg border p-4" aria-labelledby="auto-title">
      <h2 id="auto-title" class="font-semibold">Turn on automatic replacement</h2>
      {#if clientCheckReady}
        <p class="text-muted-foreground mt-1 max-w-prose text-sm">
          When an address looks blocked, FCP makes a new one in a tested location, checks it with
          its own sing-box and Xray clients, and moves members to it. Nothing extra is billed until
          an address is blocked.
        </p>
        <p class="text-muted-foreground mt-2 max-w-prose text-sm">
          With 2 addresses in use, members use the other one during a replacement. With 1, members
          in the blocking country wait about 10 to 15 minutes.
        </p>
      {:else}
        <p class="text-muted-foreground mt-1 max-w-prose text-sm">
          FCP replaces an address that looks blocked on any fronted node. It keeps one spare per
          listener, billed by your provider.
        </p>
        <p class="text-muted-foreground mt-2 max-w-prose text-sm">
          It switches to a spare you have tested. Test each new spare at the top of this page before
          it can be used.
        </p>
      {/if}
      <Button class="mt-3" disabled={automationBusy} onclick={() => setAutomation(true)}>
        Turn on
      </Button>
    </section>
  {/if}

  <RecentActivity entries={activity} />

  <footer class="text-muted-foreground border-t pt-4 text-sm">
    <Link href={edgesPaths.overview()} class="hover:text-foreground underline underline-offset-4">
      All fronted nodes
    </Link>
  </footer>
</div>

<!-- The node always comes first; the account step adds one when there is none. -->
{#if sheetOpen}
  <ProtectSheet
    open={sheetOpen}
    runId={runParam.value || null}
    server={serverParam.value || null}
    node={nodeParam.value || null}
    onRunCreated={(id) => setSearchParams({ run: id, protect: null, server: null, node: null })}
    onClose={closeSheet}
  />
{/if}
