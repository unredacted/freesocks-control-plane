<script lang="ts">
  /**
   * A node's edges, as one panel (no tabs): the status sentence (the server's
   * origin status, worded by lib/statusWords.ts), the actions (Go live or
   * Replace address, and More: a spare, Protect again, Origin details, Remove
   * protection), the paused card, the test card, the addresses in use per
   * transport, the per-node automatic switch and recent activity in plain
   * words. URL state: `?test=<edgeId>` opens the test card for that address.
   *
   * It lives on the node's own page: the Servers node page embeds it (lazily)
   * for a backend node, and `/admin/edges/nodes/<slug>` shows it for an origin
   * that is not a backend node (manual, a whole Outline server).
   *
   * It keeps itself current (lib/livePoll.ts): its lists poll every 30 s, every
   * 4 s while something runs on the node, and a change the origin lookup or
   * attention sees (an automatic replacement shorter than one poll) refreshes
   * them at once. "Updated N s ago" beside the status reads them again now.
   *
   * "Protect again" (an enrolled node that is live behind edges): a re-protect
   * run (new addresses, Try it, the approval when one is needed) in the protect
   * sheet's progress. Members keep what they have until it goes live; a cancel
   * drops only the new addresses. It is the primary action while the node waits
   * to be protected again (its stage is not `live`).
   *
   * On the test card "Doesn't work" replaces that one address: an address in
   * use opens "Replace now", a spare is renewed (SpareDialog), a go-live check
   * retries its run for that line.
   *
   * "Put it in use" on a spare: while fewer addresses are in use than the node
   * wants, the server's `pool_below_desired` attention item names the one spare
   * that passes the publish checks; its line offers the same publish as the
   * Edges home (lib/attentionCalls.ts), which opens the run. When the free slot
   * is held for what the node still lacks (reserved allocation: the item's code
   * `pool_reserved`, or the providers view's `spares`), the confirm says the
   * address would stay a spare and for which location the slot is held, and
   * offers Replace address instead of a publish that ends as a spare.
   *
   * Recent activity names a failed run by what it was (adding a spare is no
   * replacement) with the provider's words, and links it to the run.
   *
   * A retiring address (drained after a Replace) says when it is deleted; "Delete
   * now" ends its drain early (DELETE the edge: members who have not refreshed
   * lose it), "Keep as a spare" puts it back among the spares (the operator
   * reactivate). Both refuse while a rotation, a restore or a pause holds the
   * origin, so they are offered only when nothing does.
   *
   * Each address in use or spare says what it counts as from each checked
   * country (works, blocked since, down, not checked, why, and whether that
   * comes from its own checks, its location or a mark), with "Mark for a
   * country" and "Check from every country now" in its Countries menu. The
   * checks read every 30 s, every 4 s while a check asked for here is out.
   *
   * Props:
   *   slug: string                          the origin's slug
   *   enrolled?: { stage: string } | null   the enrolled node behind it (Servers knows)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import { Label } from '@client/components/ui/label';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import Link from '@client/components/Link.svelte';
  import { router } from '@client/stores/router.svelte';
  import { searchParam } from '@client/lib/urlState.svelte';
  import {
    PLAIN_ATTENTION_ACTION_LABELS,
    plainAuditActionLabel,
    plainWords,
    restorePhaseWords,
  } from '@client/lib/edgeCodes';
  import {
    attentionQuery,
    deleteEdge,
    deleteRelay,
    edgeConfigQuery,
    edgeCountriesQuery,
    edgeKeys,
    invalidateRelay,
    relayEdgesQuery,
    relayListenersQuery,
    relayLookupQuery,
    relayProvidersQuery,
    relayTimelineQuery,
    reprotectRelay,
    requireRelayEdges,
    resolveEdgeOperator,
    retrySetupRun,
    updateRelay,
  } from '@client/lib/edgesApi';
  import { originBusy } from '@client/lib/livePoll';
  import type { EdgeAdmin } from '@shared/contracts/edges';
  import AdminListState from '../../AdminListState.svelte';
  import UpdatedAgo from '../../UpdatedAgo.svelte';
  import Timeline from '../components/Timeline.svelte';
  import ActionConfirm from '../relay/ActionConfirm.svelte';
  import ReplaceDialog from '../relay/ReplaceDialog.svelte';
  import { ATTENTION_ACTION_PLAN } from '../lib/attention';
  import { runAttentionCall } from '../lib/attentionCalls';
  import { attentionCallDeps } from '../lib/attentionCallDeps';
  import { anyCountryCheckPending } from '../lib/countryCheckRequests';
  import { assertEdgeOk, edgeErrorMessage } from '../lib/edgeErrors';
  import { transportName } from '../lib/format';
  import { edgesPaths } from '../lib/routes';
  import { originSentence, statusOf } from '../lib/statusWords';
  import { timelineLinkParams } from '../relay/relayLogic';
  import EndpointTestCard from './EndpointTestCard.svelte';
  import ListenerAddresses from './ListenerAddresses.svelte';
  import NodeProvidersCard from './NodeProvidersCard.svelte';
  import PausedCard from './PausedCard.svelte';
  import SpareDialog from './SpareDialog.svelte';
  import StatusDot from './StatusDot.svelte';
  import { endNowWords } from './drainWords';
  import {
    heldSpareWords,
    nodeAutomationWords,
    spareInUseWords,
    upkeepAddsMissing,
    type SpareSlot,
  } from './runWords';

  interface Props {
    slug: string;
    enrolled?: { stage: string } | null;
  }
  let { slug, enrolled = null }: Props = $props();
  const uid = $props.id();

  const qc = useQueryClient();
  const relayQ = relayLookupQuery(() => slug);
  const relay = $derived(relayQ.data ?? null);
  const attention = attentionQuery();
  const ref = {
    slug: () => slug,
    id: () => relay?.id ?? null,
    // Faster while anything runs on the node: a rotation, a setup run, a restore.
    rotating: () =>
      (!!relay && originBusy(relay)) || !!statusOf(attention.data?.origins, slug)?.runId,
  };
  const listenersQ = relayListenersQuery(ref);
  const edgesQ = relayEdgesQuery(ref);
  // The pool against the provider set: what the free slots are held for, per spare.
  const setQ = relayProvidersQuery(ref);
  const timelineQ = relayTimelineQuery(ref);
  const config = edgeConfigQuery();
  const countriesQ = edgeCountriesQuery({ busy: (d) => anyCountryCheckPending(d) });
  const testParam = searchParam('test');

  const listeners = $derived((listenersQ.data?.listeners ?? []).filter((l) => !l.retired));
  const edges = $derived((edgesQ.data ?? []).filter((e) => e.status !== 'destroyed'));
  const published = $derived(edges.filter((e) => e.publication === 'published'));
  // The ONE status the server judged for this origin (the attention response).
  const status = $derived(statusOf(attention.data?.origins, slug));
  const runId = $derived(status?.runId ?? null);
  // The newest setup run when it stopped: its sheet has Try again.
  const failedRunId = $derived(status?.failedRunId ?? null);
  const autoWords = $derived(
    config.data && relay
      ? nodeAutomationWords(config.data.config, { ...relay, runLive: !!runId })
      : null,
  );
  /** Where one spare (or retiring address) stands against the pool. */
  const slotOf = (edgeId: string): SpareSlot | null =>
    setQ.data
      ? {
          takesSlot: setQ.data.spares.find((x) => x.edgeId === edgeId)?.takesSlot ?? null,
          missing: setQ.data.missing,
          held: setQ.data.pool?.held,
        }
      : null;
  // Whether automatic upkeep adds what the node still lacks (the providers card says).
  const upkeepAdds = $derived(
    !!config.data && !!relay && upkeepAddsMissing(config.data.config, relay),
  );
  // The oldest of what the panel shows, and one way to read it all again now.
  const updatedAt = $derived(
    Math.min(relayQ.dataUpdatedAt, listenersQ.dataUpdatedAt, edgesQ.dataUpdatedAt),
  );
  const refreshNow = () =>
    Promise.all([
      qc.refetchQueries({ queryKey: edgeKeys.relay(slug), type: 'active' }),
      qc.refetchQueries({ queryKey: edgeKeys.attention, type: 'active' }),
    ]);
  const name = $derived(
    relay
      ? (relay.label ?? (relay.origin.kind === 'panel-node' ? relay.origin.nodeName : relay.slug))
      : slug,
  );
  const busy = $derived(!!relay?.activeRotationId || !!runId);
  // Protect again: an enrolled node that is live behind edges, nothing else running on it.
  const canProtectAgain = $derived(
    !!enrolled &&
      !!relay &&
      relay.origin.kind === 'panel-node' &&
      !relay.bindingDeferred &&
      !relay.setupOwned &&
      !relay.restore &&
      !relay.deleting &&
      !relay.quarantine &&
      !busy,
  );
  const protectAgainFirst = $derived(canProtectAgain && enrolled?.stage !== 'live');
  // A first protection that stopped short with nothing in use and no run to
  // open (an earlier cancel left it): the protect sheet picks it up again.
  const continueSetup = $derived(
    relay &&
      relay.origin.kind === 'panel-node' &&
      relay.origin.nodeUuid &&
      relay.setupOwned &&
      !runId &&
      !failedRunId &&
      !relay.restore &&
      !relay.deleting &&
      published.length === 0
      ? edgesPaths.home({
          protect: '1',
          server: relay.origin.backendServerId,
          node: relay.origin.nodeUuid,
        })
      : null,
  );

  // Put a spare in use: the server's publish item for this origin (it names the
  // spare that passes the publish checks), and the same call the Edges home makes.
  const putInUse = $derived(
    attention.data?.items.find(
      (i) =>
        i.kind === 'pool_below_desired' &&
        (i.action === 'publish' || i.code === 'pool_reserved') &&
        i.relaySlug === slug &&
        i.edgeId,
    ) ?? null,
  );
  // That spare would stay a spare: its free slot is held for what the node lacks.
  const putInUseHeld = $derived(
    !!putInUse &&
      (putInUse.code === 'pool_reserved' || slotOf(putInUse.edgeId!)?.takesSlot === false),
  );
  const PUBLISH = ATTENTION_ACTION_PLAN.publish.confirm;
  const publishDeps = attentionCallDeps(qc, { plain: true });
  let putInUseOpen = $state(false);

  // Replace: one published address, or a choice when several are in use.
  let replacing = $state<{ kind: 'rotate' | 'burn'; edge: EdgeAdmin } | null>(null);
  let choosing = $state<'rotate' | 'burn' | null>(null);
  function replace(kind: 'rotate' | 'burn') {
    if (published.length === 1) replacing = { kind, edge: published[0]! };
    else choosing = kind;
  }
  // A retiring address: end its drain now, or keep it as a spare.
  let ending = $state<{ edge: EdgeAdmin; action: 'delete' | 'keep' } | null>(null);
  const canEndDrains = $derived(
    !!relay && !relay.deleting && !relay.restore && !relay.quarantine && !relay.activeRotationId,
  );
  const addressOf = (e: EdgeAdmin) =>
    e.addresses.hostname ?? e.addresses.v4 ?? e.addresses.v6 ?? e.name;
  let spareOpen = $state(false);
  let renewing = $state<{ edgeId: string; listenerId: string; listenerKey: string } | null>(null);
  let removeOpen = $state(false);
  let againOpen = $state(false);
  let testEdgeIds = $state<string[]>([]);
  // The activation run the server opened when go-live found untested addresses.
  let testRunId = $state<string | null>(null);
  $effect(() => {
    if (testParam.value) testEdgeIds = [testParam.value];
  });

  function closeTest() {
    testEdgeIds = [];
    testParam.value = null;
    testRunId = null;
  }
  /** "Doesn't work" outside a run: replace the address in use, or renew the spare. */
  function doesNotWork(edgeId: string) {
    const edge = edges.find((e) => e.id === edgeId);
    if (!edge) return;
    closeTest();
    if (edge.publication === 'published') {
      replacing = { kind: 'burn', edge };
      return;
    }
    const listenerKey = listeners.find((l) => l.id === edge.listenerId)?.listenerKey;
    if (listenerKey) renewing = { edgeId, listenerId: edge.listenerId, listenerKey };
  }

  // A run that failed or kept its address a spare links to the run itself.
  const runHref = (entry: {
    action: string;
    targetType: string | null;
    targetId: string | null;
    payload: unknown;
  }) => {
    if (entry.action !== 'edge.rotation_failed' && entry.action !== 'edge.publish_held')
      return null;
    const rotation = timelineLinkParams(entry)?.rotation;
    return rotation ? edgesPaths.relay(slug, { tab: 'rotations', rotation }) : null;
  };

  let autoBusy = $state(false);
  async function setAuto(next: boolean) {
    if (!relay) return;
    autoBusy = true;
    try {
      assertEdgeOk(await updateRelay(relay.id, { autoRotate: next }));
      invalidateRelay(qc, slug);
    } catch (e) {
      toast.error(edgeErrorMessage(e));
    } finally {
      autoBusy = false;
    }
  }
  let goLiveBusy = $state(false);
  async function goLive() {
    if (!relay) return;
    goLiveBusy = true;
    try {
      const res = await requireRelayEdges(relay.id);
      if (res.pending.length > 0) {
        testEdgeIds = res.pending.map((p) => p.edgeId);
        testRunId = res.runId;
        toast.message('Test each address first. Going live continues once every one works.');
      } else {
        toast.success('Going live.');
        router.navigate(edgesPaths.home({ run: res.runId }));
      }
      invalidateRelay(qc, slug);
    } catch (e) {
      toast.error(edgeErrorMessage(e));
    } finally {
      goLiveBusy = false;
    }
  }
</script>

<section aria-labelledby={`${uid}-edges`} class="touch-44 space-y-6">
  <div class="flex flex-wrap items-start justify-between gap-3">
    <div class="min-w-0">
      <h2 id={`${uid}-edges`} class="text-base font-semibold">Edges</h2>
      {#if relay && status}
        <p class="mt-1 flex flex-wrap items-center gap-x-2 text-sm font-medium" role="status">
          <StatusDot dot={status.dot} />
          {originSentence(status)}
          {#if runId}
            <Link
              href={edgesPaths.home({ run: runId })}
              class="text-primary inline-flex min-h-11 items-center text-sm font-normal underline underline-offset-4 sm:min-h-0"
            >
              Watch
            </Link>
          {:else if failedRunId}
            <Link
              href={edgesPaths.home({ run: failedRunId })}
              class="text-primary inline-flex min-h-11 items-center text-sm font-normal underline underline-offset-4 sm:min-h-0"
            >
              Open the run
            </Link>
          {/if}
        </p>
        {#if relay.restore}
          <p class="text-muted-foreground mt-1 text-sm">
            Removing protection: {restorePhaseWords(relay.restore.phase)}.
          </p>
        {/if}
        <UpdatedAgo at={updatedAt} onRefresh={refreshNow} />
      {:else if !relayQ.error}
        <Skeleton class="mt-2 h-5 w-64" />
      {/if}
    </div>
    {#if relay}
      <div class="flex shrink-0 flex-wrap items-center gap-2">
        {#if protectAgainFirst}
          <Button onclick={() => (againOpen = true)}>Protect again</Button>
        {:else if relay.bindingDeferred && !runId && published.length > 0}
          <Button disabled={goLiveBusy} onclick={goLive}>Go live</Button>
        {:else if published.length > 0}
          <Button disabled={busy} onclick={() => replace('rotate')}>Replace address</Button>
        {:else if continueSetup}
          <Button onclick={() => router.navigate(continueSetup)}>Continue setup</Button>
        {/if}
        <DropdownMenu.Root>
          <DropdownMenu.Trigger>
            {#snippet child({ props })}
              <Button {...props} variant="outline" aria-label="More edge actions">
                More <ChevronDown aria-hidden="true" />
              </Button>
            {/snippet}
          </DropdownMenu.Trigger>
          <DropdownMenu.Content align="end" class="w-64">
            {#if published.length > 0}
              <DropdownMenu.Item disabled={busy} onSelect={() => replace('burn')}>
                Replace now, address is blocked
              </DropdownMenu.Item>
            {/if}
            <DropdownMenu.Item disabled={busy} onSelect={() => (spareOpen = true)}>
              Add a spare address
            </DropdownMenu.Item>
            {#if canProtectAgain && !protectAgainFirst}
              <DropdownMenu.Item onSelect={() => (againOpen = true)}
                >Protect again</DropdownMenu.Item
              >
            {/if}
            <DropdownMenu.Item onSelect={() => router.navigate(edgesPaths.relay(relay.slug))}>
              Origin details
            </DropdownMenu.Item>
            <DropdownMenu.Separator />
            <DropdownMenu.Item
              variant="destructive"
              disabled={relay.deleting || !!relay.restore}
              onSelect={() => (removeOpen = true)}
            >
              Remove protection
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Root>
      </div>
    {/if}
  </div>

  {#if relayQ.error && !relay}
    <AdminListState error={relayQ.error} onRetry={() => void relayQ.refetch()} />
  {:else if relay}
    {#if relay.quarantine}
      <PausedCard {relay} />
    {/if}

    {#if testEdgeIds.length > 0}
      <EndpointTestCard
        edgeIds={testEdgeIds}
        runId={testRunId}
        nameOf={(key) => {
          const l = listeners.find((x) => x.listenerKey === key);
          return l ? transportName(l) : null;
        }}
        onClose={closeTest}
        onRetried={(id) => {
          closeTest();
          router.navigate(edgesPaths.home({ run: id }));
        }}
        onDoesNotWork={doesNotWork}
        onAllDone={() => {
          const runId = testRunId;
          closeTest();
          invalidateRelay(qc, slug);
          // Every address ticked: resume the activation run the server opened
          // rather than asking for go-live a second time.
          if (runId)
            void retrySetupRun(runId, {})
              .then(() => {
                toast.success('Going live.');
                router.navigate(edgesPaths.home({ run: runId }));
              })
              .catch((e) => toast.error(edgeErrorMessage(e)));
        }}
      />
    {/if}

    <section aria-labelledby={`${uid}-addresses`}>
      <h3 id={`${uid}-addresses`} class="mb-3 text-sm font-semibold">Addresses in use</h3>
      {#if listenersQ.isPending || edgesQ.isPending}
        <Skeleton class="h-20 w-full" />
      {:else if listenersQ.isError}
        <AdminListState error={listenersQ.error} onRetry={() => void listenersQ.refetch()} />
      {:else if edgesQ.isError}
        <AdminListState error={edgesQ.error} onRetry={() => void edgesQ.refetch()} />
      {:else if listeners.length === 0}
        <p class="text-muted-foreground text-sm">This node has no transport FCP can protect yet.</p>
      {:else}
        <ul class="space-y-3">
          {#each listeners as l (l.id)}
            <li class="rounded-lg border p-3">
              <p class="text-sm font-medium">{transportName(l)}</p>
              <ListenerAddresses
                listener={l}
                {edges}
                onTest={(edgeId) => (testEdgeIds = [edgeId])}
                publishable={busy ? null : (putInUse?.edgeId ?? null)}
                onPublish={() => (putInUseOpen = true)}
                onRetiring={canEndDrains
                  ? (edge, action) => (ending = { edge, action })
                  : undefined}
                countries={countriesQ.data ?? null}
              />
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    {#if relay.origin.kind === 'panel-node'}
      <NodeProvidersCard
        relay={{ id: relay.id, slug: relay.slug }}
        {busy}
        {upkeepAdds}
        nameOf={(key) => {
          const l = listeners.find((x) => x.listenerKey === key);
          return l ? transportName(l) : key;
        }}
        onRunStarted={(id) => router.navigate(edgesPaths.home({ run: id }))}
      />
    {/if}

    <section class="flex items-start justify-between gap-4 rounded-lg border p-3">
      <div class="min-w-0">
        <Label for={`${uid}-auto`}>Replace addresses automatically on this node</Label>
        {#if autoWords}
          <p class="text-muted-foreground text-xs">{autoWords.line}</p>
          {#if autoWords.spares}
            <p class="text-muted-foreground mt-1 text-xs">{autoWords.spares}</p>
          {/if}
        {/if}
      </div>
      <Switch
        id={`${uid}-auto`}
        checked={relay.autoRotate}
        disabled={autoBusy}
        onCheckedChange={(v) => void setAuto(v)}
      />
    </section>

    <section aria-labelledby={`${uid}-activity`}>
      <h3 id={`${uid}-activity`} class="mb-3 text-sm font-semibold">Recent activity</h3>
      {#if timelineQ.isPending}
        <Skeleton class="h-24 w-full" />
      {:else if timelineQ.isError}
        <AdminListState error={timelineQ.error} onRetry={() => void timelineQ.refetch()} />
      {:else}
        <Timeline
          entries={timelineQ.data?.entries ?? []}
          max={8}
          labelFor={plainAuditActionLabel}
          hrefFor={runHref}
          listenerName={(key) => {
            const l = listeners.find((x) => x.listenerKey === key);
            return l ? transportName(l) : 'a transport';
          }}
          label="Recent activity"
        />
      {/if}
    </section>
  {:else}
    <Skeleton class="h-32 w-full" />
  {/if}
</section>

{#if relay}
  {#if replacing}
    <ReplaceDialog
      open={true}
      plain
      kind={replacing.kind}
      {relay}
      {edges}
      edge={replacing.edge}
      onClose={() => (replacing = null)}
      onStarted={() => {
        toast.success('Replacing the address. Members move over on their next refresh.');
        replacing = null;
      }}
    />
  {/if}
  {#if choosing}
    {@const kind = choosing}
    <ActionConfirm
      open={true}
      title="Which address?"
      body="Several addresses are in use on this node. Pick the one to replace."
      confirmLabel="Choose"
      disabled
      run={async () => {}}
      onClose={() => (choosing = null)}
    >
      <div class="flex flex-col gap-2">
        {#each published as e (e.id)}
          <Button
            variant="outline"
            size="sm"
            onclick={() => {
              choosing = null;
              replacing = { kind, edge: e };
            }}
          >
            {e.addresses.hostname ?? e.addresses.v4 ?? e.addresses.v6 ?? e.name}
          </Button>
        {/each}
      </div>
    </ActionConfirm>
  {/if}
  {#if ending}
    {@const e = ending.edge}
    {#if ending.action === 'delete'}
      {@const w = endNowWords(e, addressOf(e))}
      <ActionConfirm
        open={true}
        title={w.title}
        body={w.body}
        confirmLabel={w.label}
        danger
        onClose={() => (ending = null)}
        run={async () => {
          assertEdgeOk(await deleteEdge(e.id));
          toast.success(w.done);
          invalidateRelay(qc, slug);
        }}
      />
    {:else}
      {@const keepNote = config.data
        ? spareInUseWords(config.data.config, relay, slotOf(e.id))
        : null}
      <ActionConfirm
        open={true}
        title={`Keep ${addressOf(e)} as a spare?`}
        body={`It stops retiring and is not deleted. Members are not given it; it waits as a spare and can be put in use again later. Your provider keeps billing for it.${
          keepNote ? ` ${keepNote}` : ''
        }`}
        confirmLabel="Keep as a spare"
        onClose={() => (ending = null)}
        run={async () => {
          assertEdgeOk(await resolveEdgeOperator(e.id, 'reactivate'));
          toast.success(`${addressOf(e)} is a spare again.`);
          invalidateRelay(qc, slug);
        }}
      />
    {/if}
  {/if}
  <SpareDialog
    bind:open={spareOpen}
    {relay}
    listeners={listeners.map((l) => ({ id: l.id, listenerKey: l.listenerKey }))}
  />
  {#if putInUse && putInUseHeld}
    {@const spare = edges.find((x) => x.id === putInUse.edgeId)}
    <!-- The free slot is held for what the node lacks: a publish would end as a spare. -->
    <ActionConfirm
      bind:open={putInUseOpen}
      title={`${spare ? addressOf(spare) : 'This address'} stays a spare`}
      body={heldSpareWords(slotOf(putInUse.edgeId!) ?? { missing: [] })}
      confirmLabel="Replace address"
      disabled={busy || published.length === 0}
      run={async () => replace('rotate')}
    />
  {:else if putInUse}
    {@const item = putInUse}
    <ActionConfirm
      bind:open={putInUseOpen}
      title={plainWords(PUBLISH.title)}
      body={plainWords(PUBLISH.body)}
      confirmLabel={PLAIN_ATTENTION_ACTION_LABELS.publish}
      run={() => runAttentionCall(item, publishDeps)}
    />
  {/if}
  {#if renewing}
    <SpareDialog open={true} {relay} renew={renewing} onClose={() => (renewing = null)} />
  {/if}
  <ActionConfirm
    bind:open={againOpen}
    title={`Protect ${name} again?`}
    body="FCP makes a new address for each transport, you try each one from a real app, and you approve go-live if the node needs it. Members keep the addresses they have until the new ones go live, then the new ones take their places. Cancelling drops only the new addresses."
    confirmLabel="Protect again"
    run={async () => {
      const res = await reprotectRelay(relay.id);
      toast.success('Protecting again. The progress opens now.');
      invalidateRelay(qc, slug);
      router.navigate(edgesPaths.home({ run: res.runId }));
    }}
  />
  <ActionConfirm
    bind:open={removeOpen}
    title={`Remove protection from ${name}?`}
    body="Members get the node's own address back at their next refresh, the panel is restored one checked step at a time, and the provider addresses are destroyed afterwards. The node's own address becomes visible again."
    typed={relay.slug}
    confirmLabel="Remove protection"
    danger
    run={async () => {
      assertEdgeOk(await deleteRelay(relay.id, 'restore-direct'));
      toast.success('Removing protection. The node page shows each step.');
      invalidateRelay(qc, slug);
    }}
  />
{/if}
