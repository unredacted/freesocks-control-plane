<script lang="ts">
  /**
   * One protected node (`/admin/edges/nodes/:slug`), no tabs: the status
   * sentence, the addresses in use per inbound, "Replace address", the
   * per-node automatic switch, recent activity in plain words, and a More
   * menu (spare address, remove protection, advanced details). URL state:
   * `?test=<edgeId>` opens the test card for that address.
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { ApiCallError } from '@client/lib/api';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import { Label } from '@client/components/ui/label';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import Link from '@client/components/Link.svelte';
  import { router } from '@client/stores/router.svelte';
  import { searchParam } from '@client/lib/urlState.svelte';
  import { countryName } from '@client/lib/countries';
  import { plainAuditActionLabel, restorePhaseWords } from '@client/lib/edgeCodes';
  import {
    attentionQuery,
    deleteRelay,
    edgeConfigQuery,
    invalidateRelay,
    relayEdgesQuery,
    relayListenersQuery,
    relayLookupQuery,
    relayTimelineQuery,
    requireRelayEdges,
    retrySetupRun,
    setupRunsQuery,
    updateRelay,
  } from '@client/lib/edgesApi';
  import type { EdgeAdmin } from '@shared/contracts/edges';
  import AdminListState from '../../AdminListState.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import Timeline from '../components/Timeline.svelte';
  import ActionConfirm from '../relay/ActionConfirm.svelte';
  import ProvisionDialog from '../relay/ProvisionDialog.svelte';
  import ReplaceDialog from '../relay/ReplaceDialog.svelte';
  import { assertEdgeOk, edgeErrorMessage } from '../lib/edgeErrors';
  import { protocolLine } from '../lib/format';
  import { edgesPaths } from '../lib/routes';
  import EndpointTestCard from './EndpointTestCard.svelte';
  import ListenerAddresses from './ListenerAddresses.svelte';
  import StatusDot from './StatusDot.svelte';
  import { liveRunFor, nodeStatus } from './nodeStatus';
  import { automationOn } from './runWords';

  interface Props {
    slug: string;
  }
  let { slug }: Props = $props();

  const qc = useQueryClient();
  const relayQ = relayLookupQuery(() => slug);
  const relay = $derived(relayQ.data ?? null);
  const ref = {
    slug: () => slug,
    id: () => relay?.id ?? null,
    rotating: () => !!relay?.activeRotationId,
  };
  const listenersQ = relayListenersQuery(ref);
  const edgesQ = relayEdgesQuery(ref);
  const timelineQ = relayTimelineQuery(ref);
  const attention = attentionQuery();
  const runs = setupRunsQuery();
  const config = edgeConfigQuery();
  const testParam = searchParam('test');

  const listeners = $derived((listenersQ.data?.listeners ?? []).filter((l) => !l.retired));
  const edges = $derived((edgesQ.data ?? []).filter((e) => e.status !== 'destroyed'));
  const published = $derived(edges.filter((e) => e.publication === 'published'));
  const run = $derived(liveRunFor(runs.data?.runs ?? [], slug));
  const status = $derived(
    relay
      ? nodeStatus(
          {
            relay,
            pool: published.map((e) => ({ health: e.health })),
            standbys: edges.filter((e) => e.publication === 'unpublished' && e.status === 'active')
              .length,
          },
          { attention: attention.data?.items ?? [], runs: runs.data?.runs ?? [] },
        )
      : null,
  );
  const globalOn = $derived(config.data ? automationOn(config.data.config) : true);
  const notFound = $derived(relayQ.error instanceof ApiCallError && relayQ.error.status === 404);
  const name = $derived(
    relay
      ? (relay.label ?? (relay.origin.kind === 'panel-node' ? relay.origin.nodeName : relay.slug))
      : slug,
  );

  // Replace: one published address, or a choice when several are in use.
  let replacing = $state<{ kind: 'rotate' | 'burn'; edge: EdgeAdmin } | null>(null);
  let choosing = $state<'rotate' | 'burn' | null>(null);
  function replace(kind: 'rotate' | 'burn') {
    if (published.length === 1) replacing = { kind, edge: published[0]! };
    else choosing = kind;
  }
  let spareOpen = $state(false);
  let removeOpen = $state(false);
  let testEdgeIds = $state<string[]>([]);
  // The activation run the server opened when go-live found untested addresses.
  let testRunId = $state<string | null>(null);
  $effect(() => {
    if (testParam.value) testEdgeIds = [testParam.value];
  });

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

{#if notFound}
  <SectionHeader title="Node not found" back={{ href: edgesPaths.home(), label: 'Nodes' }} />
  <p class="text-muted-foreground text-sm">
    There is no protected node called "{slug}". It may have been removed, or the link is old.
  </p>
{:else if relayQ.error && !relay}
  <SectionHeader title={slug} back={{ href: edgesPaths.home(), label: 'Nodes' }} />
  <AdminListState error={relayQ.error} onRetry={() => void relayQ.refetch()} />
{:else if !relay || !status}
  <SectionHeader title={slug} back={{ href: edgesPaths.home(), label: 'Nodes' }} />
  <div class="space-y-3"><Skeleton class="h-6 w-72" /><Skeleton class="h-32 w-full" /></div>
{:else}
  <SectionHeader
    title={name}
    description={relay.locationCode ? countryName(relay.locationCode, 'en') : undefined}
    back={{ href: edgesPaths.home(), label: 'Nodes' }}
  >
    {#snippet actions()}
      {#if relay.bindingDeferred && !run && published.length > 0}
        <Button disabled={goLiveBusy} onclick={goLive}>Go live</Button>
      {:else if published.length > 0}
        <Button disabled={!!relay.activeRotationId || !!run} onclick={() => replace('rotate')}>
          Replace address
        </Button>
      {/if}
      <DropdownMenu.Root>
        <DropdownMenu.Trigger>
          {#snippet child({ props })}
            <Button {...props} variant="outline">More <ChevronDown aria-hidden="true" /></Button>
          {/snippet}
        </DropdownMenu.Trigger>
        <DropdownMenu.Content align="end" class="w-64">
          {#if published.length > 0}
            <DropdownMenu.Item
              disabled={!!relay.activeRotationId || !!run}
              onSelect={() => replace('burn')}
            >
              Replace now, address is blocked
            </DropdownMenu.Item>
          {/if}
          <DropdownMenu.Item
            disabled={!!relay.activeRotationId || !!run}
            onSelect={() => (spareOpen = true)}
          >
            Add a spare address
          </DropdownMenu.Item>
          <DropdownMenu.Item onSelect={() => router.navigate(edgesPaths.relay(relay.slug))}>
            Advanced details
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
    {/snippet}
  </SectionHeader>

  <div class="space-y-8">
    <p class="flex items-center gap-2 text-lg font-medium" role="status">
      <StatusDot dot={status.dot} class="size-3" />
      {status.sentence}
      {#if run}
        <Link
          href={edgesPaths.home({ run: run.id })}
          class="text-primary text-sm underline underline-offset-4"
        >
          Watch
        </Link>
      {/if}
    </p>
    {#if relay.restore}
      <p class="text-muted-foreground -mt-6 text-sm">
        Removing protection: {restorePhaseWords(relay.restore.phase)}.
      </p>
    {/if}

    {#if testEdgeIds.length > 0}
      <EndpointTestCard
        edgeIds={testEdgeIds}
        onClose={() => {
          testEdgeIds = [];
          testParam.value = null;
        }}
        onAllDone={() => {
          const runId = testRunId;
          testEdgeIds = [];
          testParam.value = null;
          testRunId = null;
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

    <section aria-labelledby="addresses">
      <h2 id="addresses" class="mb-3 text-base font-semibold">Addresses in use</h2>
      {#if listenersQ.isPending || edgesQ.isPending}
        <Skeleton class="h-20 w-full" />
      {:else if listenersQ.isError}
        <AdminListState error={listenersQ.error} onRetry={() => void listenersQ.refetch()} />
      {:else if edgesQ.isError}
        <AdminListState error={edgesQ.error} onRetry={() => void edgesQ.refetch()} />
      {:else if listeners.length === 0}
        <p class="text-muted-foreground text-sm">This node has no inbound FCP can protect yet.</p>
      {:else}
        <ul class="space-y-3">
          {#each listeners as l (l.id)}
            <li class="rounded-lg border p-3">
              <p class="text-sm font-medium">
                {l.listenerKey}
                <span class="text-muted-foreground font-normal">{protocolLine(l)}</span>
              </p>
              <ListenerAddresses
                listener={l}
                {edges}
                onTest={(edgeId) => (testEdgeIds = [edgeId])}
              />
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <section class="flex items-start justify-between gap-4 rounded-lg border p-3">
      <div class="min-w-0">
        <Label for="node-auto">Replace addresses automatically on this node</Label>
        <p class="text-muted-foreground text-xs">
          {#if !globalOn}
            Global automatic protection is off. Turn it on from the nodes page for this to act.
          {:else}
            When an address looks blocked, FCP switches members to a tested spare on its own.
          {/if}
        </p>
      </div>
      <Switch
        id="node-auto"
        checked={relay.autoRotate}
        disabled={autoBusy}
        onCheckedChange={(v) => void setAuto(v)}
      />
    </section>

    <section aria-labelledby="activity">
      <h2 id="activity" class="mb-3 text-base font-semibold">Recent activity</h2>
      {#if timelineQ.isPending}
        <Skeleton class="h-24 w-full" />
      {:else if timelineQ.isError}
        <AdminListState error={timelineQ.error} onRetry={() => void timelineQ.refetch()} />
      {:else}
        <Timeline
          entries={timelineQ.data?.entries ?? []}
          max={8}
          labelFor={plainAuditActionLabel}
          label="Recent activity"
        />
      {/if}
    </section>
  </div>

  {#if replacing}
    <ReplaceDialog
      open={true}
      kind={replacing.kind}
      {relay}
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
  <ProvisionDialog
    bind:open={spareOpen}
    {relay}
    {listeners}
    onStarted={() =>
      toast.success(
        'Creating a spare address. The Edges overview will ask you to test it once it is ready.',
      )}
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
