<script lang="ts">
  /**
   * One node (`/admin/servers/nodes/:uuid?backend=<slug>`), the node's ONE
   * page. Header: its name, "machine · country · backend", its status
   * sentence and every action on the node (NodeActions). Then a sticky section
   * bar over one scroll (components/SectionBar.svelte, lib/nodeSections.ts):
   *
   *   Summary      the profile it runs, a rename, its notes, what its origin
   *                says first (quarantine, deleting, a running rotation),
   *                a fronting run's progress INLINE (`?run=<id>`), and its
   *                activation and approval (ActivationSection)
   *   Addresses    the Edges panel when an origin fronts it (loaded lazily;
   *                `?test=<edgeId>` opens its test card), else "Front this
   *                node", which opens the protect sheet here (`?front=1`)
   *   Transports   port changes, each transport with Change port and the
   *                addresses members get (and the operator's own fronts apart),
   *                Add a transport
   *   SNIs         each REALITY transport's SNIs and their one next step
   *                (TransportNames: manage, add suggestions, send, test)
   *   Modes        its mode, whether members can pick it, the mode groups each
   *                transport is in, and the modes it also serves (ExtraModesCard)
   *   Activity     the fronted node's recent activity
   *   Technical details  closed by default (`?section=details&tab=`): ALL of
   *                the origin page (edges/relay/TechnicalDetails.svelte: its
   *                tabs, drawers and actions). The old origin details address
   *                redirects here (edges/RelayPage.svelte).
   *
   * Nothing on this page changes a backend unless changes are allowed and the
   * node role has handed it over. Wording: ./lib/words.ts (pure, unit-tested).
   */
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import {
    intentsQuery,
    invalidateServers,
    renamesQuery,
    retryRename,
    serverSummaryQuery,
    serverTreeQuery,
  } from '@client/lib/serversApi';
  import { router } from '@client/stores/router.svelte';
  import { searchParam, setSearchParams } from '@client/lib/urlState.svelte';
  import type { AddressView, TransportView } from '../../../../shared/contracts/servers';
  import AdminListState from '../AdminListState.svelte';
  import SectionHeader from '../edges/components/SectionHeader.svelte';
  import { edgeSummaryQuery, invalidateOverview, relayLookupQuery } from '@client/lib/edgesApi';
  import { transportsQuery } from '@client/lib/sniApi';
  import TransportNames from '../edges/names/TransportNames.svelte';
  import OriginNotices from '../edges/relay/OriginNotices.svelte';
  import NodeActivity from '../edges/simple/NodeActivity.svelte';
  import ProtectSheet from '../edges/simple/ProtectSheet.svelte';
  import StatusDot from '../edges/simple/StatusDot.svelte';
  import ActivationSection from './components/ActivationSection.svelte';
  import DetailsFold from './components/DetailsFold.svelte';
  import ExtraModesCard from './components/ExtraModesCard.svelte';
  import HostDialog from './components/HostDialog.svelte';
  import NamesDialog from './components/NamesDialog.svelte';
  import NodeActions from './components/NodeActions.svelte';
  import AddTransportDialog from './components/AddTransportDialog.svelte';
  import PortChangesCard from './components/PortChangesCard.svelte';
  import PortDialog from './components/PortDialog.svelte';
  import RunProgress from './components/RunProgress.svelte';
  import SectionBar from './components/SectionBar.svelte';
  import { codeOf } from './lib/run';
  import { machineNameShown } from './lib/machineName';
  import { NODE_SECTIONS, patchSearch } from './lib/nodeSections';
  import { nodeSectionState, sectionId } from './lib/nodeSectionState.svelte';
  import { pickInstance, serversPaths } from './lib/routes';
  import {
    countryLabel,
    frontsHint,
    inboundSummary,
    intentRestarting,
    nodeNotes,
    nodeWords,
    portChangeable,
    renameWords,
    serverErrorWords,
    serverNamesLabel,
    splitAddresses,
  } from './lib/words';

  let { uuid }: { uuid: string } = $props();
  const summary = serverSummaryQuery();
  let slug = $derived(pickInstance(router.search, summary.data?.instances ?? []));
  const tree = serverTreeQuery(() => slug);
  const intents = intentsQuery(() => slug);
  const qc = useQueryClient();
  const renames = renamesQuery(() => slug);
  // A rename of this node still running, or one that stopped, shown until it is old news.
  let renaming = $derived(
    (renames.data?.renames ?? []).find(
      (r) =>
        r.nodeUuid === uuid &&
        (r.state === 'running' ||
          (r.state === 'failed' && Date.now() - Date.parse(r.updatedAt) < 24 * 3600_000)),
    ) ?? null,
  );
  let instance = $derived(summary.data?.instances.find((i) => i.slug === slug) ?? null);
  let node = $derived(tree.data?.nodes.find((n) => n.nodeUuid === uuid) ?? null);
  // The enrolled node behind this backend row, when the node role enrolled it.
  let intent = $derived(
    intents.data?.intents.find((i) => i.nodeUuid === uuid || (node && i.name === node.name)) ??
      null,
  );
  // An enrolled node not live yet: its addresses are staged (off, or held back
  // by the closed gate), so nobody gets them until go-live.
  let notLiveYet = $derived(!!intent && intent.stage !== 'live');
  let manageOn = $derived(summary.data?.config['manage.enabled'] ?? false);
  let canWrite = $derived(manageOn && !!instance?.writable && !!instance?.setUp);
  // The Edges origin in front of this node, if any: its panel is part of this page.
  const edgeSummary = edgeSummaryQuery();
  let relaySlug = $derived(
    (edgeSummary.data?.relays ?? []).find(
      (r) =>
        r.relay.origin.kind === 'panel-node' &&
        r.relay.origin.backendServerId === instance?.id &&
        (r.relay.origin.nodeUuid === uuid || (!!node && r.relay.origin.nodeName === node.name)),
    )?.relay.slug ?? null,
  );
  // No answer yet, or a failed read: whether an origin fronts it is unknown.
  let frontingUnknown = $derived(!relaySlug && (edgeSummary.isPending || edgeSummary.isError));
  const relayQ = relayLookupQuery(() => relaySlug);
  const relay = $derived(relaySlug ? (relayQ.data ?? null) : null);
  const EdgesPanel = () => import('../edges/simple/NodeEdgesPanel.svelte');
  const Details = () => import('../edges/relay/TechnicalDetails.svelte');
  // Each REALITY transport's names: where they stand and the next step.
  const sniTransports = transportsQuery(() => slug);
  let back = $derived({ href: serversPaths.nodes(), label: 'Nodes' });

  // --- sections, the inline run, the protect sheet
  const nav = nodeSectionState(() => !!node || !!intent);
  const runParam = searchParam('run');
  const frontParam = searchParam('front');
  /** This page with some params changed (the run inline, the fold at a tab). */
  const here = (patch: Record<string, string | null>) =>
    patchSearch(router.pathname, router.search, patch);
  const runHref = (id: string) => here({ run: id, front: null, section: null });
  const openRun = (id: string) => {
    setSearchParams({ run: id, front: null, section: null });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };
  const openFront = () => setSearchParams({ front: '1', run: null });
  const closeFront = () => {
    setSearchParams({ front: null });
    invalidateOverview(qc);
  };
  const detailsHref = $derived(here({ section: 'details' }));
  const openEdge = (edgeId: string) => setSearchParams({ edge: edgeId, rotation: null });
  const openRotation = (rotationId: string) =>
    setSearchParams({ rotation: rotationId, edge: null });

  let hostOpen = $state(false);
  let hostFor = $state<{ inbound: TransportView; host: AddressView | null } | null>(null);
  let namesOpen = $state(false);
  let namesFor = $state<{ profileUuid: string; inbound: TransportView } | null>(null);
  let portOpen = $state(false);
  let portFor = $state<{ profileUuid: string; inbound: TransportView } | null>(null);
  let addOpen = $state(false);
  const editHost = (inbound: TransportView, host: AddressView | null) => {
    hostFor = { inbound, host };
    hostOpen = true;
  };
  const backendName = $derived(
    (summary.data?.instances.length ?? 0) > 1 ? (instance?.name ?? null) : null,
  );
</script>

{#snippet addressRow(inbound: TransportView, host: AddressView)}
  <li class={host.isDisabled ? 'text-muted-foreground line-through' : ''}>
    {#if canWrite}
      <button
        type="button"
        class="hover:text-foreground focus-visible:ring-ring/50 rounded text-start underline-offset-2 outline-none hover:underline focus-visible:ring-3"
        onclick={() => editHost(inbound, host)}
      >
        <span class="break-all">{host.remark}</span>
      </button>
    {:else}
      <span class="break-all">{host.remark}</span>
    {/if}
    <span class="text-muted-foreground break-all">
      {host.address}:{host.port}{host.sni ? ` · ${host.sni}` : ''}
    </span>
  </li>
{/snippet}

{#snippet sectionTitle(id: (typeof NODE_SECTIONS)[number], title: string)}
  <h2 id={`${sectionId(id)}-title`} class="mb-3 text-base font-semibold">{title}</h2>
{/snippet}

{#if summary.isPending || tree.isPending || (!node && intents.isPending)}
  <SectionHeader title="Node" {back} />
  <div class="space-y-3"><Skeleton class="h-6 w-72" /><Skeleton class="h-32 w-full" /></div>
{:else if tree.isError}
  <SectionHeader title="Node" {back} />
  <p class="text-destructive text-sm">{serverErrorWords(codeOf(tree.error))}</p>
{:else if !node && slug && intent?.retirement}
  <!-- Retiring removes the panel row before the machine is wiped: the steps stay here. -->
  <SectionHeader
    title={intent.name}
    description={machineNameShown(intent.name, intent.machineName) ?? undefined}
    {back}
  />
  <ActivationSection {slug} {intent} onOpenRun={openRun} />
{:else if !node || !slug}
  <SectionHeader title="Node not found" {back} />
  <p class="text-muted-foreground text-sm">
    There is no node with this id on the backend any more, or the link is old.
  </p>
{:else}
  {@const w = nodeWords(node, { restarting: !!intent && intentRestarting(intent, Date.now()) })}
  {@const country = countryLabel(node.countryCode)}
  {@const notes = nodeNotes(node)}
  {@const sniTransportsHere = node.transports.filter(
    (t) => t.security === 'reality' || !!serverNamesLabel(t),
  )}
  <SectionHeader
    title={node.name}
    description={[
      machineNameShown(node.name, intent?.machineName),
      country,
      backendName,
      node.address,
    ]
      .filter(Boolean)
      .join(' · ') || undefined}
    {back}
  >
    {#snippet actions()}
      {#if canWrite || (intent && !intent.retirement)}
        <NodeActions {slug} {node} {canWrite} {intent} />
      {/if}
    {/snippet}
  </SectionHeader>

  <p class="-mt-3 mb-4 flex items-center gap-2 text-lg font-medium" role="status">
    <StatusDot dot={w.dot} class="size-3" />
    {w.sentence}
  </p>

  <SectionBar sections={NODE_SECTIONS} current={nav.section} onPick={nav.pick} />

  <div class="space-y-10">
    <section
      id={sectionId('summary')}
      class="scroll-mt-16 space-y-6"
      aria-labelledby={`${sectionId('summary')}-title`}
    >
      {@render sectionTitle('summary', 'Summary')}
      <div class="-mt-3">
        {#if node.profile}
          <p class="text-muted-foreground text-sm">Runs the profile {node.profile.name}.</p>
        {/if}
        {#if renaming}
          {@const rw = renameWords(renaming)}
          <p class="mt-1 flex flex-wrap items-center gap-2 text-sm" role="status">
            <StatusDot dot={rw.dot} />
            {rw.sentence}
            {#if canWrite && renaming.code === 'servers.rename_host_refused' && slug}
              <Button
                variant="outline"
                size="sm"
                onclick={async () => {
                  try {
                    await retryRename(slug!, renaming!.id);
                    toast.success('Trying again.');
                  } catch (e) {
                    toast.error(serverErrorWords(codeOf(e)));
                  } finally {
                    invalidateServers(qc);
                  }
                }}
              >
                Retry
              </Button>
            {/if}
          </p>
        {/if}
        {#if notes.length > 0}
          <ul class="text-muted-foreground mt-1 space-y-1 text-sm" aria-label="Notes">
            {#each notes as n (n)}
              <li>{n}</li>
            {/each}
          </ul>
        {/if}
      </div>

      {#if relay}
        <OriginNotices {relay} onOpenEdge={openEdge} onOpenRotation={openRotation} />
      {/if}

      {#if runParam.value}
        <RunProgress runId={runParam.value} onClose={() => (runParam.value = null)} />
      {/if}

      {#if intent && slug}
        <ActivationSection
          {slug}
          {intent}
          origin={!!relaySlug}
          onFront={openFront}
          onOpenRun={openRun}
          inlineRunId={runParam.value || null}
        />
      {/if}
    </section>

    <section
      id={sectionId('addresses')}
      class="scroll-mt-16"
      aria-labelledby={`${sectionId('addresses')}-title`}
    >
      {@render sectionTitle('addresses', 'Addresses')}
      {#if relaySlug}
        {#await EdgesPanel()}
          <Skeleton class="h-32 w-full" />
        {:then mod}
          {@const Panel = mod.default}
          <Panel
            slug={relaySlug}
            enrolled={intent ? { stage: intent.stage } : null}
            heading={false}
            activity={false}
            {runHref}
            protectHref={() => here({ front: '1', run: null })}
            {detailsHref}
          />
        {:catch}
          <p class="text-muted-foreground text-sm">
            The edges of this node did not load. Reload the page to try again.
          </p>
        {/await}
      {:else if edgeSummary.isError}
        <!-- Not knowing whether an origin fronts it is not the same as none. -->
        <AdminListState error={edgeSummary.error} onRetry={() => void edgeSummary.refetch()} />
      {:else if edgeSummary.isPending}
        <Skeleton class="h-16 w-full" />
      {:else}
        <div class="rounded-lg border p-4">
          <p class="text-sm font-medium">Members reach this node directly.</p>
          <p class="text-muted-foreground mt-1 max-w-prose text-sm">
            A fronted node gives members a provider address instead of its own, and FCP replaces it
            when it stops working. Members see no change until the new address is tested.
          </p>
          <Button class="mt-3" size="sm" onclick={openFront}>Front this node</Button>
        </div>
      {/if}
    </section>

    <section
      id={sectionId('transports')}
      class="scroll-mt-16 space-y-4"
      aria-labelledby={`${sectionId('transports')}-title`}
    >
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h2 id={`${sectionId('transports')}-title`} class="text-base font-semibold">Transports</h2>
        {#if canWrite && node.profile}
          <Button variant="outline" size="sm" onclick={() => (addOpen = true)}>
            Add a transport
          </Button>
        {/if}
      </div>
      {#if node.profile}
        <PortChangesCard {slug} profileUuid={node.profile.profileUuid} {canWrite} />
      {/if}
      {#if node.transports.length === 0}
        <p class="text-muted-foreground text-sm">This node serves no transport.</p>
      {:else}
        <ul class="space-y-3">
          {#each node.transports as inbound (inbound.transportUuid)}
            {@const split = splitAddresses(inbound.addresses)}
            <li class="rounded-lg border p-3 text-sm">
              <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
                <p class="font-medium break-all">
                  {inbound.tag}
                  <span class="text-muted-foreground font-normal">{inboundSummary(inbound)}</span>
                </p>
                {#if canWrite && node.profile && portChangeable(inbound)}
                  <Button
                    variant="ghost"
                    size="sm"
                    class="-my-1"
                    onclick={() => {
                      portFor = { profileUuid: node.profile!.profileUuid, inbound };
                      portOpen = true;
                    }}
                  >
                    Change port
                  </Button>
                {/if}
              </div>

              <div class="mt-3">
                <h3 class="text-muted-foreground text-xs font-medium uppercase">
                  {notLiveYet ? 'Addresses members will get once live' : 'Addresses members get'}
                </h3>
                {#if split.members.length === 0}
                  <p class="text-muted-foreground">None yet.</p>
                {:else}
                  <ul class="mt-1 space-y-0.5">
                    {#each split.members as host (host.addressUuid)}
                      {@render addressRow(inbound, host)}
                    {/each}
                  </ul>
                {/if}
                {#if canWrite}
                  <Button
                    variant="ghost"
                    size="sm"
                    class="-ms-2 mt-1"
                    onclick={() => editHost(inbound, null)}
                  >
                    Add an address
                  </Button>
                {/if}
              </div>

              {#if split.fronts.length > 0}
                <div class="text-muted-foreground mt-3">
                  <h3 class="text-xs font-medium uppercase">
                    Your own fronts, left out of members' subscriptions
                  </h3>
                  <p>{frontsHint(split.fronts.length, node.frontKeys)}</p>
                  <ul class="mt-1 space-y-0.5">
                    {#each split.fronts as host (host.addressUuid)}
                      {@render addressRow(inbound, host)}
                    {/each}
                  </ul>
                </div>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <section
      id={sectionId('snis')}
      class="scroll-mt-16"
      aria-labelledby={`${sectionId('snis')}-title`}
    >
      {@render sectionTitle('snis', 'SNIs')}
      {#if sniTransportsHere.length === 0}
        <p class="text-muted-foreground text-sm">This node serves no transport with SNIs.</p>
      {:else}
        <ul class="space-y-3">
          {#each sniTransportsHere as inbound (inbound.transportUuid)}
            {@const names = serverNamesLabel(inbound)}
            <li class="rounded-lg border p-3 text-sm">
              <p class="font-medium break-all">{inbound.tag}</p>
              {#if inbound.security === 'reality' && slug && !sniTransports.isError}
                <TransportNames
                  backendSlug={slug}
                  nodeUuid={uuid}
                  transport={sniTransports.data?.transports.find(
                    (t) => t.transportUuid === inbound.transportUuid,
                  )}
                  switches={sniTransports.data?.switches}
                  names={inbound.serverNames ?? []}
                  serversHref={serversPaths.nodes({ backend: slug })}
                  onEditByHand={canWrite && node.profile
                    ? () => {
                        namesFor = { profileUuid: node.profile!.profileUuid, inbound };
                        namesOpen = true;
                      }
                    : undefined}
                />
              {:else if names}
                {@const unknown = inbound.security === 'reality' && sniTransports.isError}
                <div class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1">
                  <details class="min-w-0">
                    <summary class="text-muted-foreground cursor-pointer">
                      {names}{inbound.realityTarget ? `, from ${inbound.realityTarget}` : ''}
                    </summary>
                    <ul class="mt-1 columns-1 gap-x-6 sm:columns-2">
                      {#each inbound.serverNames ?? [] as name (name)}
                        <li class="break-all">{name}</li>
                      {/each}
                    </ul>
                  </details>
                  {#if canWrite && node.profile && !unknown}
                    <Button
                      variant="ghost"
                      size="sm"
                      class="-my-1"
                      onclick={() => {
                        namesFor = { profileUuid: node.profile!.profileUuid, inbound };
                        namesOpen = true;
                      }}
                    >
                      Edit
                    </Button>
                  {/if}
                  {#if unknown}
                    <span class="text-muted-foreground basis-full">
                      Could not read whether FCP manages these SNIs. Reload to try again.
                    </span>
                  {/if}
                </div>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <section
      id={sectionId('modes')}
      class="scroll-mt-16 space-y-4"
      aria-labelledby={`${sectionId('modes')}-title`}
    >
      <h2 id={`${sectionId('modes')}-title`} class="text-base font-semibold">Modes</h2>
      {#if intent}
        <p class="text-sm">
          Enrolled for the {intent.mode.name} mode.
          {#if !intent.modeEnabled}
            <span class="text-amber-700 dark:text-amber-300">
              Members cannot pick it right now, so this node reaches nobody.
            </span>
            <Link href="/admin/connection-modes" class="text-primary underline underline-offset-4">
              Connection modes
            </Link>
          {/if}
        </p>
      {/if}
      {#if node.transports.length > 0}
        <ul class="space-y-1 text-sm">
          {#each node.transports as inbound (inbound.transportUuid)}
            <li>
              <span class="font-medium break-all">{inbound.tag}</span>
              <span class="text-muted-foreground">
                {#if inbound.modeGroups.length === 0}
                  in no mode group.
                {:else}
                  in {inbound.modeGroups.map((s) => s.name).join(', ')}.
                {/if}
              </span>
            </li>
          {/each}
        </ul>
        <p class="text-muted-foreground text-sm">
          Mode groups belong to the backend.
          <Link
            href={serversPaths.nodes({ backend: slug })}
            class="text-primary underline underline-offset-4"
          >
            Change them
          </Link>
        </p>
      {/if}
      {#if intent && slug}
        <ExtraModesCard {slug} {intent} {canWrite} />
      {/if}
    </section>

    <section
      id={sectionId('activity')}
      class="scroll-mt-16"
      aria-labelledby={`${sectionId('activity')}-title`}
    >
      {@render sectionTitle('activity', 'Activity')}
      {#if frontingUnknown}
        <p class="text-muted-foreground text-sm">
          Whether anything fronts this node could not be read yet.
        </p>
      {:else if relaySlug}
        <NodeActivity
          slug={relaySlug}
          heading={false}
          rotationHref={(rotation) =>
            here({ section: 'details', tab: 'rotations', rotation, edge: null })}
        />
      {:else}
        <p class="text-muted-foreground text-sm">
          Nothing fronts this node, so it has no edge activity. What FCP sent to the backend is
          under Recent changes on
          <Link
            href={serversPaths.nodes({ backend: slug })}
            class="text-primary underline underline-offset-4">Nodes</Link
          >.
        </p>
      {/if}
    </section>

    <DetailsFold open={nav.detailsOpen} onToggle={nav.toggleDetails} id={sectionId('details')}>
      {#if frontingUnknown}
        <p class="text-muted-foreground text-sm">
          Whether anything fronts this node could not be read yet.
        </p>
      {:else if relaySlug}
        {#await Details()}
          <Skeleton class="h-40 w-full" />
        {:then mod}
          {@const TechnicalDetails = mod.default}
          <TechnicalDetails slug={relaySlug} />
        {/await}
      {:else}
        <p class="text-muted-foreground text-sm">
          Nothing fronts this node, so it has no origin, listeners, edges or rotations. Front it
          from Addresses.
        </p>
      {/if}
    </DetailsFold>

    {#if !canWrite}
      <p class="text-muted-foreground border-t pt-4 text-sm">
        {#if !manageOn}
          Changes from here are off. Turn them on from the
          <Link href={back.href} class="underline underline-offset-4">Nodes page</Link>.
        {:else if instance && !instance.setUp}
          Changes are refused until this backend is set up or adopted from the Nodes page.
        {/if}
      </p>
    {/if}
  </div>

  {#if hostFor}
    <HostDialog
      bind:open={hostOpen}
      {slug}
      transportUuid={hostFor.inbound.transportUuid}
      transportTag={hostFor.inbound.tag}
      host={hostFor.host}
    />
  {/if}
  {#if portFor}
    <PortDialog
      bind:open={portOpen}
      {slug}
      profileUuid={portFor.profileUuid}
      inbound={portFor.inbound}
    />
  {/if}
  {#if node.profile}
    <AddTransportDialog
      bind:open={addOpen}
      {slug}
      profileUuid={node.profile.profileUuid}
      profileName={node.profile.name}
    />
  {/if}
  {#if namesFor}
    <NamesDialog
      bind:open={namesOpen}
      {slug}
      profileUuid={namesFor.profileUuid}
      inbound={namesFor.inbound}
    />
  {/if}
  {#if frontParam.value === '1'}
    <ProtectSheet
      open={true}
      runId={null}
      server={slug}
      node={uuid}
      onRunCreated={(id) => openRun(id)}
      onClose={closeFront}
    />
  {/if}
{/if}
