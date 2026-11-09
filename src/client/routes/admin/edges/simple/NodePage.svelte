<script lang="ts">
  /**
   * `/admin/servers/origins/:slug`. A backend node has ONE page, its Servers node
   * page: this address redirects there (`nodeHomeOf`), keeping the query
   * (`?test=<edgeId>`, `?section=`, `?tab=`, ...). An origin added by hand
   * (manual, a whole Outline server) has no Servers page, so it gets the same
   * layout here, without Transports, SNIs and Modes (it serves no transport of
   * its own; servers/lib/nodeSections.ts `ORIGIN_SECTIONS`):
   *
   *   Summary       its status, what it says first (quarantine, deleting, a
   *                 running rotation) and a run's progress inline (`?run=`)
   *   Addresses     its edges panel (NodeEdgesPanel)
   *   Activity      its recent activity
   *   Technical details  closed by default: the whole origin page
   *                 (relay/TechnicalDetails.svelte)
   */
  import { untrack } from 'svelte';
  import { ApiCallError } from '@client/lib/api';
  import { countryName } from '@client/lib/countries';
  import { attentionQuery, relayLookupQuery } from '@client/lib/edgesApi';
  import { serverSummaryQuery, serverTreeQuery } from '@client/lib/serversApi';
  import { router } from '@client/stores/router.svelte';
  import { searchParam, setSearchParams } from '@client/lib/urlState.svelte';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { instanceSlugOf, nodeHomeOf, serversPaths } from '../../servers/lib/routes';
  import { ORIGIN_SECTIONS, joinSearch, patchSearch } from '../../servers/lib/nodeSections';
  import { nodeSectionState, sectionId } from '../../servers/lib/nodeSectionState.svelte';
  import DetailsFold from '../../servers/components/DetailsFold.svelte';
  import RunProgress from '../../servers/components/RunProgress.svelte';
  import SectionBar from '../../servers/components/SectionBar.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { originSentence, statusOf } from '../lib/statusWords';
  import OriginNotices from '../relay/OriginNotices.svelte';
  import TechnicalDetails from '../relay/TechnicalDetails.svelte';
  import NodeActivity from './NodeActivity.svelte';
  import NodeEdgesPanel from './NodeEdgesPanel.svelte';
  import StatusDot from './StatusDot.svelte';

  interface Props {
    slug: string;
  }
  let { slug }: Props = $props();

  const relayQ = relayLookupQuery(() => slug);
  const relay = $derived(relayQ.data ?? null);
  const notFound = $derived(relayQ.error instanceof ApiCallError && relayQ.error.status === 404);
  const panelNode = $derived(relay?.origin.kind === 'panel-node' ? relay.origin : null);
  const summary = serverSummaryQuery();
  // An origin made before node uuids were recorded: its node is found by name.
  const tree = serverTreeQuery(() =>
    panelNode && !panelNode.nodeUuid
      ? instanceSlugOf(summary.data?.instances, panelNode.backendServerId)
      : null,
  );
  const target = $derived(
    relay ? nodeHomeOf(relay.origin, summary.data?.instances, tree.data?.nodes) : null,
  );
  // Still finding out where a backend node lives (or about to move there).
  const resolving = $derived(
    !!panelNode && (!!target || summary.isPending || (!panelNode.nodeUuid && tree.isLoading)),
  );
  // Once: the move changes the address this page would read again.
  let moved = false;
  $effect(() => {
    if (!target || moved) return;
    moved = true;
    router.navigate(
      joinSearch(
        target,
        untrack(() => router.search),
      ),
      { replace: true },
    );
  });
  const back = { href: serversPaths.nodes({ show: 'by-hand' }), label: 'Nodes' };

  const attention = attentionQuery();
  const status = $derived(statusOf(attention.data?.origins, slug));
  const nav = nodeSectionState(() => !!relay && !resolving);
  const runParam = searchParam('run');
  const here = (patch: Record<string, string | null>) =>
    patchSearch(router.pathname, router.search, patch);
</script>

{#if notFound}
  <SectionHeader title="Node not found" {back} />
  <p class="text-muted-foreground text-sm">
    There is no fronted node called "{slug}". It may have been removed, or the link is old.
  </p>
{:else if !relay || resolving}
  <SectionHeader title={slug} {back} />
  {#if relayQ.error}
    <NodeEdgesPanel {slug} />
  {:else}
    <div class="space-y-3"><Skeleton class="h-6 w-72" /><Skeleton class="h-32 w-full" /></div>
  {/if}
{:else}
  <SectionHeader
    title={relay.label ?? (panelNode ? panelNode.nodeName : relay.slug)}
    description={[
      panelNode ? null : 'Added by hand',
      relay.locationCode ? countryName(relay.locationCode, 'en') : null,
    ]
      .filter(Boolean)
      .join(' · ')}
    {back}
  />
  {#if status}
    <p class="-mt-3 mb-4 flex items-center gap-2 text-lg font-medium" role="status">
      <StatusDot dot={status.dot} class="size-3" />
      {originSentence(status, { onNode: true })}
    </p>
  {/if}

  <SectionBar sections={ORIGIN_SECTIONS} current={nav.section} onPick={nav.pick} />

  <div class="space-y-10">
    <section
      id={sectionId('summary')}
      class="scroll-mt-16 space-y-6"
      aria-labelledby={`${sectionId('summary')}-title`}
    >
      <h2 id={`${sectionId('summary')}-title`} class="text-base font-semibold">Summary</h2>
      <OriginNotices
        {relay}
        onOpenEdge={(edgeId) => setSearchParams({ edge: edgeId, rotation: null })}
        onOpenRotation={(rotationId) => setSearchParams({ rotation: rotationId, edge: null })}
      />
      {#if runParam.value}
        <RunProgress runId={runParam.value} onClose={() => (runParam.value = null)} />
      {:else if !relay.quarantine && !relay.deleting && !relay.activeRotationId}
        <p class="text-muted-foreground text-sm">Nothing waits for you here.</p>
      {/if}
    </section>

    <section
      id={sectionId('addresses')}
      class="scroll-mt-16"
      aria-labelledby={`${sectionId('addresses')}-title`}
    >
      <h2 id={`${sectionId('addresses')}-title`} class="mb-3 text-base font-semibold">Addresses</h2>
      <NodeEdgesPanel
        {slug}
        heading={false}
        activity={false}
        runHref={(id) => here({ run: id, section: null })}
        detailsHref={here({ section: 'details' })}
      />
    </section>

    <section
      id={sectionId('activity')}
      class="scroll-mt-16"
      aria-labelledby={`${sectionId('activity')}-title`}
    >
      <h2 id={`${sectionId('activity')}-title`} class="mb-3 text-base font-semibold">Activity</h2>
      <NodeActivity
        {slug}
        heading={false}
        rotationHref={(rotation) =>
          here({ section: 'details', tab: 'rotations', rotation, edge: null })}
      />
    </section>

    <DetailsFold open={nav.detailsOpen} onToggle={nav.toggleDetails} id={sectionId('details')}>
      <TechnicalDetails {slug} />
    </DetailsFold>
  </div>
{/if}
