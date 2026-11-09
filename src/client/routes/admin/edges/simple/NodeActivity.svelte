<script lang="ts">
  /**
   * A fronted node's recent activity in plain words (the origin's timeline
   * through `plainAuditActionLabel`). A failed run is named by what it was
   * (adding a spare is no replacement) with the provider's words, and links to
   * the run (`runHref`). The node page shows it as its Activity section;
   * NodeEdgesPanel shows it at its foot when the page has no such section.
   *
   * Props:
   *   slug: string                                   the origin's slug
   *   rotationHref?: (rotationId: string) => string  where a run's link goes (default: the origin's Rotations)
   *   heading?: boolean                              its own "Recent activity" heading (default true)
   */
  import { Skeleton } from '@client/components/ui/skeleton';
  import { plainAuditActionLabel } from '@client/lib/edgeCodes';
  import { relayListenersQuery, relayLookupQuery, relayTimelineQuery } from '@client/lib/edgesApi';
  import { originBusy } from '@client/lib/livePoll';
  import AdminListState from '../../AdminListState.svelte';
  import Timeline from '../components/Timeline.svelte';
  import { transportName } from '../lib/format';
  import { edgesPaths } from '../lib/routes';
  import { timelineLinkParams } from '../relay/relayLogic';

  interface Props {
    slug: string;
    rotationHref?: (rotationId: string) => string;
    heading?: boolean;
  }
  let { slug, rotationHref, heading = true }: Props = $props();
  const uid = $props.id();

  const relayQ = relayLookupQuery(() => slug);
  const relay = $derived(relayQ.data ?? null);
  const ref = {
    slug: () => slug,
    id: () => relay?.id ?? null,
    rotating: () => !!relay && originBusy(relay),
  };
  const listenersQ = relayListenersQuery(ref);
  const timelineQ = relayTimelineQuery(ref);
  const listeners = $derived(listenersQ.data?.listeners ?? []);

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
    if (!rotation) return null;
    return rotationHref
      ? rotationHref(rotation)
      : edgesPaths.relay(slug, { tab: 'rotations', rotation });
  };
</script>

<section
  aria-labelledby={heading ? `${uid}-activity` : undefined}
  aria-label={heading ? undefined : 'Recent activity'}
>
  {#if heading}
    <h3 id={`${uid}-activity`} class="mb-3 text-sm font-semibold">Recent activity</h3>
  {/if}
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
