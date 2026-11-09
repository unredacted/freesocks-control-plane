<script lang="ts">
  /**
   * One fronted node's timeline for the Overview's Recent activity, drawn as
   * nothing: the same query (and cache) as the node page's Recent activity,
   * handed up through `onReport` (null when the node goes away).
   *
   * Props:
   *   id, slug: the origin
   *   onReport: (slug, entries | null) => void
   */
  import { untrack } from 'svelte';
  import { relayTimelineQuery } from '@client/lib/edgesApi';
  import type { TimelineEntryInput } from './overviewModel';

  interface Props {
    id: string;
    slug: string;
    onReport: (slug: string, entries: readonly TimelineEntryInput[] | null) => void;
  }
  let { id, slug, onReport }: Props = $props();

  const timeline = relayTimelineQuery({ slug: () => slug, id: () => id });

  $effect(() => {
    const s = slug;
    const entries = timeline.data?.entries ?? null;
    untrack(() => onReport(s, entries));
  });
  $effect(() => {
    const s = slug;
    return () => untrack(() => onReport(s, null));
  });
</script>
