<script lang="ts">
  /**
   * The test card for addresses OUTSIDE a guided run (a spare, a retest, the
   * go-live check): fetches each address's isolated test link, and a tick calls
   * `verifyEdge` with the binding that link carried. `onAllDone` fires once every
   * address is confirmed.
   *
   * Props:
   *   edgeIds: string[]
   *   onAllDone?: () => void
   *   onClose?: () => void
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { invalidateOverview, testLinksQuery, verifyEdge } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import TestCard from './TestCard.svelte';
  import type { TestItem } from './runWords';

  interface Props {
    edgeIds: string[];
    onAllDone?: () => void;
    onClose?: () => void;
  }
  let { edgeIds, onAllDone, onClose }: Props = $props();

  const qc = useQueryClient();
  const links = testLinksQuery(() => edgeIds);
  const items = $derived<TestItem[]>(
    (links.data ?? []).map((l) => ({
      edgeId: l.binding.edgeId,
      listenerKey: l.binding.listenerKey,
      link: l.link,
      method: 'test_link',
      endpoint: l.binding.endpoint,
      listenerRevision: l.binding.listenerRevision,
      configHash: l.binding.configHash,
    })),
  );
  let done = $state(new Set<string>());
  let busyId = $state<string | null>(null);

  async function works(item: TestItem): Promise<void> {
    busyId = item.edgeId;
    try {
      const res = await verifyEdge(item.edgeId, {
        endpoint: item.endpoint,
        listenerRevision: item.listenerRevision,
        configHash: item.configHash,
        method: 'test_link',
      });
      done = new Set([...done, item.edgeId]);
      toast.success(
        res.accountTrusted
          ? 'Address tested. The provider account is now trusted.'
          : 'Address tested.',
      );
      invalidateOverview(qc);
      if (items.every((i) => done.has(i.edgeId))) onAllDone?.();
    } catch (e) {
      toast.error(edgeErrorMessage(e));
      // A stale binding: the link is rebuilt, never stamped as shown.
      void links.refetch();
    } finally {
      busyId = null;
    }
  }
</script>

<div class="rounded-lg border border-sky-500/40 bg-sky-500/10 p-4">
  <div class="mb-2 flex items-start justify-between gap-3">
    <p class="font-medium">Test the address</p>
    {#if onClose}
      <Button variant="ghost" size="sm" onclick={onClose}>Close</Button>
    {/if}
  </div>
  {#if links.isPending}
    <Skeleton class="h-16 w-full" />
  {:else if links.isError}
    <AdminListState error={links.error} onRetry={() => void links.refetch()} />
  {:else}
    <TestCard {items} {done} {busyId} onWorks={works} />
  {/if}
</div>
