<script lang="ts">
  /**
   * The test card for addresses OUTSIDE a guided run's sheet (a spare, a retest,
   * the go-live check): fetches each address's isolated test link, and each tick
   * calls `verifyEdge` with the binding that link carried (saved on its own).
   * `onAllDone` fires once every address is confirmed.
   *
   * "Doesn't work" replaces that one address: with `runId` (the activation run
   * a go-live check opened) the run provisions a new address for that line
   * only, then `onRetried` hands the run to its progress view; otherwise the
   * page decides (`onDoesNotWork`: replace a blocked address, renew a spare).
   *
   * Props:
   *   edgeIds: string[]
   *   runId?: string | null
   *   onAllDone?: () => void
   *   onRetried?: (runId: string) => void
   *   onDoesNotWork?: (edgeId: string) => void
   *   onClose?: () => void
   *   nameOf?: (listenerKey: string) => string | null   the transport in words for a line
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import {
    invalidateOverview,
    releaseTestLink,
    retrySetupRun,
    testLinksQuery,
    verifyEdge,
  } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import TestCard from './TestCard.svelte';
  import type { TestItem } from './runWords';

  interface Props {
    edgeIds: string[];
    runId?: string | null;
    onAllDone?: () => void;
    onRetried?: (runId: string) => void;
    onDoesNotWork?: (edgeId: string) => void;
    onClose?: () => void;
    nameOf?: (listenerKey: string) => string | null;
  }
  let {
    edgeIds,
    runId = null,
    onAllDone,
    onRetried,
    onDoesNotWork,
    onClose,
    nameOf = () => null,
  }: Props = $props();

  const qc = useQueryClient();
  const links = testLinksQuery(() => edgeIds);
  const items = $derived<TestItem[]>(
    (links.data ?? []).map((l) => ({
      edgeId: l.binding.edgeId,
      listenerKey: l.binding.listenerKey,
      name: nameOf(l.binding.listenerKey),
      link: l.link,
      method: 'test_link',
      endpoint: l.binding.endpoint,
      listenerRevision: l.binding.listenerRevision,
      configHash: l.binding.configHash,
    })),
  );
  let done = $state(new Set<string>());
  let busyId = $state<string | null>(null);

  /**
   * A link built on a temporary credential (an Outline key) is released the
   * moment the card is closed or finished, instead of at its 24 h expiry.
   * Best effort: the sweep still catches a release that never lands.
   */
  async function release(): Promise<void> {
    const owed = (links.data ?? []).filter((l) => l.credentialId);
    await Promise.allSettled(owed.map((l) => releaseTestLink(l.binding.edgeId, l.credentialId!)));
  }
  function close(): void {
    void release();
    onClose?.();
  }

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
      if (items.every((i) => done.has(i.edgeId))) {
        void release();
        onAllDone?.();
      }
    } catch (e) {
      toast.error(edgeErrorMessage(e));
      // A stale binding: the link is rebuilt, never stamped as shown.
      void links.refetch();
    } finally {
      busyId = null;
    }
  }

  async function fails(item: TestItem): Promise<void> {
    if (!runId) {
      onDoesNotWork?.(item.edgeId);
      return;
    }
    busyId = item.edgeId;
    try {
      await retrySetupRun(runId, { tryAnotherAddress: true, edgeId: item.edgeId });
      void release();
      toast.message('Replacing that address. The new one comes back here to test.');
      invalidateOverview(qc);
      onRetried?.(runId);
    } catch (e) {
      toast.error(edgeErrorMessage(e));
    } finally {
      busyId = null;
    }
  }
  const canFail = $derived(runId !== null || onDoesNotWork !== undefined);
</script>

<div class="rounded-lg border border-sky-500/40 bg-sky-500/10 p-4">
  <div class="mb-2 flex items-start justify-between gap-3">
    <p class="font-medium">Test the address</p>
    {#if onClose}
      <Button variant="ghost" size="sm" onclick={close}>Close</Button>
    {/if}
  </div>
  {#if links.isPending}
    <Skeleton class="h-16 w-full" />
  {:else if links.isError}
    <AdminListState error={links.error} onRetry={() => void links.refetch()} />
  {:else}
    <TestCard {items} {done} {busyId} onWorks={works} onFails={canFail ? fails : undefined} />
  {/if}
</div>
