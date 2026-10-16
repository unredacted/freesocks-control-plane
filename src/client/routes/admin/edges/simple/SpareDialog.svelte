<script lang="ts">
  /**
   * "Add a spare address" on the node page: one confirm. FCP picks the
   * transport and the account (the provision preflight's own choice); the
   * spare waits unused until someone ticks it on the test card, and only a
   * tested spare is ever put in use. The dry run shows only what blocks it.
   *
   * With `renew` the spare is a replacement for one that does not work: that
   * one is destroyed first and the new one is created for the same transport
   * (a retry after a failed create only creates; the old one is already gone).
   *
   * Props:
   *   open (bindable); relay; renew?: { edgeId, listenerId, listenerKey } | null
   *   onStarted?()                 after the create was accepted
   *   onClose?()                   whenever the dialog closes (for a caller that mounts it per use)
   */
  import { createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { OriginAdmin } from '@shared/contracts/edges';
  import { Skeleton } from '@client/components/ui/skeleton';
  import {
    deleteEdge,
    edgeKeys,
    invalidateRelay,
    preflightRelay,
    provisionRelay,
  } from '@client/lib/edgesApi';
  import CodeNote from '../components/CodeNote.svelte';
  import AdminListState from '../../AdminListState.svelte';
  import ActionConfirm from '../relay/ActionConfirm.svelte';
  import { assertEdgeOk } from '../lib/edgeErrors';

  interface Props {
    open: boolean;
    relay: OriginAdmin;
    renew?: { edgeId: string; listenerId: string; listenerKey: string } | null;
    onStarted?: () => void;
    onClose?: () => void;
  }
  let { open = $bindable(false), relay, renew = null, onStarted, onClose }: Props = $props();

  const qc = useQueryClient();
  const preflight = createQuery(() => ({
    queryKey: [...edgeKeys.relay(relay.slug), 'preflight', 'spare', renew?.listenerId ?? ''],
    queryFn: () =>
      preflightRelay(relay.id, {
        kind: 'provision',
        trigger: 'manual',
        ...(renew ? { listenerKey: renew.listenerKey } : {}),
      }),
    enabled: open,
    staleTime: 0,
    gcTime: 0,
  }));
  const blockers = $derived(preflight.data?.blockers ?? []);
  // A spare being renewed frees its own slot: its account-capacity blocker is not real.
  const real = $derived(
    renew ? blockers.filter((b) => b.code !== 'account_capacity_reached') : blockers,
  );

  let destroyed = $state<string | null>(null);
  async function run(): Promise<void> {
    if (renew && destroyed !== renew.edgeId) {
      assertEdgeOk(await deleteEdge(renew.edgeId));
      destroyed = renew.edgeId;
      invalidateRelay(qc, relay.slug);
    }
    await provisionRelay(relay.id, renew ? { listenerId: renew.listenerId } : {});
    toast.success(
      renew
        ? 'Replacing that spare. Test the new one here once it is ready.'
        : 'Creating a spare address. Test it here once it is ready.',
    );
    invalidateRelay(qc, relay.slug);
    onStarted?.();
  }
</script>

<ActionConfirm
  bind:open
  title={renew ? 'Replace this spare address?' : 'Add a spare address?'}
  body={renew
    ? 'FCP destroys this spare and creates a new one for the same transport at your provider. The new spare is billed and stays unused until you test it.'
    : 'FCP creates one more address for this node at your provider and keeps it as a spare. It is billed, and it is only put in use after you test it.'}
  confirmLabel={renew ? 'Replace the spare' : 'Add a spare'}
  disabled={preflight.isPending || real.length > 0}
  {onClose}
  {run}
>
  {#if preflight.isPending}
    <Skeleton class="h-9 w-full" />
  {:else if preflight.isError}
    <AdminListState error={preflight.error} onRetry={() => void preflight.refetch()} />
  {:else if real.length > 0}
    <div class="space-y-1.5">
      <p class="text-sm font-medium">It cannot start yet:</p>
      {#each real as b, i (`${b.code}:${i}`)}
        <CodeNote issue={b} compact />
      {/each}
    </div>
  {/if}
</ActionConfirm>
