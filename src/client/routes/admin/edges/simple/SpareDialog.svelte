<script lang="ts">
  /**
   * "Add a spare address" on the node page: one confirm. FCP picks the
   * transport and the account (the provision preflight's own choice); the
   * spare waits unused until someone ticks it on the test card, and only a
   * tested spare is ever put in use. Both the dry run and the provision ask
   * for an unpublished spare (`publish: false`), so an existing standby is
   * never put in use instead. The dry run shows only what blocks it.
   *
   * With `renew` the spare is a replacement for one that does not work: that
   * one is destroyed first (always allowed), then the dry run is asked again
   * and the new spare is created only when nothing blocks it. A destroyed edge
   * still counts against its account until the provider confirms it gone, so
   * an account at its limit gets the new spare later ("Add a spare" again).
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
  import { codeLabel } from '@client/lib/edgeCodes';
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
  const spareCheck = (listenerKey?: string) =>
    preflightRelay(relay.id, {
      kind: 'provision',
      trigger: 'manual',
      publish: false,
      ...(listenerKey ? { listenerKey } : {}),
    });
  // A new spare is checked before the confirm; a renewal after the old one is gone.
  const preflight = createQuery(() => ({
    queryKey: [...edgeKeys.relay(relay.slug), 'preflight', 'spare'],
    queryFn: () => spareCheck(),
    enabled: open && !renew,
    staleTime: 0,
    gcTime: 0,
  }));
  const blockers = $derived(renew ? [] : (preflight.data?.blockers ?? []));

  let destroyed = $state<string | null>(null);
  async function run(): Promise<void> {
    if (!renew) {
      await provisionRelay(relay.id, { publish: false });
      toast.success('Creating a spare address. Test it here once it is ready.');
      invalidateRelay(qc, relay.slug);
      onStarted?.();
      return;
    }
    if (destroyed !== renew.edgeId) {
      assertEdgeOk(await deleteEdge(renew.edgeId));
      destroyed = renew.edgeId;
      invalidateRelay(qc, relay.slug);
    }
    const check = await spareCheck(renew.listenerKey);
    const first = check.blockers[0];
    if (first) {
      toast.message(
        `Removed that spare. A new one cannot be created yet (${codeLabel(first.code.replace(/^edge\./, '')).toLowerCase()}). Add a spare again once that is fixed.`,
      );
      return;
    }
    await provisionRelay(relay.id, { listenerId: renew.listenerId, publish: false });
    toast.success('Replacing that spare. Test the new one here once it is ready.');
    invalidateRelay(qc, relay.slug);
    onStarted?.();
  }
</script>

<ActionConfirm
  bind:open
  title={renew ? 'Replace this spare address?' : 'Add a spare address?'}
  body={renew
    ? 'FCP destroys this spare, then creates a new one for the same transport at your provider when nothing blocks it. The new spare is billed and stays unused until you test it.'
    : 'FCP creates one more address for this node at your provider and keeps it as a spare. It is billed, and it is only put in use after you test it.'}
  confirmLabel={renew ? 'Replace the spare' : 'Add a spare'}
  disabled={!renew && (preflight.isPending || blockers.length > 0)}
  {onClose}
  {run}
>
  {#if !renew}
    {#if preflight.isPending}
      <Skeleton class="h-9 w-full" />
    {:else if preflight.isError}
      <AdminListState error={preflight.error} onRetry={() => void preflight.refetch()} />
    {:else if blockers.length > 0}
      <div class="space-y-1.5">
        <p class="text-sm font-medium">It cannot start yet:</p>
        {#each blockers as b, i (`${b.code}:${i}`)}
          <CodeNote issue={b} compact />
        {/each}
      </div>
    {/if}
  {/if}
</ActionConfirm>
