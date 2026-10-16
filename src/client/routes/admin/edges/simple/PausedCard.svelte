<script lang="ts">
  /**
   * "Paused for safety" (a quarantined node) in plain words, with the same two
   * resolver actions as the Advanced QuarantineResolver: check what the backend
   * serves right now, then keep the old or the new addresses. The audit reason
   * is generated from what the check found (justificationText); the Advanced
   * page keeps the editable reason and the side-by-side bindings ("Details").
   *
   * Props: relay (OriginAdmin with a `quarantine`)
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { OriginAdmin } from '@shared/contracts/edges';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import InlineError from '@client/components/InlineError.svelte';
  import Link from '@client/components/Link.svelte';
  import {
    edgeKeys,
    inspectRelayQuarantine,
    invalidateRelay,
    invalidateOverview,
    relayQuarantineQuery,
    resolveRelayQuarantine,
  } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import ActionConfirm from '../relay/ActionConfirm.svelte';
  import { justificationText, recommendKeep, type QuarantineMatch } from '../relay/relayLogic';
  import { assertEdgeOk, edgeErrorMessage } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';

  interface Props {
    relay: OriginAdmin;
  }
  let { relay }: Props = $props();

  const qc = useQueryClient();
  const viewQ = relayQuarantineQuery({ slug: () => relay.slug, id: () => relay.id });
  const view = $derived(viewQ.data ?? null);
  const recommended = $derived(view ? recommendKeep(view.listeners) : null);

  const MATCH: Record<QuarantineMatch, string> = {
    previous: 'the backend serves the old address',
    current: 'the backend serves the new address',
    neither: 'the backend serves something else',
    absent: 'the backend has nothing for it',
    unknown: 'not checked yet',
  };
  const WHICH = { previous: 'old', current: 'new' } as const;

  const inspect = createMutation(() => ({
    mutationFn: () => inspectRelayQuarantine(relay.id),
    onSuccess: (data) => qc.setQueryData(edgeKeys.relayQuarantine(relay.slug), data),
  }));

  let keep = $state<'previous' | 'current' | null>(null);
  async function resolve(): Promise<void> {
    if (!keep) return;
    const reason = justificationText({
      keep,
      listeners: view?.listeners ?? [],
      inspectedAt: view?.inspectedAt ?? null,
    });
    assertEdgeOk(await resolveRelayQuarantine(relay.id, { keep, reason }));
    toast.success(`Unpaused. FCP keeps the ${WHICH[keep]} addresses.`);
    invalidateRelay(qc, relay.slug);
    invalidateOverview(qc);
  }
</script>

<section
  class="space-y-3 rounded-lg border border-red-500/40 bg-red-500/10 p-4 text-sm"
  aria-labelledby="paused-title"
>
  <h2 id="paused-title" class="text-base font-semibold">Paused for safety</h2>
  <p>
    Replacing an address stopped half way through updating the backend and could not undo it. FCP
    stopped changing this node until you say which addresses members really get.
    {#if relay.quarantine}
      <span class="text-muted-foreground">Since {relativeTime(relay.quarantine.since)}.</span>
    {/if}
  </p>

  <div class="flex flex-wrap items-center gap-3">
    <Button
      variant="outline"
      class="h-11 sm:h-9"
      disabled={inspect.isPending}
      onclick={() => inspect.mutate()}
    >
      {inspect.isPending ? 'Checking the backend' : 'Check the backend'}
    </Button>
    <span class="text-muted-foreground text-xs">
      {view?.inspectedAt
        ? `Last checked ${relativeTime(view.inspectedAt)}.`
        : 'Check first, so the choice rests on what members really get.'}
    </span>
  </div>
  {#if inspect.error}<InlineError message={edgeErrorMessage(inspect.error)} />{/if}

  {#if viewQ.isPending}
    <Skeleton class="h-16 w-full" />
  {:else if viewQ.error}
    <AdminListState error={viewQ.error} onRetry={() => void viewQ.refetch()} />
  {:else if view}
    {#if view.listeners.length > 0}
      <ul class="space-y-1">
        {#each view.listeners as l (l.listenerKey)}
          <li><span class="font-medium">{l.listenerKey}</span>: {MATCH[l.match]}.</li>
        {/each}
      </ul>
    {/if}
    {#if view.extraHosts.length > 0}
      <p class="text-muted-foreground">
        The backend also serves {view.extraHosts.length === 1
          ? 'one address'
          : `${view.extraHosts.length} addresses`} under this node's names that FCP does not know. Remove
        them in the backend if they should not exist.
      </p>
    {/if}
    <p>
      {#if recommended}
        The backend serves the {WHICH[recommended]} addresses for every transport, so keep those.
      {:else if view.inspectedAt}
        The transports do not agree. Fix the odd one in the backend, check again, then decide.
      {:else}
        Which addresses to keep depends on what the backend serves now.
      {/if}
    </p>
    <div class="flex flex-wrap gap-2">
      <Button
        class="h-11 sm:h-9"
        variant={recommended === 'previous' ? 'default' : 'outline'}
        onclick={() => (keep = 'previous')}
      >
        Keep the old addresses
      </Button>
      <Button
        class="h-11 sm:h-9"
        variant={recommended === 'current' ? 'default' : 'outline'}
        onclick={() => (keep = 'current')}
      >
        Keep the new addresses
      </Button>
    </div>
  {/if}
  <Link
    href={edgesPaths.relay(relay.slug, {
      tab: 'rotations',
      rotation: relay.quarantine?.rotationId,
    })}
    class="text-muted-foreground inline-flex min-h-11 items-center text-xs underline underline-offset-4 sm:min-h-0"
  >
    Details
  </Link>
</section>

{#if keep}
  {@const which = WHICH[keep]}
  <ActionConfirm
    open={true}
    title={`Keep the ${which} addresses?`}
    body={keep === 'previous'
      ? 'FCP records that members are still on the addresses from before the replacement: the old address stays in use and the new one becomes a spare. FCP does not change the backend here.'
      : 'FCP records that the replacement did take effect: the new address stays in use and the old one is retired. FCP does not change the backend here.'}
    confirmLabel={`Keep the ${which} addresses`}
    danger={recommended !== null && recommended !== keep}
    onClose={() => (keep = null)}
    run={resolve}
  >
    {#if recommended !== null && recommended !== keep}
      <p class="border-destructive/40 bg-destructive/10 text-destructive rounded-md border p-2">
        The backend serves the {WHICH[recommended]} addresses. Keeping the {which} ones makes FCP's record
        disagree with what members get.
      </p>
    {/if}
  </ActionConfirm>
{/if}
