<script lang="ts">
  /**
   * Resolve a quarantined origin. A rotation stopped half way through switching
   * the backend Hosts and could not roll back, so FCP no longer knows which binding
   * members get. Per listener: the previous binding, what the backend serves right
   * now ("Inspect backend", throttled) and the current binding, with the matching
   * one highlighted; then "Keep previous" / "Keep current" with an editable,
   * generated justification that is written to the audit log.
   *
   * Props: origin; onOpenEdge(edgeId); onOpenRotation(rotationId)
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { RelayAdmin } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Label } from '@client/components/ui/label';
  import { Skeleton } from '@client/components/ui/skeleton';
  import InlineError from '@client/components/InlineError.svelte';
  import {
    edgeKeys,
    inspectRelayQuarantine,
    invalidateRelay,
    relayQuarantineQuery,
    resolveRelayQuarantine,
  } from '@client/lib/edgesApi';
  import { codeLabel } from '@client/lib/edgeCodes';
  import AdminListState from '../../AdminListState.svelte';
  import { assertEdgeOk, edgeErrorMessage } from '../lib/edgeErrors';
  import { relativeTime } from '../lib/time';
  import ActionConfirm from './ActionConfirm.svelte';
  import HostTupleBox from './HostTupleBox.svelte';
  import {
    MATCH_WORDS,
    REASON_MAX,
    highlightedColumn,
    justificationText,
    matchTone,
    recommendKeep,
    tupleLine,
  } from './relayLogic';

  interface Props {
    relay: RelayAdmin;
    onOpenEdge: (edgeId: string) => void;
    onOpenRotation: (rotationId: string) => void;
  }
  let { relay, onOpenEdge, onOpenRotation }: Props = $props();

  const qc = useQueryClient();
  const viewQ = relayQuarantineQuery({ slug: () => relay.slug, id: () => relay.id });
  const view = $derived(viewQ.data ?? null);
  const recommended = $derived(view ? recommendKeep(view.listeners) : null);

  const inspect = createMutation(() => ({
    mutationFn: () => inspectRelayQuarantine(relay.id),
    onSuccess: (data) => {
      qc.setQueryData(edgeKeys.relayQuarantine(relay.slug), data);
      toast.success('Read the Hosts from the backend.');
    },
  }));

  let keep = $state<'previous' | 'current' | null>(null);
  let reason = $state('');
  function ask(which: 'previous' | 'current'): void {
    reason = justificationText({
      keep: which,
      listeners: view?.listeners ?? [],
      inspectedAt: view?.inspectedAt ?? null,
    });
    keep = which;
  }

  async function resolve(): Promise<void> {
    if (!keep) return;
    const text = reason.trim();
    assertEdgeOk(
      await resolveRelayQuarantine(relay.id, { keep, ...(text ? { reason: text } : {}) }),
    );
    toast.success(`Quarantine resolved. FCP now treats the ${keep} binding as the truth.`);
    invalidateRelay(qc, relay.slug);
  }
</script>

<Card.Root class="border-destructive/50">
  <Card.Header>
    <Card.Title class="flex flex-wrap items-center gap-2">
      Quarantined
      <Badge variant="danger">Needs your decision</Badge>
    </Card.Title>
    <Card.Description>
      A rotation changed the backend Hosts of this origin and could neither finish nor undo it. FCP
      stopped touching the origin so it cannot make things worse: no rotation, publish or unpublish
      runs until you say which binding is the real one.
    </Card.Description>
    {#if relay.quarantine}
      <Card.Action>
        <Button
          variant="outline"
          size="sm"
          onclick={() => relay.quarantine && onOpenRotation(relay.quarantine.rotationId)}
        >
          Open the rotation
        </Button>
      </Card.Action>
    {/if}
  </Card.Header>
  <Card.Content class="space-y-4 text-sm">
    {#if relay.quarantine}
      <p class="text-muted-foreground">
        Since {relativeTime(relay.quarantine.since)}. Reason: {codeLabel(
          relay.quarantine.reason.replace(/^edge\./, ''),
        )}.
      </p>
    {/if}

    <ol class="list-decimal space-y-1 ps-5 text-muted-foreground">
      <li>Inspect the backend to see which Host it serves for each listener right now.</li>
      <li>
        Keep the binding the backend serves. If the listeners disagree, fix the odd Host in the
        backend first, inspect again, then decide.
      </li>
    </ol>

    <div class="flex flex-wrap items-center gap-3">
      <Button variant="outline" disabled={inspect.isPending} onclick={() => inspect.mutate()}>
        {inspect.isPending ? 'Reading the panel…' : 'Inspect panel'}
      </Button>
      <span class="text-xs text-muted-foreground">
        {view?.inspectedAt
          ? `Last inspected ${relativeTime(view.inspectedAt)}.`
          : 'Not inspected yet: the middle column is empty until you do.'}
        This reads the live panel, so it is limited to a few calls per minute.
      </span>
    </div>
    {#if inspect.error}
      <InlineError message={edgeErrorMessage(inspect.error)} />
    {/if}

    {#if viewQ.isPending}
      <Skeleton class="h-32 w-full" />
    {:else if viewQ.error}
      <AdminListState error={viewQ.error} onRetry={() => void viewQ.refetch()} />
    {:else if view}
      {#if view.listeners.length === 0}
        <AdminListState
          emptyText="The rotation recorded no Host for any listener. Either binding is safe to keep: choose the current one unless you know the rotation never published its edge."
        />
      {/if}
      {#each view.listeners as l (l.listenerKey)}
        {@const column = highlightedColumn(l.match)}
        <section class="space-y-2 rounded-lg border p-3" aria-label={`Listener ${l.listenerKey}`}>
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="font-medium">Listener <span class="font-mono">{l.listenerKey}</span></h3>
            <Badge variant={matchTone(l.match)}>{MATCH_WORDS[l.match]}</Badge>
            {#if l.remark}
              <span class="text-xs text-muted-foreground">
                Host remark <span class="font-mono">{l.remark}</span>
              </span>
            {/if}
          </div>
          <div class="grid gap-2 md:grid-cols-3">
            <HostTupleBox
              title="Previous binding"
              tuple={l.previous}
              edgeId={l.previous?.edgeId}
              emptyText="There was no Host before this rotation."
              highlight={column === 'previous'}
              {onOpenEdge}
            />
            <HostTupleBox
              title="Panel, right now"
              tuple={l.live}
              uuid={l.live?.uuid}
              emptyText={l.match === 'absent'
                ? 'The panel has no Host under this remark.'
                : 'Unknown until you inspect the panel.'}
              tone={column ? 'match' : l.match === 'unknown' ? 'plain' : 'mismatch'}
            />
            <HostTupleBox
              title="Current binding"
              tuple={l.current}
              edgeId={l.current?.edgeId}
              emptyText="The rotation had not planned a Host for this listener."
              highlight={column === 'current'}
              {onOpenEdge}
            />
          </div>
        </section>
      {/each}

      {#if view.extraHosts.length > 0}
        <section class="space-y-1 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3">
          <h3 class="font-medium">Other Hosts under this origin's names</h3>
          <p class="text-xs text-muted-foreground">
            The backend serves these too and no listener claims them: duplicates or leftovers from
            an earlier setup. Members may be handed them. Remove them in the backend if they are not
            meant to exist.
          </p>
          <ul class="space-y-0.5 font-mono text-xs">
            {#each view.extraHosts as h (h.uuid)}
              <li>{h.remark}: {tupleLine(h)}, server name {h.sni ?? 'none'} ({h.uuid})</li>
            {/each}
          </ul>
        </section>
      {/if}

      <div class="flex flex-wrap items-center gap-2 border-t pt-4">
        <Button
          variant={recommended === 'previous' ? 'default' : 'outline'}
          onclick={() => ask('previous')}
        >
          Keep previous
        </Button>
        <Button
          variant={recommended === 'current' ? 'default' : 'outline'}
          onclick={() => ask('current')}
        >
          Keep current
        </Button>
        <span class="text-xs text-muted-foreground">
          {#if recommended}
            Every listener matches the {recommended} binding, so that is the safe choice.
          {:else if view.inspectedAt}
            The listeners do not agree on one binding. Look at each row before deciding.
          {:else}
            Inspect the panel first so the choice rests on what it really serves.
          {/if}
        </span>
      </div>
    {/if}
  </Card.Content>
</Card.Root>

{#if keep}
  <ActionConfirm
    open={true}
    title={keep === 'previous' ? 'Keep the previous binding?' : 'Keep the current binding?'}
    body={keep === 'previous'
      ? 'FCP records that members are on the edges from before the rotation: the old edge stays published and the new one becomes an unpublished standby. FCP does not write to the panel here, so the panel must already serve the previous Hosts.'
      : 'FCP records that the rotation did take effect: the new edge is published and the old one drains. FCP does not write to the panel here, so the panel must already serve the current Hosts.'}
    confirmLabel={keep === 'previous' ? 'Keep previous' : 'Keep current'}
    danger={recommended !== null && recommended !== keep}
    disabled={reason.trim().length > REASON_MAX}
    onClose={() => (keep = null)}
    run={resolve}
  >
    {#if recommended !== null && recommended !== keep}
      <p
        class="mb-3 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-destructive"
      >
        The panel serves the {recommended} binding for every listener. Keeping the other one makes FCP's
        record disagree with what members get.
      </p>
    {/if}
    <div class="space-y-1.5">
      <Label for="quarantine-reason">Justification (goes to the audit log, edit as needed)</Label>
      <textarea
        id="quarantine-reason"
        bind:value={reason}
        rows="3"
        maxlength={REASON_MAX}
        class="w-full rounded-md border bg-background px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
      ></textarea>
      <p class="text-xs text-muted-foreground">
        {reason.trim().length} of {REASON_MAX} characters.
      </p>
    </div>
  </ActionConfirm>
{/if}
