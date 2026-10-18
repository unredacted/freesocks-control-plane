<script lang="ts">
  /**
   * Where a node's addresses come from: its provider set (docs/edges.md §
   * "Provider sets"). One line per location: how many addresses are in use and
   * spare there, whether it cools after a block, whether it is trusted yet.
   * Then what members miss (a transport with no backup at another provider,
   * one whose locations all cool, one no location carries).
   *
   * Change: "Add a location" lists the locations that carry at least one of
   * the node's transports; on a live enrolled node adding one starts a run (new
   * addresses, tested, reviewed when they are a new place) whose progress opens.
   * "Remove" drains that location's addresses, refused while what is left
   * elsewhere would not serve every transport with a tested address.
   *
   * Props:
   *   relay: { id, slug }      the origin
   *   busy: boolean            a run or a rotation holds the origin (no edits)
   *   onRunStarted: (runId) => void
   *   nameOf?: (listenerKey) => string    a transport in words
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { changeProviderSet, invalidateRelay, relayProvidersQuery } from '@client/lib/edgesApi';
  import type { ProviderSetView } from '@shared/contracts/edges';
  import AdminListState from '../../AdminListState.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import { providerLabel } from '../lib/format';
  import { providerPickWords } from './runWords';

  interface Props {
    relay: { id: string; slug: string };
    busy: boolean;
    onRunStarted: (runId: string) => void;
    /** A transport in words, by key. */
    nameOf?: (listenerKey: string) => string;
  }
  let { relay, busy, onRunStarted, nameOf }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const setQ = relayProvidersQuery({
    slug: () => relay.slug,
    id: () => relay.id,
    rotating: () => busy,
  });
  const view = $derived(setQ.data ?? null);
  const words = $derived(view ? providerPickWords(view, nameOf) : null);

  let adding = $state(false);
  let chosen = $state<string[]>([]);
  let removing = $state<ProviderSetView['picks'][number] | null>(null);
  let removeOpen = $state(false);

  const change = createMutation(() => ({
    mutationFn: (body: { add?: string[]; remove?: string[] }) => changeProviderSet(relay.id, body),
    onSuccess: (r) => {
      invalidateRelay(qc, relay.slug);
      adding = false;
      chosen = [];
      if (r.runId) {
        toast.success('Adding the location. New addresses are tested before members get them.');
        onRunStarted(r.runId);
      } else toast.success(r.drained > 0 ? 'Location removed. Its addresses drain.' : 'Saved.');
    },
  }));
  const issue = $derived(change.error ? edgeErrorIssue(change.error) : null);
</script>

<section aria-labelledby={`${uid}-providers`}>
  <h3 id={`${uid}-providers`} class="mb-3 text-sm font-semibold">Where its addresses come from</h3>
  {#if setQ.isPending}
    <Skeleton class="h-16 w-full" />
  {:else if setQ.isError || !view || !words}
    <AdminListState error={setQ.error} onRetry={() => void setQ.refetch()} />
  {:else}
    <div class="space-y-3 rounded-lg border p-3">
      {#if view.picks.length === 0}
        <p class="text-muted-foreground text-sm">
          No location is recorded for this node yet: automatic work may use any trusted location.
        </p>
      {:else}
        <ul class="divide-y">
          {#each view.picks as p (p.locationId)}
            {@const line = words.picks.find((x) => x.locationId === p.locationId)}
            <li class="flex flex-wrap items-start justify-between gap-2 py-2 first:pt-0 last:pb-0">
              <div class="min-w-0 space-y-0.5">
                <p class="flex flex-wrap items-center gap-2 text-sm font-medium">
                  {p.label}
                  <span class="text-muted-foreground font-normal"
                    >{p.accountName}, {providerLabel(p.provider)}</span
                  >
                  {#if !p.qualified}<Badge variant="muted">Not trusted yet</Badge>{/if}
                  {#if !p.usable}<Badge variant="warning">Off</Badge>{/if}
                </p>
                <p class="text-muted-foreground text-xs">{line?.counts}</p>
                {#if line?.cooling}<p class="text-xs">{line.cooling}</p>{/if}
              </div>
              {#if view.picks.length > 1}
                <Button
                  size="sm"
                  variant="ghost"
                  class="text-destructive h-11 sm:h-8"
                  disabled={busy || change.isPending}
                  onclick={() => {
                    removing = p;
                    removeOpen = true;
                  }}
                >
                  Remove
                </Button>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
      {#each words.notes as note (note)}
        <p class="text-muted-foreground text-sm">{note}</p>
      {/each}
      {#if issue}<CodeNote {issue} />{:else if change.error}<p class="text-destructive text-sm">
          {edgeErrorMessage(change.error)}
        </p>{/if}
      <Button
        size="sm"
        variant="outline"
        class="h-11 sm:h-8"
        disabled={busy || change.isPending || view.available.length === 0}
        title={view.available.length === 0
          ? 'No other location carries a transport of this node'
          : undefined}
        onclick={() => (adding = true)}
      >
        Add a location
      </Button>
    </div>
  {/if}
</section>

<Dialog.Root bind:open={adding}>
  <Dialog.Content class="sm:max-w-lg">
    <Dialog.Header>
      <Dialog.Title>Add a location</Dialog.Title>
      <Dialog.Description>
        The node gets addresses there too. A location at another provider gives members a backup
        elsewhere. New addresses are tested before members get them.
      </Dialog.Description>
    </Dialog.Header>
    <fieldset class="space-y-1.5">
      <legend class="sr-only">Locations</legend>
      {#each view?.available ?? [] as a (a.locationId)}
        <label
          class="has-[:checked]:border-primary has-[:checked]:bg-primary/5 flex cursor-pointer items-start gap-2 rounded-md border px-2 py-1.5"
        >
          <input
            type="checkbox"
            class="accent-primary mt-1"
            checked={chosen.includes(a.locationId)}
            onchange={(e) =>
              (chosen = e.currentTarget.checked
                ? [...chosen, a.locationId]
                : chosen.filter((x) => x !== a.locationId))}
          />
          <span class="min-w-0">
            <span class="block text-sm">{a.label}</span>
            <span class="text-muted-foreground block text-xs">
              {a.accountName}, {providerLabel(a.provider)}{a.qualified
                ? ''
                : '. Not trusted yet: its first tested address trusts it.'}
            </span>
          </span>
        </label>
      {/each}
    </fieldset>
    <Dialog.Footer>
      <Button
        class="h-11 sm:h-8"
        disabled={chosen.length === 0 || change.isPending}
        onclick={() => change.mutate({ add: chosen })}
      >
        {change.isPending ? 'Adding' : 'Add'}
      </Button>
      <Button variant="outline" class="h-11 sm:h-8" onclick={() => (adding = false)}>Cancel</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<ConfirmDialog
  bind:open={removeOpen}
  title={`Stop using ${removing?.label ?? 'this location'}?`}
  body="Its addresses drain: members move to the node's other addresses at their next refresh. FCP refuses while what is left would not serve every transport with a tested address."
  confirmLabel="Remove location"
  danger
  onConfirm={async () => {
    if (removing) await change.mutateAsync({ remove: [removing.locationId] });
  }}
/>
