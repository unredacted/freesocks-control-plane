<script lang="ts">
  /**
   * Where a node's addresses come from: its provider set (docs/edges.md §
   * "Provider sets"). One line per location: how many addresses are in use and
   * spare there, whether it cools after a block, whether it is trusted yet.
   * Then what members miss (a transport with no backup at another provider,
   * one whose locations all cool, one no location carries).
   *
   * Change: "Add a location" lists the locations that carry at least one of
   * the node's transports, and makes a new one from any account (another
   * region, or any DNS zone a CDN account reaches: `LocationPicker`); on a
   * live enrolled node adding one starts a run (new addresses, tested, reviewed
   * when they are a new place) whose progress opens. A WebSocket node is
   * offered CDN accounts only: a load balancer cannot front it (one it had
   * from before reads "Not used").
   * "Remove" drains that location's addresses, refused while what is left
   * elsewhere would not serve every transport with a tested address.
   * "Change options" protects the node again with other provider options at
   * that location: every address is replaced, members move at go-live.
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
  import * as Select from '@client/components/ui/select';
  import { Label } from '@client/components/ui/label';
  import {
    changeProviderSet,
    invalidateRelay,
    providersQuery,
    relayProvidersQuery,
    reprotectRelay,
    templatesQuery,
  } from '@client/lib/edgesApi';
  import OptionFields from '../templates/OptionFields.svelte';
  import { asParams, type Params } from '../templates/params';
  import { optionSummary, overrides, pickBase } from '../lib/options';
  import { EDGE_PROVIDER_META, accountFronts, frontsNode } from '@client/lib/edgeProviderMeta';
  import { codeExplain } from '@client/lib/edgeCodes';
  import LocationPicker from '../forms/LocationPicker.svelte';
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
  /** The account a new location is being made in (the dialog's "New location"). */
  let newIn = $state<string | null>(null);
  const providers = providersQuery();
  const websocketNode = $derived(view?.websocketNode ?? false);
  const accounts = $derived(
    (providers.data?.accounts ?? []).filter(
      (a) => a.enabled && accountFronts(a) && frontsNode(a.provider, websocketNode),
    ),
  );
  const newAccount = $derived(accounts.find((a) => a.id === newIn) ?? null);
  function onNewLocation(id: string) {
    newIn = null;
    invalidateRelay(qc, relay.slug);
    chosen = [...chosen.filter((x) => x !== id), id];
  }
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

  // --- options of one pick (changing them protects the node again) --------------------------------
  const templatesQ = templatesQuery();
  function optionsOf(p: ProviderSetView['picks'][number]) {
    const schema = providers.data?.optionSchemas[p.provider];
    const account = providers.data?.accounts.find((a) => a.id === p.accountId);
    if (!schema || !account) return null;
    const location = account.locations.find((l) => l.id === p.locationId) ?? null;
    const base = pickBase(
      schema,
      templatesQ.data?.schemas[p.provider]?.defaults ?? {},
      templatesQ.data?.templates ?? [],
      account,
      location,
    );
    // What this node chose there: its stored options, less what it would get anyway.
    return {
      fields: schema.fields,
      base,
      chosen: overrides(asParams(p.options), base, schema.fields),
    };
  }
  let optionsFor = $state<ProviderSetView['picks'][number] | null>(null);
  let draft = $state<Params>({});
  let confirmOptions = $state(false);
  const editing = $derived(optionsFor ? optionsOf(optionsFor) : null);
  function openOptions(p: ProviderSetView['picks'][number]) {
    optionsFor = p;
    draft = optionsOf(p)?.chosen ?? {};
  }
  const reprotect = createMutation(() => ({
    mutationFn: (v: { locationId: string; values: Params }) =>
      reprotectRelay(relay.id, 'replace_all', { [v.locationId]: v.values }),
    onSuccess: (r) => {
      invalidateRelay(qc, relay.slug);
      optionsFor = null;
      toast.success('Protecting the node again with the new options.');
      onRunStarted(r.runId);
    },
    onError: (e) => toast.error(edgeErrorMessage(e)),
  }));
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
            {@const o = optionsOf(p)}
            <li class="flex flex-wrap items-start justify-between gap-2 py-2 first:pt-0 last:pb-0">
              <div class="min-w-0 space-y-0.5">
                <p class="flex flex-wrap items-center gap-2 text-sm font-medium">
                  {p.label}
                  <span class="text-muted-foreground font-normal"
                    >{p.accountName}, {providerLabel(p.provider)}</span
                  >
                  {#if !p.qualified}<Badge variant="muted">Not trusted yet</Badge>{/if}
                  {#if !p.usable}<Badge variant="warning">Off</Badge>{/if}
                  {#if !frontsNode(p.provider, websocketNode)}
                    <Badge variant="muted" title={codeExplain('l4_not_for_websocket')}
                      >Not used</Badge
                    >
                  {/if}
                </p>
                <p class="text-muted-foreground text-xs">{line?.counts}</p>
                {#if line?.cooling}<p class="text-xs">{line.cooling}</p>{/if}
                {#if o && frontsNode(p.provider, websocketNode)}
                  {@const said = optionSummary(o.fields, o.chosen)}
                  <p class="text-muted-foreground text-xs">
                    {said.length > 0 ? `Options: ${said.join(', ')}.` : "The location's defaults."}
                    <button
                      type="button"
                      class="text-primary min-h-11 underline-offset-2 hover:underline disabled:opacity-50 sm:min-h-0"
                      disabled={busy || reprotect.isPending}
                      onclick={() => openOptions(p)}>Change options</button
                    >
                  </p>
                {/if}
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
        disabled={busy || change.isPending}
        onclick={() => (adding = true)}
      >
        Add a location
      </Button>
    </div>
  {/if}
</section>

<Dialog.Root bind:open={adding}>
  <Dialog.Content class={newIn ? 'sm:max-w-2xl' : 'sm:max-w-lg'}>
    <Dialog.Header>
      <Dialog.Title>Add a location</Dialog.Title>
      <Dialog.Description>
        The node gets addresses there too. A location at another provider gives members a backup
        elsewhere. New addresses are tested before members get them.
        {#if websocketNode}
          A WebSocket node takes CDN locations only: a load balancer cannot front it.
        {/if}
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
      {#if (view?.available ?? []).length === 0}
        <p class="text-muted-foreground text-sm">
          No other location carries a transport of this node yet. Make one below.
        </p>
      {/if}
    </fieldset>
    <div class="space-y-2 border-t pt-3">
      <div class="space-y-1.5">
        <Label for={`${uid}-new-in`}>New location in</Label>
        <Select.Root
          type="single"
          value={newIn ?? ''}
          onValueChange={(v: string) => (newIn = v || null)}
          disabled={change.isPending}
        >
          <Select.Trigger id={`${uid}-new-in`} class="w-full">
            {newAccount ? newAccount.name : 'Choose an account'}
          </Select.Trigger>
          <Select.Content>
            {#each accounts as a (a.id)}
              <Select.Item value={a.id} label={a.name}>
                {a.name}
                <span class="text-muted-foreground text-xs">
                  {providerLabel(a.provider)}{EDGE_PROVIDER_META[a.provider].layer === 'l7'
                    ? ', any zone it reaches'
                    : ', another region'}
                </span>
              </Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
      </div>
      {#if newAccount}
        {#key newAccount.id}
          <LocationPicker
            accountId={newAccount.id}
            provider={newAccount.provider}
            onCreated={onNewLocation}
            onCancel={() => (newIn = null)}
          />
        {/key}
      {/if}
    </div>
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

<Dialog.Root
  open={optionsFor !== null}
  onOpenChange={(v) => {
    if (!v) optionsFor = null;
  }}
>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
    <Dialog.Header>
      <Dialog.Title>Options at {optionsFor?.label ?? 'this location'}</Dialog.Title>
      <Dialog.Description>
        What this node's addresses there are built with. Saving protects the node again: every
        address is replaced and members move at go-live. Addresses that exist keep theirs until
        then.
      </Dialog.Description>
    </Dialog.Header>
    {#if editing}
      <OptionFields
        fields={editing.fields}
        values={draft}
        base={editing.base}
        baseWord="the location's defaults"
        prominentFirst
        onchange={(next) => (draft = overrides(next, editing.base, editing.fields))}
      />
    {/if}
    <Dialog.Footer>
      <Button
        class="h-11 sm:h-8"
        disabled={reprotect.isPending}
        onclick={() => (confirmOptions = true)}>Protect again with these</Button
      >
      <Button variant="outline" class="h-11 sm:h-8" onclick={() => (optionsFor = null)}
        >Cancel</Button
      >
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<ConfirmDialog
  bind:open={confirmOptions}
  title="Protect the node again?"
  body="Fresh addresses are made everywhere, tested, and reviewed when a review is needed. Members keep what they have until the new addresses go live; the old ones then drain."
  confirmLabel="Protect again"
  onConfirm={async () => {
    if (optionsFor)
      await reprotect.mutateAsync({
        locationId: optionsFor.locationId,
        values: $state.snapshot(draft),
      });
  }}
/>

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
