<script lang="ts">
  /**
   * How many addresses one location of a node's provider set holds, per
   * transport (docs/edges.md "Addresses per location"). Before saving, the
   * dialog says what the count adds and what that costs a month, and whether it
   * fits under the account's monthly cap (nothing written). Upkeep then fills
   * it: a spare there first, else a new address there.
   *
   * Props:
   *   open: boolean (bindable)
   *   relayId: string
   *   relaySlug: string
   *   pick: { locationId, label, want, carries } | null
   *   nameOf: transport words by key (optional)
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import { invalidateRelay, previewPickWant, setPickWant } from '@client/lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { MAX_PICK_WANT, wantLine, wantPreviewLines } from './pickWantWords';

  interface Props {
    open: boolean;
    relayId: string;
    relaySlug: string;
    pick: { locationId: string; label: string; want: number | null; carries: string[] } | null;
    nameOf?: (key: string) => string;
  }
  let { open = $bindable(), relayId, relaySlug, pick, nameOf }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  /** '' = at least one, of any transport. */
  let chosen = $state('');
  let seededFor = $state<string | null>(null);
  $effect(() => {
    if (open) {
      chosen = pick?.want ? String(pick.want) : '';
      seededFor = pick?.locationId ?? null;
    } else seededFor = null;
  });
  const want = $derived(chosen === '' ? null : Number(chosen));
  const unchanged = $derived(!!pick && (pick.want ?? null) === want);

  const preview = createQuery(() => {
    const w = want;
    return {
      queryKey: ['edges', 'pick-want-preview', relayId, pick?.locationId ?? '', w],
      queryFn: () => previewPickWant(relayId, pick!.locationId, w),
      enabled: open && !!pick && seededFor === pick.locationId && !unchanged,
      staleTime: 15_000,
      retry: false,
    };
  });
  const lines = $derived(unchanged || !preview.data ? null : wantPreviewLines(preview.data));

  const save = createMutation(() => ({
    mutationFn: () => setPickWant(relayId, pick!.locationId, want),
    onSuccess: (r) => {
      invalidateRelay(qc, relaySlug);
      toast.success(r.want === null ? 'No count for this location now' : 'Count saved');
      open = false;
    },
  }));
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-lg`}>
    <Dialog.Header>
      <Dialog.Title>Addresses at {pick?.label ?? 'this location'}</Dialog.Title>
      <Dialog.Description>
        How many addresses this node keeps in use here, of each transport the location carries.
        Upkeep publishes a spare here first, then adds new ones here, within the account's monthly
        cap.
      </Dialog.Description>
    </Dialog.Header>
    <div class="space-y-1">
      <label for="{uid}-want" class="text-sm font-medium">Addresses here</label>
      <select
        id="{uid}-want"
        class="border-input bg-background h-11 w-full rounded-md border px-2 text-sm sm:h-9"
        bind:value={chosen}
        disabled={save.isPending}
      >
        <option value="">At least one, of any transport</option>
        {#each Array.from({ length: MAX_PICK_WANT }, (_, i) => i + 1) as n (n)}
          <option value={String(n)}>{n}{pick && pick.carries.length > 1 ? ' of each' : ''}</option>
        {/each}
      </select>
      {#if pick}
        <p class="text-muted-foreground text-xs">{wantLine(want, pick.carries, nameOf)}</p>
      {/if}
    </div>
    {#if lines}
      <div class="space-y-1 rounded-md border p-3 text-xs" aria-live="polite">
        {#each lines as line (line)}<p>{line}</p>{/each}
      </div>
    {:else if preview.isFetching}
      <p class="text-muted-foreground text-xs">Working out what it adds.</p>
    {:else if preview.error}
      <InlineError message={edgeErrorMessage(preview.error)} />
    {/if}
    {#if save.error}<InlineError message={edgeErrorMessage(save.error)} />{/if}
    <Dialog.Footer class={STICKY_FOOTER}>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button
        disabled={!pick || unchanged || save.isPending || preview.data?.tooLarge === true}
        onclick={() => save.mutate()}
      >
        {save.isPending ? 'Saving' : 'Save count'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
