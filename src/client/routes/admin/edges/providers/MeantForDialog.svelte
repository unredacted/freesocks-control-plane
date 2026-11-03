<script lang="ts">
  /**
   * The countries one location is meant for (docs/edges.md "Locations meant
   * for a country"): members steered by one of them are handed an address
   * here first, among those not blocked there. The censored-country list is
   * what can be chosen; before saving, the dialog shows how many members of
   * each country added or removed would get a different first address on the
   * nodes with an address in use here (synthetic seats, nothing written).
   *
   * Props:
   *   open: boolean (bindable)
   *   account: EdgeProviderAccountAdmin
   *   location: EdgeLocationAdmin | null
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import { countryName } from '@client/lib/countries';
  import { adminCensoredCountriesQuery } from '@client/lib/queries';
  import type {
    EdgeLocationAdmin,
    EdgeProviderAccountAdmin,
  } from '../../../../../shared/contracts/edges';
  import {
    estimateLocationCountries,
    invalidateProviders,
    setLocationCountries,
  } from '../../../../lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { estimateLines } from './meantForWords';

  interface Props {
    open: boolean;
    account: EdgeProviderAccountAdmin;
    location: EdgeLocationAdmin | null;
  }
  let { open = $bindable(), account, location }: Props = $props();

  const qc = useQueryClient();
  const list = adminCensoredCountriesQuery();
  const nameOf = (code: string) => countryName(code, 'en');
  let chosen = $state<string[]>([]);
  // Which location `chosen` was copied from: nothing is estimated before the
  // copy is made (it would ask about an empty list), nor after the dialog closes.
  let seededFor = $state<string | null>(null);
  $effect(() => {
    if (open) {
      chosen = [...(location?.meantFor ?? [])];
      seededFor = location?.id ?? null;
    } else seededFor = null;
  });
  /**
   * What can be ticked: the censored-country list, plus any country the
   * location still has that left the list since (it can only be unticked).
   */
  const options = $derived.by(() => {
    const listed = (list.data?.countries ?? []).map((c) => c.code);
    const stale = (location?.meantFor ?? []).filter((c) => !listed.includes(c));
    return [
      ...listed.map((code) => ({ code, label: nameOf(code) })),
      ...stale.map((code) => ({ code, label: `${nameOf(code)} (no longer on the list)` })),
    ];
  });
  const unchanged = $derived(
    !!location &&
      chosen.length === location.meantFor.length &&
      chosen.every((c) => location.meantFor.includes(c)),
  );
  function toggle(code: string, on: boolean) {
    chosen = on ? [...chosen.filter((c) => c !== code), code] : chosen.filter((c) => c !== code);
  }

  const estimate = createQuery(() => {
    const codes = [...chosen];
    return {
      queryKey: ['edges', 'location-countries-estimate', location?.id ?? '', [...codes].sort()],
      queryFn: () => estimateLocationCountries(account.id, location!.id, codes),
      enabled: open && !!location && seededFor === location.id && !unchanged,
      staleTime: 30_000,
    };
  });
  const lines = $derived(unchanged ? null : estimateLines(estimate.data, nameOf));

  const save = createMutation(() => ({
    mutationFn: () => setLocationCountries(account.id, location!.id, [...chosen]),
    onSuccess: (r) => {
      invalidateProviders(qc);
      toast.success(
        r.codes.length === 0 ? 'No country in particular now' : 'Countries saved for this location',
      );
      open = false;
    },
  }));
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-lg`}>
    <Dialog.Header>
      <Dialog.Title>Countries {location?.label ?? 'this location'} is meant for</Dialog.Title>
      <Dialog.Description>
        Members in these countries get an address here first, as long as it is not blocked there.
        Proof that it is blocked always wins. Only members whose country is known and stored are
        ordered this way.
      </Dialog.Description>
    </Dialog.Header>
    {#if list.isPending}
      <p class="text-muted-foreground text-sm">Reading the censored-country list.</p>
    {:else if options.length === 0}
      <p class="text-muted-foreground text-sm">
        The censored-country list is empty. Add countries to it under Settings first.
      </p>
    {:else}
      <fieldset class="grid max-h-[50vh] gap-2 overflow-y-auto sm:grid-cols-2">
        <legend class="sr-only">Countries</legend>
        {#each options as c (c.code)}
          <label class="flex min-h-11 items-center gap-2 text-sm sm:min-h-8">
            <Checkbox
              checked={chosen.includes(c.code)}
              disabled={save.isPending || (!chosen.includes(c.code) && chosen.length >= 8)}
              onCheckedChange={(v) => toggle(c.code, v === true)}
            />
            <span>{c.label}</span>
          </label>
        {/each}
      </fieldset>
    {/if}
    {#if lines}
      <div class="space-y-1 rounded-md border p-3 text-xs" aria-live="polite">
        {#each lines as line (line)}<p>{line}</p>{/each}
      </div>
    {:else if estimate.isFetching}
      <p class="text-muted-foreground text-xs">Working out who would move.</p>
    {/if}
    {#if save.error}<InlineError message={edgeErrorMessage(save.error)} />{/if}
    <Dialog.Footer class={STICKY_FOOTER}>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button disabled={!location || unchanged || save.isPending} onclick={() => save.mutate()}>
        {save.isPending ? 'Saving' : 'Save countries'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
