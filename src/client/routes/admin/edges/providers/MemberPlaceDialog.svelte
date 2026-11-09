<script lang="ts">
  /**
   * Where members are told one location's addresses are (docs/edges.md "Names
   * in apps"): a place name and a country, either optional, shown in members'
   * apps after the node's own place, `🇨🇦 Example Port via Example Town` (the
   * flag is the node's; this country's flag shows only for a node with no place,
   * `🇧🇷 via Example Town`). Without a name the addresses read `… via relay A`. The provider's own region name never reaches members;
   * this is the only place name that does. The dialog shows the name members
   * would read as it is typed (src/shared/entryNames.ts, the renderer's own
   * function).
   *
   * Props:
   *   open: boolean (bindable)
   *   account: EdgeProviderAccountAdmin
   *   location: EdgeLocationAdmin | null
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import { COUNTRY_CODES, countryName } from '@client/lib/countries';
  import type {
    EdgeLocationAdmin,
    EdgeProviderAccountAdmin,
  } from '../../../../../shared/contracts/edges';
  import { MAX_PLACE_NAME } from '../../../../../shared/entryNames';
  import { invalidateProviders, setLocationMemberPlace } from '../../../../lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { memberPlaceLine } from './memberPlaceWords';

  interface Props {
    open: boolean;
    account: EdgeProviderAccountAdmin;
    location: EdgeLocationAdmin | null;
  }
  let { open = $bindable(), account, location }: Props = $props();

  const qc = useQueryClient();
  let name = $state('');
  let country = $state('');
  $effect(() => {
    if (open) {
      name = location?.memberPlace.name ?? '';
      country = location?.memberPlace.country ?? '';
    }
  });
  const countries = COUNTRY_CODES.map((code) => ({ code, label: countryName(code, 'en') })).sort(
    (a, b) => a.label.localeCompare(b.label),
  );
  const preview = $derived(memberPlaceLine({ name, country }));
  const unchanged = $derived(
    !!location &&
      name.trim() === (location.memberPlace.name ?? '') &&
      country === (location.memberPlace.country ?? ''),
  );

  const save = createMutation(() => ({
    mutationFn: () => setLocationMemberPlace(account.id, location!.id, { name, country }),
    onSuccess: (r) => {
      invalidateProviders(qc);
      toast.success(
        r.nodes > 0
          ? `Saved. Members of ${r.nodes} node${r.nodes === 1 ? '' : 's'} see it at their next refresh.`
          : 'Saved',
      );
      open = false;
    },
  }));
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-lg`}>
    <Dialog.Header>
      <Dialog.Title>Name in apps for {location?.label ?? 'this location'}</Dialog.Title>
      <Dialog.Description>
        Members see this in their apps for every address here, and anyone with a free account can
        read it. Use a city or a country, never the provider's region name. It follows the node's
        own place, as in "Example Port via Example City". Left empty, members read "Example Port via
        relay A".
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="grid gap-3"
      onsubmit={(e) => {
        e.preventDefault();
        if (location && !unchanged && !save.isPending) save.mutate();
      }}
    >
      <div class="grid gap-1.5">
        <Label for="member-place-name">Place</Label>
        <Input
          id="member-place-name"
          bind:value={name}
          autocomplete="off"
          maxlength={MAX_PLACE_NAME}
          placeholder="Example City"
        />
      </div>
      <div class="grid gap-1.5">
        <Label for="member-place-country">Country (its flag, for a node with no place)</Label>
        <select
          id="member-place-country"
          class="border-input bg-background h-11 rounded-md border px-2 text-sm sm:h-9"
          bind:value={country}
        >
          <option value="">No flag</option>
          {#each countries as c (c.code)}
            <option value={c.code}>{c.label} ({c.code})</option>
          {/each}
        </select>
      </div>
      <p class="rounded-md border p-3 text-sm" aria-live="polite">{preview}</p>
      {#if save.error}<InlineError message={edgeErrorMessage(save.error)} />{/if}
      <Dialog.Footer class={STICKY_FOOTER}>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!location || unchanged || save.isPending}>
          {save.isPending ? 'Saving' : 'Save'}
        </Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
