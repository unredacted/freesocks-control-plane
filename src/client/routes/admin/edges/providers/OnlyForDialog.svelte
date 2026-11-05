<script lang="ts">
  /**
   * Addresses only for a location's countries (docs/edges.md "Addresses only
   * for some countries"). Switching on: addresses made here from now on are
   * handed only to members in those countries; addresses in use now stay for
   * everyone. Switching off: every address here is everyone's again, for good.
   * The dialog first says why it may not be switched on, when it may not.
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
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import { countryName } from '@client/lib/countries';
  import type {
    EdgeLocationAdmin,
    EdgeProviderAccountAdmin,
  } from '../../../../../shared/contracts/edges';
  import {
    invalidateProviders,
    previewLocationOnly,
    setLocationOnly,
  } from '../../../../lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { onlyForWords } from './meantForWords';

  interface Props {
    open: boolean;
    account: EdgeProviderAccountAdmin;
    location: EdgeLocationAdmin | null;
  }
  let { open = $bindable(), account, location }: Props = $props();

  const qc = useQueryClient();
  const turningOn = $derived(!location?.onlyForMeant);
  const words = $derived(
    location ? onlyForWords(location.meantFor, (c) => countryName(c, 'en')) : null,
  );
  const preview = createQuery(() => ({
    queryKey: ['edges', 'location-only-preview', location?.id ?? ''],
    queryFn: () => previewLocationOnly(account.id, location!.id),
    enabled: open && !!location,
    staleTime: 10_000,
    retry: false,
  }));
  const save = createMutation(() => ({
    mutationFn: () => setLocationOnly(account.id, location!.id, turningOn),
    onSuccess: (r) => {
      invalidateProviders(qc);
      toast.success(
        turningOn
          ? 'New addresses here are only for its countries now'
          : `Every address here is for everyone again${r.widened > 0 ? ` (${r.widened} were contained)` : ''}`,
      );
      open = false;
    },
  }));
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-lg`}>
    <Dialog.Header>
      <Dialog.Title>
        {turningOn ? 'Only for these countries' : 'Back to everyone'} at {location?.label ??
          'this location'}
      </Dialog.Title>
      <Dialog.Description>
        {turningOn ? words?.on : words?.off}
      </Dialog.Description>
    </Dialog.Header>
    {#if turningOn}
      <p class="text-muted-foreground text-xs">{words?.caveat}</p>
      {#if preview.data?.refusal}
        <InlineError message={preview.data.refusal.message} />
      {/if}
    {:else if preview.data && preview.data.contained > 0}
      <p class="text-xs">
        {preview.data.contained}
        {preview.data.contained === 1 ? 'address here is' : 'addresses here are'} only for its countries
        now: members anywhere are handed them from their next refresh.
      </p>
    {/if}
    {#if save.error}<InlineError message={edgeErrorMessage(save.error)} />{/if}
    <Dialog.Footer class={STICKY_FOOTER}>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button
        variant={turningOn ? 'default' : 'destructive'}
        disabled={!location ||
          save.isPending ||
          preview.isPending ||
          (turningOn && !!preview.data?.refusal)}
        onclick={() => save.mutate()}
      >
        {save.isPending ? 'Saving' : turningOn ? 'Only for these countries' : 'Back to everyone'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
