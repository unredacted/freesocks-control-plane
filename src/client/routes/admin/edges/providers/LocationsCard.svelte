<script lang="ts">
  /**
   * An account's locations: where its edges are created. One row per
   * location with its trust, its addresses and its cost note; actions to add
   * one (`LocationPicker`), trust or untrust one (trust is per location: a
   * new region is trusted by its first tested address), switch one off, make
   * one the default the pickers preselect, or remove one nothing uses. A CDN
   * account has exactly one location, created with it.
   *
   * Props:
   *   account: EdgeProviderAccountAdmin
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import type {
    EdgeLocationAdmin,
    EdgeProviderAccountAdmin,
  } from '../../../../../shared/contracts/edges';
  import {
    deleteProviderLocation,
    invalidateProviders,
    qualifyProviderLocation,
    updateProviderLocation,
  } from '../../../../lib/edgesApi';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { relativeTime } from '../lib/time';
  import LocationPicker from '../forms/LocationPicker.svelte';
  import { hasLocations } from '../forms/providerFields';
  import QualifyDialog from './QualifyDialog.svelte';
  import { locationTrustWords } from './accountWords';

  interface Props {
    account: EdgeProviderAccountAdmin;
  }
  let { account }: Props = $props();

  const qc = useQueryClient();
  const places = $derived(hasLocations(account.provider));
  let adding = $state(false);
  let trusting = $state<EdgeLocationAdmin | null>(null);
  let trustOpen = $state(false);
  let removing = $state<EdgeLocationAdmin | null>(null);
  let removeOpen = $state(false);

  const patch = createMutation(() => ({
    mutationFn: (a: { id: string; patch: Parameters<typeof updateProviderLocation>[2] }) =>
      updateProviderLocation(account.id, a.id, a.patch),
    onSuccess: () => invalidateProviders(qc),
    onError: (err: unknown) => toast.error(edgeErrorMessage(err)),
  }));

  async function qualify(id: string, qualified: boolean): Promise<void> {
    await qualifyProviderLocation(account.id, id, qualified);
    invalidateProviders(qc);
    toast.success(qualified ? 'Location trusted' : 'Trust removed');
  }

  function capacity(l: EdgeLocationAdmin): string {
    return l.maxLiveEdges === null
      ? `${l.liveEdges} address${l.liveEdges === 1 ? '' : 'es'}`
      : `${l.liveEdges} of ${l.maxLiveEdges} addresses`;
  }
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Locations</CardTitle>
    <CardDescription>
      {#if places}
        Where this account's edges are created. Pick one when you protect a node or add an address;
        each address stays in the location it was created in. Trust is per location: a new one is
        trusted by its first tested address.
      {:else}
        This provider is not tied to a region: the account has one location, created with it.
      {/if}
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-3">
    {#if account.locations.length === 0}
      <p class="text-muted-foreground text-sm">
        No location yet. Add one: nothing can be created in this account until it has one.
      </p>
    {/if}
    <ul class="divide-y rounded-md border">
      {#each account.locations as l (l.id)}
        {@const trust = locationTrustWords(l)}
        <li class="flex flex-wrap items-start justify-between gap-3 p-3">
          <div class="min-w-0 space-y-1">
            <p class="flex flex-wrap items-center gap-2 font-medium">
              {l.label}
              {#if l.isDefault && account.locations.length > 1}<Badge variant="info">Default</Badge
                >{/if}
              {#if !l.enabled}<Badge variant="muted">Off</Badge>{/if}
              <Badge variant={trust.tone}>{trust.label}</Badge>
            </p>
            <p class="text-muted-foreground text-xs">
              {trust.detail}
              {capacity(l)}.
              {#if l.inventoryAt}Inventory {relativeTime(l.inventoryAt)}.{/if}
            </p>
            {#if l.costNote}<p class="text-xs">{l.costNote}</p>{/if}
            {#if Object.keys(l.regionalParams).length > 0}
              <p class="text-muted-foreground font-mono text-xs">
                {Object.entries(l.regionalParams)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join(', ')}
              </p>
            {/if}
          </div>
          <div class="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="outline"
              class="h-11 sm:h-8"
              onclick={() => {
                trusting = l;
                trustOpen = true;
              }}
            >
              {l.qualified ? 'Remove trust' : 'Trust override'}
            </Button>
            {#if places}
              <Button
                size="sm"
                variant="outline"
                class="h-11 sm:h-8"
                disabled={patch.isPending}
                onclick={() => patch.mutate({ id: l.id, patch: { enabled: !l.enabled } })}
              >
                {l.enabled ? 'Switch off' : 'Switch on'}
              </Button>
              {#if !l.isDefault}
                <Button
                  size="sm"
                  variant="ghost"
                  class="h-11 sm:h-8"
                  disabled={patch.isPending}
                  onclick={() => patch.mutate({ id: l.id, patch: { makeDefault: true } })}
                >
                  Make default
                </Button>
              {/if}
              <Button
                size="sm"
                variant="ghost"
                class="text-destructive h-11 sm:h-8"
                disabled={l.liveEdges > 0}
                title={l.liveEdges > 0 ? 'Addresses still live here' : undefined}
                onclick={() => {
                  removing = l;
                  removeOpen = true;
                }}
              >
                Remove
              </Button>
            {/if}
          </div>
        </li>
      {/each}
    </ul>
    {#if places}
      <Button size="sm" class="h-11 sm:h-8" onclick={() => (adding = true)}>Add location</Button>
    {/if}
  </CardContent>
</Card>

<Dialog.Root bind:open={adding}>
  <Dialog.Content class="sm:max-w-2xl">
    <Dialog.Header>
      <Dialog.Title>Add a location to {account.name}</Dialog.Title>
      <Dialog.Description>
        A region or zone this account can create addresses in. The provider lists what these
        credentials can use.
      </Dialog.Description>
    </Dialog.Header>
    {#if adding}
      <LocationPicker
        accountId={account.id}
        provider={account.provider}
        onCreated={() => (adding = false)}
        onCancel={() => (adding = false)}
      />
    {/if}
  </Dialog.Content>
</Dialog.Root>

<QualifyDialog
  bind:open={trustOpen}
  account={trusting
    ? { id: trusting.id, name: `${account.name}, ${trusting.label}`, qualified: trusting.qualified }
    : null}
  tested={!!account.lastTestOkAt && !account.lastTestError}
  onQualify={qualify}
/>

<ConfirmDialog
  bind:open={removeOpen}
  title={`Remove the location ${removing?.label ?? ''}?`}
  body="Nothing at the provider is touched. FCP refuses while an address still lives here or a protected node uses this location."
  confirmLabel="Remove location"
  danger
  onConfirm={async () => {
    if (!removing) return;
    await deleteProviderLocation(account.id, removing.id);
    invalidateProviders(qc);
    toast.success('Location removed');
  }}
/>

{#if patch.error}<InlineError message={edgeErrorMessage(patch.error)} />{/if}
