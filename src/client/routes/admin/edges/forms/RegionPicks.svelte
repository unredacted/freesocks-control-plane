<script lang="ts">
  /**
   * The regions a load balancer account's key reaches that are no location of
   * it yet (its catalog, as the server offers them), each one pickable where a
   * node's addresses are chosen: the protect sheet and a node's "Add a
   * location". Picking a region creates the location then
   * (`POST …/locations {placement: {region}, fill: true}`): the server
   * completes the project and, where one is needed, the private network and
   * subnet from what the key reaches. No credential test runs again, and the
   * new location is untrusted until its first tested address.
   *
   * "Change options" opens the location form on that region with those
   * defaults filled in (`LocationPicker` with `region`), every value
   * changeable. A region the server cannot complete on its own opens it too:
   * no project or network to start from (`location_options_needed`), or a
   * balancer size the template leaves to the region (`template_value_required`:
   * a size is never guessed). "Refresh the list" lists the regions again with
   * the stored credentials.
   *
   * Each row is one place to choose: later, its plan and price go beside it.
   *
   * Props:
   *   accountId: string
   *   provider: EdgeProviderId
   *   regions: Array<{ id, label }>
   *   onPicked: (locationId: string) => void    the location made (or found) for the region
   *   onRefreshed?: () => void                  the list was listed again (ask the server again)
   *   nodeCountry?: string | null               the node's country, for the region hint
   *   disabled?: boolean
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import InlineError from '@client/components/InlineError.svelte';
  import type { EdgeProviderId } from '@shared/contracts/edges';
  import {
    createProviderLocation,
    edgeKeys,
    invalidateProviders,
    refreshProviderCatalog,
  } from '@client/lib/edgesApi';
  import CodeNote from '../components/CodeNote.svelte';
  import { edgeErrorCode, edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import LocationPicker from './LocationPicker.svelte';
  import { regionPlacement } from './providerFields';

  interface Props {
    accountId: string;
    provider: EdgeProviderId;
    regions: ReadonlyArray<{ id: string; label: string }>;
    onPicked: (locationId: string) => void;
    onRefreshed?: () => void;
    nodeCountry?: string | null;
    disabled?: boolean;
  }
  let {
    accountId,
    provider,
    regions,
    onPicked,
    onRefreshed,
    nodeCountry = null,
    disabled = false,
  }: Props = $props();

  const qc = useQueryClient();
  /** The region whose location form is open ("Change options"). */
  let changing = $state<string | null>(null);
  /** Refusals that a choice in the location form answers: the form opens on them. */
  const ASKS: ReadonlySet<string> = new Set(['location_options_needed', 'template_value_required']);

  const pick = createMutation(() => ({
    mutationFn: (regionId: string) =>
      createProviderLocation(accountId, {
        placement: regionPlacement(provider, regionId) ?? {},
        fill: true,
      }),
    onSuccess: (r) => {
      invalidateProviders(qc);
      toast.success(r.created ? 'Location added' : 'This location already exists');
      onPicked(r.id);
    },
    onError: (e, regionId) => {
      // What the key reaches leaves a choice open (no network there, no size): ask for it.
      if (ASKS.has(edgeErrorCode(e) ?? '')) changing = regionId;
    },
  }));
  const askCode = $derived(pick.isError ? edgeErrorCode(pick.error) : null);
  const asked = $derived(askCode !== null && ASKS.has(askCode));
  const refresh = createMutation(() => ({
    mutationFn: () => refreshProviderCatalog(accountId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: edgeKeys.providerCatalog(accountId) });
      onRefreshed?.();
    },
  }));
  function onCreated(id: string) {
    changing = null;
    onPicked(id);
  }
  const LINK =
    'text-primary min-h-11 underline-offset-2 hover:underline disabled:opacity-50 sm:min-h-0';
</script>

<div class="space-y-1.5">
  {#if regions.length > 0}
    <p class="text-muted-foreground text-xs">
      Other regions this account reaches. Picking one adds it as a location, not trusted until its
      first tested address.
    </p>
  {:else}
    <p class="text-muted-foreground text-xs">No region of this account is listed yet.</p>
  {/if}
  <ul class="space-y-1.5">
    {#each regions as r (r.id)}
      {@const adding = pick.isPending && pick.variables === r.id}
      <li>
        <div class="flex items-start gap-2 rounded-md border border-dashed px-2 py-1.5">
          <label class="flex min-w-0 flex-1 cursor-pointer items-start gap-2">
            <input
              type="checkbox"
              class="accent-primary mt-1"
              checked={adding}
              disabled={disabled || pick.isPending}
              onchange={(e) => {
                if (e.currentTarget.checked) pick.mutate(r.id);
              }}
            />
            <span class="min-w-0 flex-1">
              <span class="block text-sm">{r.label}</span>
              <span class="text-muted-foreground block text-xs" aria-live="polite">
                {adding ? 'Adding the location.' : 'New location.'}
              </span>
            </span>
          </label>
          <button
            type="button"
            class={`${LINK} shrink-0 text-xs`}
            disabled={disabled || pick.isPending}
            aria-expanded={changing === r.id}
            onclick={() => (changing = changing === r.id ? null : r.id)}>Change options</button
          >
        </div>
        {#if pick.isError && pick.variables === r.id && changing !== r.id}
          {@const issue = edgeErrorIssue(pick.error)}
          <div class="pt-1 pl-7">
            {#if issue}<CodeNote {issue} />{:else}<InlineError
                message={edgeErrorMessage(pick.error)}
              />{/if}
          </div>
        {/if}
        {#if changing === r.id}
          <div class="mt-1.5 rounded-md border p-3">
            {#if asked && pick.variables === r.id}
              <p class="mb-2 text-sm" role="status">
                {askCode === 'template_value_required'
                  ? 'Choose the balancer size for this region: the template names none.'
                  : 'Choose the rest of this location: FCP could not pick it from what the key lists.'}
              </p>
            {/if}
            {#key r.id}
              <LocationPicker
                {accountId}
                {provider}
                {nodeCountry}
                region={r.id}
                {onCreated}
                onCancel={() => (changing = null)}
              />
            {/key}
          </div>
        {/if}
      </li>
    {/each}
  </ul>
  <div class="flex flex-wrap items-center gap-2">
    <button
      type="button"
      class={`${LINK} text-xs`}
      disabled={disabled || refresh.isPending}
      onclick={() => refresh.mutate()}
    >
      {refresh.isPending ? 'Listing the regions again' : 'Refresh the list'}
    </button>
    {#if refresh.isError}<InlineError message={edgeErrorMessage(refresh.error)} />{/if}
  </div>
</div>
