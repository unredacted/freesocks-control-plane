<script lang="ts">
  /**
   * Choose the plan one load balancer location builds with (its regional size
   * value): every size the location offers, with its price a month, traffic
   * terms, bandwidth and what it accepts. A size that cannot carry an FCP node
   * (`size_not_multicloud`) cannot be chosen. Saving re-opens the location's
   * trust, like any change to what it builds with.
   *
   * Props:
   *   open: boolean (bindable)
   *   account: EdgeProviderAccountAdmin
   *   location: EdgeLocationAdmin | null
   *   sizeKey: string | null          the template key of the provider's size
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import type {
    EdgeLocationAdmin,
    EdgeProviderAccountAdmin,
  } from '../../../../../shared/contracts/edges';
  import { invalidateProviders, updateProviderLocation } from '../../../../lib/edgesApi';
  import PlanFacts from '../components/PlanFacts.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { planRefused } from '../lib/planWords';

  interface Props {
    open: boolean;
    account: EdgeProviderAccountAdmin;
    location: EdgeLocationAdmin | null;
    sizeKey: string | null;
  }
  let { open = $bindable(), account, location, sizeKey }: Props = $props();

  const qc = useQueryClient();
  const plans = $derived(location?.pricing?.plans ?? []);
  /** The size the location builds now, as its plans spell it (sizes compare without case). */
  const current = $derived.by(() => {
    const size = location?.pricing?.size ?? null;
    return plans.find((p) => p.size.toLowerCase() === size?.toLowerCase())?.size ?? size;
  });
  let chosen = $state<string | null>(null);
  $effect(() => {
    if (open) chosen = current;
  });

  const save = createMutation(() => ({
    mutationFn: () =>
      updateProviderLocation(account.id, location!.id, {
        regionalParams: { ...location!.regionalParams, [sizeKey!]: chosen! },
      }),
    onSuccess: () => {
      invalidateProviders(qc);
      toast.success('Plan changed');
      open = false;
    },
  }));
  const CARD =
    'has-[:checked]:border-primary has-[:checked]:bg-primary/5 flex cursor-pointer items-start gap-3 rounded-md border p-3 has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-60';
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-xl`}>
    <Dialog.Header>
      <Dialog.Title>Plan for {location?.label ?? 'this location'}</Dialog.Title>
      <Dialog.Description>
        What each new address here is built with. Addresses that already exist keep theirs.
      </Dialog.Description>
    </Dialog.Header>
    {#if plans.length === 0}
      <p class="text-muted-foreground text-sm">
        No plans were read for this location yet. Refresh its prices first.
      </p>
    {:else}
      <fieldset class="max-h-[60vh] space-y-2 overflow-y-auto">
        <legend class="sr-only">Plans</legend>
        {#each plans as p (p.size)}
          <label class={CARD}>
            <input
              type="radio"
              name="plan"
              class="accent-primary mt-1"
              value={p.size}
              checked={chosen === p.size}
              disabled={planRefused(p) && p.size !== current}
              onchange={() => (chosen = p.size)}
            />
            <span class="min-w-0 flex-1 space-y-0.5">
              <span class="block text-sm font-medium"
                >{p.label}{p.size === current ? ' (now)' : ''}</span
              >
              <PlanFacts plan={p} />
            </span>
          </label>
        {/each}
      </fieldset>
      <p class="text-muted-foreground text-xs">
        Changing the plan clears this location's trust: its next tested address trusts it again.
      </p>
    {/if}
    {#if save.error}<InlineError message={edgeErrorMessage(save.error)} />{/if}
    <Dialog.Footer class={STICKY_FOOTER}>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button
        disabled={!chosen || chosen === current || !sizeKey || !location || save.isPending}
        onclick={() => save.mutate()}
      >
        {save.isPending ? 'Saving' : 'Use this plan'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
