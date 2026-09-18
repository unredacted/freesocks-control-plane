<script lang="ts">
  /**
   * Limits and selection of one account: live-edge cap, daily allocation
   * budget, priority and the template it provisions from. One PATCH with only
   * the changed fields.
   *
   * Props:
   *   account: EdgeProviderAccountAdmin
   *   templates: EdgeTemplateAdmin[]       every template (filtered here to the ones this account can use)
   */
  import { untrack } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Label } from '@client/components/ui/label';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import * as Select from '@client/components/ui/select';
  import type {
    EdgeProviderAccountAdmin,
    EdgeTemplateAdmin,
  } from '../../../../../shared/contracts/edges';
  import {
    invalidateProviders,
    updateProvider,
    type ProviderPatch,
  } from '../../../../lib/edgesApi';
  import NumberField from '../components/NumberField.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { effectiveTemplate } from '../templates/params';

  interface Props {
    account: EdgeProviderAccountAdmin;
    templates: EdgeTemplateAdmin[];
  }
  let { account, templates }: Props = $props();

  const qc = useQueryClient();
  const NONE = '__default__';

  const seed = untrack(() => ({
    maxLiveEdges: account.maxLiveEdges,
    dailyAllocationBudget: account.dailyAllocationBudget,
    priority: account.priority,
    defaultTemplateId: account.defaultTemplateId,
  }));
  let maxLiveEdges = $state(seed.maxLiveEdges);
  let dailyAllocationBudget = $state(seed.dailyAllocationBudget);
  let priority = $state(seed.priority);
  let defaultTemplateId = $state<string | null>(seed.defaultTemplateId);
  let badMax = $state(false);
  let badBudget = $state(false);
  let badPriority = $state(false);

  const usable = $derived(
    templates.filter(
      (t) =>
        t.provider === account.provider && (t.accountId === null || t.accountId === account.id),
    ),
  );
  const fallback = $derived(effectiveTemplate(templates, { ...account, defaultTemplateId: null }));

  const patch = $derived.by(() => {
    const p: ProviderPatch = {};
    if (maxLiveEdges !== account.maxLiveEdges) p.maxLiveEdges = maxLiveEdges;
    if (dailyAllocationBudget !== account.dailyAllocationBudget)
      p.dailyAllocationBudget = dailyAllocationBudget;
    if (priority !== account.priority) p.priority = priority;
    if (defaultTemplateId !== account.defaultTemplateId) p.defaultTemplateId = defaultTemplateId;
    return p;
  });
  const changed = $derived(Object.keys(patch).length);
  const templateMoves = $derived('defaultTemplateId' in patch);

  const save = createMutation(() => ({
    mutationFn: () => updateProvider(account.id, patch),
    onSuccess: () => {
      invalidateProviders(qc);
      toast.success('Account saved');
    },
    onError: (err: unknown) =>
      toast.error('Could not save the account', { description: edgeErrorMessage(err) }),
  }));
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Limits and selection</CardTitle>
    <CardDescription>
      How much FCP may create in this account, and how it ranks against the other accounts.
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-4">
    <div class="grid gap-4 sm:grid-cols-3">
      <NumberField
        bind:value={maxLiveEdges}
        bind:invalid={badMax}
        label="Live edges, at most"
        unit="edges"
        min={1}
        max={200}
        helper="Provisioning skips the account once this many edges exist in it."
      />
      <NumberField
        bind:value={dailyAllocationBudget}
        bind:invalid={badBudget}
        label="Allocations per day"
        unit="per day"
        min={0}
        max={1000}
        helper={`New edges FCP may create here per day. ${account.allocationsToday} used today. Zero stops new edges.`}
      />
      <NumberField
        bind:value={priority}
        bind:invalid={badPriority}
        label="Priority"
        helper="Among accounts that fit, the higher number is tried first."
      />
    </div>

    <div class="max-w-md space-y-1.5">
      <Label for="acct-template">Template</Label>
      <Select.Root
        type="single"
        value={defaultTemplateId ?? NONE}
        onValueChange={(v) => (defaultTemplateId = v === NONE ? null : v)}
      >
        <Select.Trigger id="acct-template" class="w-full">
          {defaultTemplateId === null
            ? `Provider default${fallback ? ` (${fallback.name})` : ''}`
            : (usable.find((t) => t.id === defaultTemplateId)?.name ??
              'A template that was removed')}
        </Select.Trigger>
        <Select.Content>
          <Select.Item value={NONE}>
            Provider default{fallback ? ` (${fallback.name})` : ''}
          </Select.Item>
          {#each usable as t (t.id)}
            <Select.Item value={t.id}>{t.name}</Select.Item>
          {/each}
        </Select.Content>
      </Select.Root>
      {#if templateMoves}
        <p class="text-xs text-amber-700 dark:text-amber-300">
          Edges from this account will be created with different parameters, so saving clears the
          qualification when the parameters differ.
        </p>
      {/if}
    </div>

    <div class="flex items-center justify-end gap-3">
      {#if changed > 0}
        <span class="text-xs text-muted-foreground"
          >{changed} change{changed === 1 ? '' : 's'} not saved</span
        >
      {/if}
      <Button
        disabled={changed === 0 || badMax || badBudget || badPriority || save.isPending}
        onclick={() => save.mutate()}
      >
        {save.isPending ? 'Saving' : 'Save'}
      </Button>
    </div>
  </CardContent>
</Card>
