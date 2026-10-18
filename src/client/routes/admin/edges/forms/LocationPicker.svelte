<script lang="ts">
  /**
   * Add a location to a stored account: where its edges are created (region or
   * zone, the project, the private network where the provider needs one), and
   * the load balancer flavor of that region when the template's own is not
   * offered there. The lists come live from the provider with the account's
   * stored credentials (`POST providers/{id}/locations/options`); the server
   * checks the region is offered to this key before it saves the location, and
   * the same place twice is the same location.
   *
   * Props:
   *   accountId: string
   *   provider: EdgeProviderId
   *   onCreated: (locationId: string) => void
   *   onCancel?: () => void
   *   nodeCountry?: string | null    the node's country, for the region hint
   */
  import { untrack } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import type { EdgeDiscoverResponse, EdgeProviderId } from '@shared/contracts/edges';
  import {
    createProviderLocation,
    invalidateProviders,
    locationOptions,
    providersQuery,
    templatesQuery,
  } from '@client/lib/edgesApi';
  import CodeNote from '../components/CodeNote.svelte';
  import ProviderAnswer from '../components/ProviderAnswer.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import {
    locationFields,
    missingRequired,
    optionsFor,
    placementBody,
    type ProviderField,
  } from './providerFields';

  interface Props {
    accountId: string;
    provider: EdgeProviderId;
    onCreated: (locationId: string) => void;
    onCancel?: () => void;
    nodeCountry?: string | null;
  }
  let { accountId, provider, onCreated, onCancel, nodeCountry = null }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const templates = templatesQuery();
  const providers = providersQuery();

  let values = $state<Record<string, string>>({});
  let discovered = $state<EdgeDiscoverResponse | null>(null);
  let regional = $state<Record<string, string>>({});
  let costNote = $state('');
  let tried = $state(false);

  const fields = $derived(locationFields(provider));
  const ctx = $derived({ discovered, accounts: [], values });
  const missing = $derived(
    missingRequired(provider, values).filter((l) => fields.some((f) => f.label === l)),
  );

  /**
   * The template fields whose value differs per region, with the value the template carries now.
   * The template is the one the server would use for a new location: the account's chosen one,
   * then the account-scoped default, then the provider default (`resolveTemplateFor`).
   */
  const regionalFields = $derived.by(() => {
    const schema = templates.data?.schemas[provider];
    const list = (templates.data?.templates ?? []).filter(
      (t) => t.provider === provider && (t.accountId === null || t.accountId === accountId),
    );
    const chosenId = providers.data?.accounts.find((a) => a.id === accountId)?.defaultTemplateId;
    const tpl =
      (chosenId ? list.find((t) => t.id === chosenId) : undefined) ??
      list.find((t) => t.isDefault && t.accountId === accountId) ??
      list.find((t) => t.isDefault && t.accountId === null);
    const params = (tpl?.params ?? schema?.defaults ?? {}) as Record<string, unknown>;
    return (schema?.fields ?? [])
      .filter((f) => f.regional)
      .map((f) => ({ key: f.key, label: f.label, templateValue: String(params[f.key] ?? '') }));
  });
  /** A regional value the template leaves empty must be chosen here. */
  const regionalMissing = $derived(
    regionalFields.filter((f) => !f.templateValue && !(regional[f.key] ?? '').trim()),
  );

  const load = createMutation(() => ({
    mutationFn: (placement: Record<string, unknown>) => locationOptions(accountId, placement),
    onSuccess: (r) => {
      discovered = r;
      // Pre-select a list with one choice; drop a choice the new lists no longer offer.
      const next = { ...values };
      for (const f of fields) {
        if (f.kind !== 'select') continue;
        const opts = optionsFor(f, { discovered: r, accounts: [], values: next });
        const current = next[f.key] ?? '';
        if (current && opts.length > 0 && !opts.some((o) => o.id === current)) next[f.key] = '';
        if (!next[f.key] && opts.length === 1 && opts[0]) next[f.key] = opts[0].id;
      }
      values = next;
    },
  }));
  untrack(() => load.mutate({}));

  function onFieldChange(f: ProviderField, value: string) {
    const next = { ...values, [f.key]: value };
    if (f.from === 'networks') next['subnetId'] = '';
    values = next;
    // The networks, subnets and flavors of a region depend on the project and the region.
    if (f.from === 'projects' || f.from === 'regions') load.mutate(placementBody(provider, values));
  }

  const create = createMutation(() => ({
    mutationFn: () =>
      createProviderLocation(accountId, {
        placement: placementBody(provider, values),
        ...(Object.keys(cleanRegional()).length > 0 ? { regionalParams: cleanRegional() } : {}),
        ...(costNote.trim() ? { costNote: costNote.trim() } : {}),
      }),
    onSuccess: (r) => {
      invalidateProviders(qc);
      toast.success(r.created ? 'Location added' : 'This location already exists');
      onCreated(r.id);
    },
  }));
  function cleanRegional(): Record<string, string> {
    return Object.fromEntries(
      Object.entries(regional)
        .map(([k, v]) => [k, v.trim()] as const)
        .filter(([, v]) => v !== ''),
    );
  }
  const issue = $derived(create.error ? edgeErrorIssue(create.error) : null);
  const regionHint = $derived(
    nodeCountry
      ? `The node is in ${nodeCountry}. Pick a region close to it: members reach the address, which forwards to the node.`
      : 'Pick a region close to the node: members reach the address, which forwards to the node.',
  );
</script>

{#snippet fieldInput(f: ProviderField)}
  {@const opts = optionsFor(f, ctx)}
  {@const current = values[f.key] ?? ''}
  <div class="space-y-1.5">
    <Label for={`${uid}-${f.key}`}>{f.label}{f.required ? '' : ' (optional)'}</Label>
    {#if f.kind === 'select' && opts.length > 0}
      <Select.Root
        type="single"
        value={current}
        onValueChange={(v: string) => onFieldChange(f, v === '__none' ? '' : v)}
        disabled={create.isPending}
      >
        <Select.Trigger id={`${uid}-${f.key}`} class="w-full">
          {opts.find((o) => o.id === current)?.label ?? (current || 'Choose one')}
        </Select.Trigger>
        <Select.Content>
          {#if !f.required}
            <Select.Item value="__none" label="None">None</Select.Item>
          {/if}
          {#each opts as o (o.id)}
            <Select.Item value={o.id} label={o.label}>{o.label}</Select.Item>
          {/each}
        </Select.Content>
      </Select.Root>
    {:else}
      <Input
        id={`${uid}-${f.key}`}
        class="font-mono"
        value={current}
        placeholder={f.placeholder}
        disabled={create.isPending}
        oninput={(e) => onFieldChange(f, e.currentTarget.value)}
      />
      {#if f.kind === 'select' && f.from !== 'subnets' && !load.isPending}
        <p class="text-muted-foreground text-xs">
          The provider returned no list for this, so type the id.
        </p>
      {/if}
    {/if}
    {#if f.help}<p class="text-muted-foreground text-xs">{f.help}</p>{/if}
    {#if f.from === 'regions'}<p class="text-muted-foreground text-xs">{regionHint}</p>{/if}
  </div>
{/snippet}

<div class="space-y-4">
  <div aria-live="polite">
    {#if load.isPending && !discovered}
      <p class="text-muted-foreground text-sm" role="status">
        Asking the provider where this account can create addresses.
      </p>
    {:else if load.isError}
      {@const e = edgeErrorIssue(load.error)}
      {#if e}<CodeNote issue={e} />{:else}<InlineError
          message={edgeErrorMessage(load.error)}
        />{/if}
    {/if}
    {#each Object.entries(discovered?.errors ?? {}) as [list, code] (list)}
      <CodeNote
        tone="warning"
        issue={{ code, subject: list, detail: 'This list could not be read. Type the id instead.' }}
      />
      <ProviderAnswer detail={discovered?.errorDetails?.[list]} />
    {/each}
  </div>
  <div class="grid gap-4 sm:grid-cols-2">
    {#each fields as f (f.key)}
      {@render fieldInput(f)}
    {/each}
    {#each regionalFields as rf (rf.key)}
      {@const flavors = discovered?.flavors ?? []}
      {@const current = regional[rf.key] ?? ''}
      <div class="space-y-1.5">
        <Label for={`${uid}-r-${rf.key}`}>{rf.label} in this region</Label>
        {#if flavors.length > 0}
          <Select.Root
            type="single"
            value={current}
            onValueChange={(v: string) =>
              (regional = { ...regional, [rf.key]: v === '__tpl' ? '' : v })}
            disabled={create.isPending}
          >
            <Select.Trigger id={`${uid}-r-${rf.key}`} class="w-full">
              {current
                ? (flavors.find((o) => o.id === current)?.label ?? current)
                : rf.templateValue
                  ? `The template's (${rf.templateValue})`
                  : 'Choose one'}
            </Select.Trigger>
            <Select.Content>
              {#if rf.templateValue}
                <Select.Item value="__tpl" label="The template's">
                  The template's ({rf.templateValue})
                </Select.Item>
              {/if}
              {#each flavors as o (o.id)}
                <Select.Item value={o.id} label={o.label}>{o.label}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        {:else}
          <Input
            id={`${uid}-r-${rf.key}`}
            class="font-mono"
            value={current}
            placeholder={rf.templateValue || undefined}
            disabled={create.isPending}
            oninput={(e) => (regional = { ...regional, [rf.key]: e.currentTarget.value })}
          />
        {/if}
        <p class="text-muted-foreground text-xs">
          A flavor is offered per region. {rf.templateValue
            ? "Leave the template's when this region offers it."
            : 'The template names none, so choose the one to use here.'}
        </p>
      </div>
    {/each}
    <div class="space-y-1.5 sm:col-span-2">
      <Label for={`${uid}-cost`}>Cost note (optional)</Label>
      <Input
        id={`${uid}-cost`}
        bind:value={costNote}
        maxlength={120}
        placeholder="About 10 a month per address"
        disabled={create.isPending}
      />
      <p class="text-muted-foreground text-xs">
        Shown next to this location when it is picked. Only admins see it.
      </p>
    </div>
  </div>
  {#if tried && (missing.length > 0 || regionalMissing.length > 0)}
    <p class="text-destructive text-sm" role="alert">
      Still needed: {[...missing, ...regionalMissing.map((r) => r.label)].join(', ')}.
    </p>
  {/if}
  {#if issue}<CodeNote {issue} />{:else if create.error}<InlineError
      message={edgeErrorMessage(create.error)}
    />{/if}
  <div class="flex flex-wrap gap-2">
    <Button
      class="h-11 sm:h-8"
      disabled={create.isPending || load.isPending}
      onclick={() => {
        tried = true;
        if (missing.length === 0 && regionalMissing.length === 0) create.mutate();
      }}
    >
      {create.isPending ? 'Adding the location' : 'Add location'}
    </Button>
    {#if onCancel}
      <Button variant="outline" class="h-11 sm:h-8" onclick={onCancel}>Cancel</Button>
    {/if}
  </div>
</div>
