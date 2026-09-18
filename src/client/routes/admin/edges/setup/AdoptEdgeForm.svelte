<script lang="ts">
  /**
   * Import a front that already exists as an edge of this relay: a resource
   * picked from an account's inventory, or a bare address FCP does not manage.
   * The import is never published from here (publishing is its own step).
   *
   * Props:
   *   relayId: string
   *   relaySlug: string
   *   listenerKey?: string | null        preselect
   *   onAdopted: (edgeId: string) => void
   *   onCancel: () => void
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import { cn } from '@client/lib/utils';
  import {
    adoptRelayEdge,
    edgeKeys,
    invalidateRelay,
    providerInventoryQuery,
    providersQuery,
    refreshProviderInventory,
    relayListenersQuery,
    type AdoptEdgeBody,
  } from '@client/lib/edgesApi';
  import { addressLine } from '@client/lib/edgeProviderMeta';
  import AdminListState from '../../AdminListState.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import { protocolLine, providerLabel } from '../lib/format';
  import { relativeTime } from '../lib/time';
  import { normalizeHostname } from '../lib/tags';
  import { addressIssue } from '../forms/origin';

  interface Props {
    relayId: string;
    relaySlug: string;
    listenerKey?: string | null;
    onAdopted: (edgeId: string) => void;
    onCancel: () => void;
  }
  let { relayId, relaySlug, listenerKey = null, onAdopted, onCancel }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const providers = providersQuery();
  const listeners = relayListenersQuery({ slug: () => relaySlug, id: () => relayId });

  let mode = $state<'inventory' | 'address'>('inventory');
  let listenerId = $state('');
  let accountId = $state('');
  let resourceId = $state('');
  let address = $state('');
  let port = $state('443');
  let tried = $state(false);

  const usable = $derived((listeners.data?.listeners ?? []).filter((l) => !l.retired));
  const listener = $derived(usable.find((l) => l.id === listenerId) ?? null);
  $effect(() => {
    if (listenerId || usable.length === 0) return;
    const preset = usable.find((l) => l.listenerKey === listenerKey);
    if (preset) listenerId = preset.id;
    else if (usable.length === 1) listenerId = usable[0]!.id;
  });

  const accounts = $derived((providers.data?.accounts ?? []).filter((a) => a.enabled));
  const account = $derived(accounts.find((a) => a.id === accountId) ?? null);
  const inventory = providerInventoryQuery(() =>
    mode === 'inventory' && accountId ? accountId : null,
  );
  const resources = $derived(inventory.data?.inventory?.loadBalancers ?? []);
  const resource = $derived(resources.find((r) => r.id === resourceId) ?? null);

  const refresh = createMutation(() => ({
    mutationFn: () => refreshProviderInventory(accountId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: edgeKeys.providerInventory(accountId) });
      toast.success('Inventory refreshed');
    },
    onError: (err: unknown) =>
      toast.error('Could not refresh the inventory', { description: edgeErrorMessage(err) }),
  }));

  const portNumber = $derived.by(() => {
    const n = Number(port.trim());
    return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
  });
  const issues = $derived.by(() => {
    const out: string[] = [];
    if (!listenerId) out.push('Choose the listener this front carries.');
    if (mode === 'inventory') {
      if (!accountId) out.push('Choose the account the resource lives in.');
      else if (!resourceId) out.push('Choose the resource.');
    } else {
      const problem = addressIssue(address);
      if (problem) out.push(problem);
      if (portNumber === null) out.push('The port is a number between 1 and 65535.');
    }
    return out;
  });

  const adopt = createMutation(() => ({
    mutationFn: () => {
      const body: AdoptEdgeBody = { listenerId, publish: false };
      if (mode === 'inventory') {
        body.accountId = accountId;
        body.resourceId = resourceId;
      } else {
        const a = address.trim();
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) body.ipv4 = a;
        else body.hostname = normalizeHostname(a) ?? a;
        if (portNumber !== null) body.port = portNumber;
      }
      return adoptRelayEdge(relayId, body);
    },
    onSuccess: (r) => {
      invalidateRelay(qc, relaySlug);
      toast.success('Front imported as an edge');
      onAdopted(r.edgeId);
    },
  }));
  const refusal = $derived(adopt.error ? edgeErrorIssue(adopt.error) : null);

  const MODES = [
    { id: 'inventory', label: 'From an account' },
    { id: 'address', label: 'By address' },
  ] as const;
</script>

<form
  class="space-y-4 rounded-lg border p-3"
  onsubmit={(e) => {
    e.preventDefault();
    tried = true;
    if (issues.length === 0) adopt.mutate();
  }}
>
  <div>
    <h4 class="text-sm font-semibold">Import an existing front</h4>
    <p class="text-muted-foreground text-xs">
      For a load balancer or CDN front that already forwards to this origin. A resource imported
      from an account is managed like any other edge; a bare address is only tracked, never changed
      or deleted by FCP.
    </p>
  </div>

  <div class="bg-muted inline-flex rounded-lg p-0.5" role="radiogroup" aria-label="How to import">
    {#each MODES as m (m.id)}
      <button
        type="button"
        role="radio"
        aria-checked={mode === m.id}
        class={cn(
          'focus-visible:ring-ring/60 rounded-md px-3 py-1.5 text-sm outline-none focus-visible:ring-2',
          mode === m.id ? 'bg-background shadow-sm' : 'text-muted-foreground hover:text-foreground',
        )}
        onclick={() => (mode = m.id)}
      >
        {m.label}
      </button>
    {/each}
  </div>

  <div class="space-y-1.5">
    <Label for={`${uid}-listener`}>Listener</Label>
    {#if listeners.isError}
      <AdminListState error={listeners.error} onRetry={() => void listeners.refetch()} />
    {:else if !listeners.isPending && usable.length === 0}
      <AdminListState emptyText="This relay has no listener yet. Add one in the previous step." />
    {:else}
      <Select.Root type="single" bind:value={listenerId}>
        <Select.Trigger id={`${uid}-listener`} class="w-full">
          {listener ? `${listener.listenerKey}: ${protocolLine(listener)}` : 'Choose a listener'}
        </Select.Trigger>
        <Select.Content>
          {#each usable as l (l.id)}
            <Select.Item value={l.id} label={l.listenerKey}>
              <span class="font-mono">{l.listenerKey}</span>
              <span class="text-muted-foreground text-xs">{protocolLine(l)}</span>
            </Select.Item>
          {/each}
        </Select.Content>
      </Select.Root>
    {/if}
  </div>

  {#if mode === 'inventory'}
    <div class="grid gap-4 sm:grid-cols-2">
      <div class="space-y-1.5">
        <Label for={`${uid}-account`}>Account</Label>
        <Select.Root
          type="single"
          value={accountId}
          onValueChange={(v: string) => {
            accountId = v;
            resourceId = '';
          }}
        >
          <Select.Trigger id={`${uid}-account`} class="w-full">
            {account ? `${account.name} (${providerLabel(account.provider)})` : 'Choose an account'}
          </Select.Trigger>
          <Select.Content>
            {#each accounts as a (a.id)}
              <Select.Item value={a.id} label={a.name}>
                {a.name}
                <span class="text-muted-foreground text-xs">{providerLabel(a.provider)}</span>
              </Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
      </div>
      <div class="space-y-1.5">
        <div class="flex items-end justify-between">
          <Label for={`${uid}-resource`}>Resource</Label>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={!accountId || refresh.isPending}
            onclick={() => refresh.mutate()}
          >
            {refresh.isPending ? 'Refreshing' : 'Refresh'}
          </Button>
        </div>
        {#if inventory.isError}
          <AdminListState error={inventory.error} onRetry={() => void inventory.refetch()} />
        {:else}
          <Select.Root type="single" bind:value={resourceId} disabled={!accountId}>
            <Select.Trigger id={`${uid}-resource`} class="w-full">
              {resource
                ? `${resource.name} (${addressLine(resource.addresses)})`
                : !accountId
                  ? 'Choose an account first'
                  : resources.length === 0
                    ? 'Nothing listed yet. Refresh.'
                    : 'Choose a resource'}
            </Select.Trigger>
            <Select.Content>
              {#each resources as r (r.id)}
                <Select.Item value={r.id} label={r.name} disabled={r.unowned === false}>
                  {r.name}
                  <span class="text-muted-foreground font-mono text-xs">
                    {addressLine(r.addresses)}
                  </span>
                  {#if r.unowned === false}
                    <span class="text-muted-foreground text-xs">already an edge</span>
                  {/if}
                </Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
          {#if inventory.data?.inventoryAt}
            <p class="text-muted-foreground text-xs">
              Listed {relativeTime(inventory.data.inventoryAt)}.
            </p>
          {/if}
        {/if}
      </div>
    </div>
  {:else}
    <div class="grid gap-4 sm:grid-cols-[1fr_8rem]">
      <div class="space-y-1.5">
        <Label for={`${uid}-address`}>Front address</Label>
        <Input
          id={`${uid}-address`}
          class="font-mono"
          placeholder="203.0.113.20 or front.example"
          bind:value={address}
        />
        <p class="text-muted-foreground text-xs">
          The public IPv4 address of a load balancer, or the hostname of a CDN front.
        </p>
      </div>
      <div class="space-y-1.5">
        <Label for={`${uid}-port`}>Port</Label>
        <Input id={`${uid}-port`} class="font-mono" inputmode="numeric" bind:value={port} />
      </div>
    </div>
  {/if}

  {#if tried && issues.length > 0}
    <ul class="text-destructive list-disc space-y-0.5 ps-5 text-sm" role="alert">
      {#each issues as i (i)}<li>{i}</li>{/each}
    </ul>
  {/if}
  {#if refusal}
    <CodeNote issue={refusal} />
  {:else if adopt.error}
    <InlineError message={edgeErrorMessage(adopt.error)} />
  {/if}

  <div class="flex gap-2">
    <Button type="submit" disabled={adopt.isPending}>
      {adopt.isPending ? 'Importing' : 'Import as an edge'}
    </Button>
    <Button type="button" variant="outline" onclick={onCancel}>Cancel</Button>
  </div>
</form>
