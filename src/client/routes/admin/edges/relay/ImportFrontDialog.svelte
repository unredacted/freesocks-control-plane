<script lang="ts">
  /**
   * Import an existing front (a load balancer or a CDN hostname that already
   * forwards to this origin) as an edge: the ONE import form (the guided
   * wizard's own copy of it is gone). From a provider account's inventory the
   * edge is managed (the inventory can be refreshed in place; a resource that
   * is already an edge cannot be picked); entered by address it is
   * observe-only (never destroyed). What is missing is said in words on submit.
   *
   * Props: open (bindable); relay; listeners; accounts; listenerKey? (preselect);
   *        onImported(edgeId)
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type {
    EdgeProviderAccountAdmin,
    OriginAdmin,
    RelayListenerAdmin,
  } from '@shared/contracts/edges';
  import * as Dialog from '@client/components/ui/dialog';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import {
    adoptRelayEdge,
    edgeKeys,
    invalidateProviders,
    invalidateRelay,
    providerInventoryQuery,
    refreshProviderInventory,
    type AdoptEdgeBody,
  } from '@client/lib/edgesApi';
  import { codeFix, codeLabel } from '@client/lib/edgeCodes';
  import { addressLine } from '@client/lib/edgeProviderMeta';
  import { protocolLine, providerLabel } from '../lib/format';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { relativeTime } from '../lib/time';
  import { importFrontIssues } from './importFront';

  interface Props {
    open: boolean;
    relay: OriginAdmin;
    listeners: RelayListenerAdmin[];
    accounts: EdgeProviderAccountAdmin[];
    listenerKey?: string | null;
    onImported: (edgeId: string) => void;
  }
  let {
    open = $bindable(false),
    relay,
    listeners,
    accounts,
    listenerKey = null,
    onImported,
  }: Props = $props();

  const qc = useQueryClient();
  const usable = $derived(listeners.filter((l) => !l.retired));

  let listenerId = $state('');
  let source = $state<'account' | 'address'>('account');
  let accountId = $state('');
  let locationChoice = $state('');
  let resourceId = $state('');
  let hostname = $state('');
  let ipv4 = $state('');
  let port = $state('');
  let publish = $state(false);
  let tried = $state(false);

  let seeded = false;
  $effect(() => {
    if (open && !seeded) {
      seeded = true;
      listenerId =
        usable.find((l) => l.listenerKey === listenerKey)?.id ??
        (usable.length === 1 ? usable[0]!.id : '');
      tried = false;
      source = accounts.length > 0 ? 'account' : 'address';
      accountId = '';
      locationChoice = '';
      resourceId = '';
      hostname = '';
      ipv4 = '';
      port = '';
      publish = false;
      save.reset();
    } else if (!open) seeded = false;
  });

  const listener = $derived(usable.find((l) => l.id === listenerId) ?? null);
  const account = $derived(accounts.find((a) => a.id === accountId) ?? null);
  // Where the resource lives: an inventory is per location (its region).
  const locations = $derived(account?.locations ?? []);
  const locationId = $derived(
    locationChoice || locations.find((l) => l.isDefault)?.id || locations[0]?.id || '',
  );
  const location = $derived(locations.find((l) => l.id === locationId) ?? null);
  const inventoryQ = providerInventoryQuery(
    () => (open && source === 'account' && accountId ? accountId : null),
    () => locationId || null,
  );
  const resources = $derived(
    [...(inventoryQ.data?.inventory?.loadBalancers ?? [])].sort(
      (a, b) => Number(b.unowned ?? false) - Number(a.unowned ?? false),
    ),
  );
  const resource = $derived(resources.find((r) => r.id === resourceId) ?? null);
  // Picking a resource fills what it is known by.
  $effect(() => {
    if (resource) {
      hostname = resource.hostnames?.[0] ?? resource.addresses.hostname ?? '';
      ipv4 = resource.addresses.v4 ?? '';
    }
  });

  const portNumber = $derived(port.trim() === '' ? undefined : Number(port));
  const portOk = $derived(
    portNumber === undefined ||
      (Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535),
  );
  // What keeps the import from being sent, in words (shown once Import was pressed).
  const issues = $derived(
    importFrontIssues({
      hasListener: !!listener,
      source,
      accountId,
      resourceId,
      hostname,
      ipv4,
      port,
    }),
  );
  const valid = $derived(issues.length === 0);

  const refresh = createMutation(() => ({
    mutationFn: () => refreshProviderInventory(accountId, locationId || null),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: edgeKeys.providerInventory(accountId) });
      toast.success('Inventory refreshed');
    },
    onError: (err: unknown) =>
      toast.error('Could not refresh the inventory', { description: edgeErrorMessage(err) }),
  }));

  const save = createMutation(() => ({
    mutationFn: () => {
      const body: AdoptEdgeBody = { listenerId, ...(publish ? { publish: true } : {}) };
      if (source === 'account') {
        body.accountId = accountId;
        if (locationId) body.locationId = locationId;
        body.resourceId = resourceId;
      }
      if (hostname.trim()) body.hostname = hostname.trim().toLowerCase();
      if (ipv4.trim()) body.ipv4 = ipv4.trim();
      if (portNumber !== undefined) body.port = portNumber;
      return adoptRelayEdge(relay.id, body);
    },
    onSuccess: (res) => {
      invalidateRelay(qc, relay.slug);
      invalidateProviders(qc);
      if (res.code) {
        const fix = codeFix(res.code);
        toast.warning(
          `Imported, but not published: ${codeLabel(res.code)}.${fix ? ` ${fix}` : ''}`,
        );
      } else {
        toast.success(
          res.poolIndex !== null
            ? `Imported and published at position ${res.poolIndex + 1}.`
            : 'Imported as an unpublished edge.',
        );
      }
      open = false;
      onImported(res.edgeId);
    },
  }));
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-xl`}>
    <Dialog.Header>
      <Dialog.Title>Import an existing front</Dialog.Title>
      <Dialog.Description>
        Use this for a load balancer or CDN hostname that already forwards to this origin. Nothing
        is created and no budget is spent.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-4"
      novalidate
      onsubmit={(e) => {
        e.preventDefault();
        tried = true;
        if (valid) save.mutate();
      }}
    >
      <div class="space-y-1.5">
        <Label>Listener it forwards to</Label>
        <Select.Root type="single" value={listenerId} onValueChange={(v) => (listenerId = v)}>
          <Select.Trigger class="w-full">
            {listener ? `${listener.listenerKey} (${protocolLine(listener)})` : 'Choose a listener'}
          </Select.Trigger>
          <Select.Content>
            {#each usable as l (l.id)}
              <Select.Item value={l.id}>{l.listenerKey} ({protocolLine(l)})</Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
        {#if usable.length === 0}
          <p class="text-xs text-muted-foreground">
            This origin has no listener yet. Add one on the Listeners tab first.
          </p>
        {/if}
      </div>

      <fieldset class="space-y-2">
        <legend class="text-sm font-medium">Where is it?</legend>
        <label
          class="flex cursor-pointer items-start gap-2 rounded-md border p-3 has-[:checked]:border-primary"
        >
          <input
            type="radio"
            name="import-source"
            class="mt-1 accent-primary"
            checked={source === 'account'}
            disabled={accounts.length === 0}
            onchange={() => (source = 'account')}
          />
          <span>
            <span class="block text-sm font-medium">In a provider account FCP knows</span>
            <span class="block text-xs text-muted-foreground">
              FCP checks that the resource really dials this origin, then manages it like an edge it
              created, including destroying it when it is retired.
              {accounts.length === 0 ? 'No provider account exists yet.' : ''}
            </span>
          </span>
        </label>
        <label
          class="flex cursor-pointer items-start gap-2 rounded-md border p-3 has-[:checked]:border-primary"
        >
          <input
            type="radio"
            name="import-source"
            class="mt-1 accent-primary"
            checked={source === 'address'}
            onchange={() => {
              source = 'address';
              resourceId = '';
            }}
          />
          <span>
            <span class="block text-sm font-medium">Somewhere else, by address</span>
            <span class="block text-xs text-muted-foreground">
              FCP only observes it: it is published and probed, but never changed or destroyed.
            </span>
          </span>
        </label>
      </fieldset>

      {#if source === 'account'}
        <div class="grid gap-4 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label>Provider account</Label>
            <Select.Root
              type="single"
              value={accountId}
              onValueChange={(v) => {
                accountId = v;
                locationChoice = '';
                resourceId = '';
              }}
            >
              <Select.Trigger class="w-full">
                {account
                  ? `${account.name} (${providerLabel(account.provider)})`
                  : 'Choose an account'}
              </Select.Trigger>
              <Select.Content>
                {#each accounts as a (a.id)}
                  <Select.Item value={a.id}>{a.name} ({providerLabel(a.provider)})</Select.Item>
                {/each}
              </Select.Content>
            </Select.Root>
          </div>
          {#if locations.length > 1}
            <div class="space-y-1.5">
              <Label>Location</Label>
              <Select.Root
                type="single"
                value={locationId}
                onValueChange={(v) => {
                  locationChoice = v;
                  resourceId = '';
                }}
              >
                <Select.Trigger class="w-full"
                  >{location?.label ?? 'Choose a location'}</Select.Trigger
                >
                <Select.Content>
                  {#each locations as l (l.id)}
                    <Select.Item value={l.id}>{l.label}</Select.Item>
                  {/each}
                </Select.Content>
              </Select.Root>
              <p class="text-xs text-muted-foreground">
                Where the resource lives: FCP acts on it there, including when it destroys it.
              </p>
            </div>
          {/if}
          <div class="space-y-1.5">
            <div class="flex items-end justify-between gap-2">
              <Label>Resource</Label>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                class="min-h-11 sm:min-h-0"
                disabled={!accountId || refresh.isPending}
                onclick={() => refresh.mutate()}
              >
                {refresh.isPending ? 'Refreshing' : 'Refresh'}
              </Button>
            </div>
            <Select.Root
              type="single"
              value={resourceId}
              onValueChange={(v) => (resourceId = v)}
              disabled={!accountId || resources.length === 0}
            >
              <Select.Trigger class="w-full">
                {resource
                  ? resource.name
                  : !accountId
                    ? 'Choose an account first'
                    : inventoryQ.isPending
                      ? 'Loading the inventory…'
                      : resources.length === 0
                        ? 'Nothing in the inventory'
                        : 'Choose a resource'}
              </Select.Trigger>
              <Select.Content>
                {#each resources as r (r.id)}
                  <Select.Item value={r.id} disabled={r.unowned === false}>
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
            {#if accountId && !inventoryQ.isPending && resources.length === 0}
              <p class="text-xs text-muted-foreground">
                The last inventory of this account is empty. Refresh it to read the account again.
              </p>
            {:else if inventoryQ.data?.inventoryAt}
              <p class="text-xs text-muted-foreground">
                Listed {relativeTime(inventoryQ.data.inventoryAt)}.
              </p>
            {/if}
          </div>
        </div>
      {/if}

      <div class="grid gap-4 sm:grid-cols-3">
        <div class="space-y-1.5 sm:col-span-2">
          <Label for="import-hostname">Hostname (an L7 front)</Label>
          <Input
            id="import-hostname"
            bind:value={hostname}
            class="font-mono"
            placeholder="front.example"
            autocomplete="off"
          />
        </div>
        <div class="space-y-1.5">
          <Label for="import-port">Port</Label>
          <Input
            id="import-port"
            bind:value={port}
            inputmode="numeric"
            class="font-mono"
            placeholder={listener ? String(listener.originPort) : '443'}
            aria-invalid={!portOk}
          />
        </div>
        <div class="space-y-1.5 sm:col-span-2">
          <Label for="import-ipv4">IPv4 address (an L4 load balancer)</Label>
          <Input
            id="import-ipv4"
            bind:value={ipv4}
            class="font-mono"
            placeholder="198.51.100.10"
            autocomplete="off"
          />
        </div>
      </div>
      <p class="text-xs text-muted-foreground">
        Give the hostname for a CDN front, or the IPv4 address for a load balancer. Leave the port
        empty to use the listener's own port.
      </p>

      <div class="flex items-start gap-2">
        <Checkbox id="import-publish" bind:checked={publish} class="mt-0.5" />
        <div>
          <Label for="import-publish">Publish it right away</Label>
          <p class="text-xs text-muted-foreground">
            An L7 front is only published once it passed the end-to-end check. If it has not, it is
            imported unpublished and you can qualify and publish it from the table.
          </p>
        </div>
      </div>

      {#if tried && issues.length > 0}
        <ul class="text-destructive list-disc space-y-0.5 ps-5 text-sm" role="alert">
          {#each issues as i (i)}<li>{i}</li>{/each}
        </ul>
      {/if}
      {#if save.error}
        <InlineError message={edgeErrorMessage(save.error)} />
      {/if}
      <Dialog.Footer class={STICKY_FOOTER}>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? 'Importing…' : 'Import'}
        </Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
