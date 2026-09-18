<script lang="ts">
  /**
   * What FCP sees at the provider for one account: load balancers or fronts,
   * reserved addresses and the sizes on offer. A resource no edge of FCP
   * references is marked foreign.
   *
   * Props:
   *   accountId: string
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as Table from '@client/components/ui/table';
  import {
    edgeKeys,
    providerInventoryQuery,
    refreshProviderInventory,
  } from '../../../../lib/edgesApi';
  import { humanizeCode } from '../../../../lib/edgeCodes';
  import AdminListState from '../../AdminListState.svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { relativeTime } from '../lib/time';
  import { inventoryOwner } from './accountWords';

  interface Props {
    accountId: string;
  }
  let { accountId }: Props = $props();

  const qc = useQueryClient();
  const inventory = providerInventoryQuery(() => accountId);
  const refresh = createMutation(() => ({
    mutationFn: () => refreshProviderInventory(accountId),
    onSuccess: (res) => {
      qc.setQueryData(edgeKeys.providerInventory(accountId), res);
      void qc.invalidateQueries({ queryKey: edgeKeys.provider(accountId) });
      toast.success('Inventory refreshed');
    },
    onError: (err: unknown) =>
      toast.error('Could not read the inventory', { description: edgeErrorMessage(err) }),
  }));

  const inv = $derived(inventory.data?.inventory ?? null);
  const foreign = $derived(inv ? inv.loadBalancers.filter((r) => r.unowned === true).length : 0);
  const address = (a: {
    v4?: string | undefined;
    v6?: string | undefined;
    hostname?: string | undefined;
  }) => [a.hostname, a.v4, a.v6].filter((x): x is string => !!x);
</script>

<div class="space-y-4">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <p class="text-sm text-muted-foreground">
      {#if inventory.data?.inventoryAt}
        Read from the provider {relativeTime(inventory.data.inventoryAt)}.
        {#if foreign > 0}
          {foreign} resource{foreign === 1 ? ' is' : 's are'} not an edge of FCP. FCP never changes or
          deletes those.
        {/if}
      {:else}
        Not read yet.
      {/if}
    </p>
    <Button
      size="sm"
      variant="outline"
      disabled={refresh.isPending}
      onclick={() => refresh.mutate()}
    >
      {refresh.isPending ? 'Reading the provider' : 'Refresh'}
    </Button>
  </div>

  {#if inventory.isPending}
    <Skeleton class="h-24 w-full" />
  {:else if inventory.isError}
    <AdminListState error={inventory.error} onRetry={() => void inventory.refetch()} />
  {:else if !inv}
    <AdminListState
      emptyText="FCP has not read this account's inventory yet. Use Refresh to list what exists at the provider."
    />
  {:else}
    <section class="space-y-2">
      <h3 class="text-sm font-semibold">Load balancers and fronts</h3>
      {#if inv.loadBalancers.length === 0}
        <AdminListState
          emptyText="The provider lists no resource in this account. Provision an edge from a relay page to create the first one."
        />
      {:else}
        <Table.Root>
          <Table.Header>
            <Table.Row>
              <Table.Head>Name</Table.Head>
              <Table.Head>Owner</Table.Head>
              <Table.Head>Provider status</Table.Head>
              <Table.Head>Addresses</Table.Head>
              <Table.Head>Created</Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {#each inv.loadBalancers as r (r.id)}
              <Table.Row>
                <Table.Cell>
                  <div class="font-medium">{r.name}</div>
                  <div class="flex items-center gap-1 font-mono text-xs text-muted-foreground">
                    {r.id}
                    <CopyButton value={r.id} label="Copy the resource id" />
                  </div>
                </Table.Cell>
                <Table.Cell>
                  {#if inventoryOwner(r) === 'fcp'}
                    <Badge variant="success">FCP edge</Badge>
                  {:else}
                    <Badge variant="warning">Foreign</Badge>
                    <div class="mt-0.5 text-xs text-muted-foreground">
                      No edge of FCP references it
                    </div>
                  {/if}
                </Table.Cell>
                <Table.Cell>{r.status ? humanizeCode(r.status) : 'Not reported'}</Table.Cell>
                <Table.Cell class="font-mono text-xs">
                  {#each address(r.addresses) as a (a)}<div>{a}</div>{:else}
                    <span class="font-sans text-muted-foreground">None yet</span>
                  {/each}
                  {#if r.content}
                    <div class="font-sans text-muted-foreground">dials {r.content}</div>
                  {/if}
                  {#if r.hostnames && r.hostnames.length > 1}
                    <div class="font-sans text-muted-foreground">
                      serves {r.hostnames.length} hostnames
                    </div>
                  {/if}
                </Table.Cell>
                <Table.Cell class="whitespace-nowrap text-muted-foreground" title={r.createdAt}>
                  {r.createdAt ? relativeTime(r.createdAt) : 'Unknown'}
                </Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      {/if}
    </section>

    {#if inv.ips.length > 0}
      <section class="space-y-2">
        <h3 class="text-sm font-semibold">Reserved addresses</h3>
        <Table.Root>
          <Table.Header>
            <Table.Row>
              <Table.Head>Address</Table.Head>
              <Table.Head>Attached to</Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {#each inv.ips as ip (ip.id)}
              {@const owner = inv.loadBalancers.find((r) => r.id === ip.attachedTo)}
              <Table.Row>
                <Table.Cell class="font-mono text-xs">{ip.address}</Table.Cell>
                <Table.Cell>
                  {#if owner}{owner.name}{:else if ip.attachedTo}
                    <span class="font-mono text-xs">{ip.attachedTo}</span>
                  {:else}
                    <span class="text-amber-700 dark:text-amber-300"
                      >Nothing. A detached address may still be billed.</span
                    >
                  {/if}
                </Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      </section>
    {/if}

    {#if inv.flavors.length > 0}
      <section class="space-y-2">
        <h3 class="text-sm font-semibold">Sizes on offer</h3>
        <div class="flex flex-wrap gap-1.5">
          {#each inv.flavors as f (f.id)}<Badge variant="outline">{f.label}</Badge>{/each}
        </div>
      </section>
    {/if}
  {/if}
</div>
