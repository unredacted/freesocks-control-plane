<script lang="ts">
  /**
   * The Listeners tab: a card per listener, the Hosts plan when the operator
   * writes the backend Hosts, and the add / edit dialog. `?listener=<key>` scrolls
   * to (and rings) one card.
   *
   * Props: origin; listeners; edges; hostsPlan; loading; error; onRetry
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import type { z } from 'zod';
  import type {
    EdgeAdmin,
    OriginAdmin,
    RelayHostsPlan,
    RelayListenerAdmin,
  } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import * as Table from '@client/components/ui/table';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import { Label } from '@client/components/ui/label';
  import { invalidateRelay } from '@client/lib/edgesApi';
  import { searchParam, setSearchParams } from '@client/lib/urlState.svelte';
  import AdminListState from '../../AdminListState.svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import AddListenerDialog from '../forms/AddListenerDialog.svelte';
  import ListenerCard from './ListenerCard.svelte';
  import ProvisionDialog from './ProvisionDialog.svelte';

  interface Props {
    relay: OriginAdmin;
    listeners: RelayListenerAdmin[];
    edges: EdgeAdmin[];
    hostsPlan: z.infer<typeof RelayHostsPlan> | null;
    loading: boolean;
    error: unknown;
    onRetry: () => void;
  }
  let { relay, listeners, edges, hostsPlan, loading, error, onRetry }: Props = $props();

  const qc = useQueryClient();
  const listenerParam = searchParam('listener');
  let showRetired = $state(false);
  const retiredCount = $derived(listeners.filter((l) => l.retired).length);
  const shown = $derived(listeners.filter((l) => showRetired || !l.retired));
  const edgeCountOf = (listenerId: string): number =>
    edges.filter((e) => e.listenerId === listenerId && e.status !== 'destroyed').length;

  let dialogOpen = $state(false);
  let editing = $state<RelayListenerAdmin | null>(null);
  function openDialog(existing: RelayListenerAdmin | null): void {
    editing = existing;
    dialogOpen = true;
  }

  let provisionOpen = $state(false);
  let provisionKey = $state<string | null>(null);

  // Scroll the linked card into view once it exists.
  let scrolledTo = '';
  $effect(() => {
    const key = listenerParam.value;
    if (!key || key === scrolledTo || !shown.some((l) => l.listenerKey === key)) return;
    scrolledTo = key;
    queueMicrotask(() =>
      document
        .getElementById(`listener-${key}`)
        ?.scrollIntoView({ block: 'start', behavior: 'smooth' }),
    );
  });
</script>

<div class="space-y-4">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <p class="text-sm text-muted-foreground">
      A listener is one port the origin answers on. Each edge fronts exactly one listener.
    </p>
    <div class="flex flex-wrap items-center gap-3">
      {#if retiredCount > 0}
        <div class="flex items-center gap-2">
          <Switch id="listeners-show-retired" bind:checked={showRetired} />
          <Label for="listeners-show-retired" class="text-sm font-normal">
            Show {retiredCount} retired
          </Label>
        </div>
      {/if}
      <Button disabled={relay.deleting} onclick={() => openDialog(null)}>Add listener</Button>
    </div>
  </div>

  {#if loading}
    <Skeleton class="h-48 w-full" />
  {:else if error}
    <AdminListState {error} {onRetry} />
  {:else if shown.length === 0}
    <AdminListState
      emptyText={relay.origin.kind === 'panel-node'
        ? 'No listener yet. Run the node role so it registers the transports of this node, or use Add listener to describe one by hand.'
        : 'No listener yet. Use Add listener to describe the port this origin answers on.'}
    />
  {:else}
    {#each shown as l (l.id)}
      <ListenerCard
        {relay}
        listener={l}
        edgeCount={edgeCountOf(l.id)}
        highlighted={listenerParam.value === l.listenerKey}
        onEdit={(x) => openDialog(x)}
        onProvision={(key) => {
          provisionKey = key;
          provisionOpen = true;
        }}
      />
    {/each}
  {/if}

  {#if hostsPlan && hostsPlan.mode === 'operator'}
    <Card.Root>
      <Card.Header>
        <Card.Title>Hosts plan</Card.Title>
        <Card.Description>
          You write the backend Hosts of this origin. After every publish or rotation, make the
          Hosts in the backend say exactly this, or members keep dialling the old edge.
        </Card.Description>
      </Card.Header>
      <Card.Content>
        {#if hostsPlan.hosts.length === 0}
          <AdminListState
            emptyText="Nothing to write yet. Publish an edge for a listener and its Host appears here."
          />
        {:else}
          <div class="overflow-x-auto">
            <Table.Root>
              <Table.Header>
                <Table.Row>
                  <Table.Head>Listener</Table.Head>
                  <Table.Head>Remark</Table.Head>
                  <Table.Head>Address</Table.Head>
                  <Table.Head>Server name</Table.Head>
                  <Table.Head>Host header</Table.Head>
                  <Table.Head>Transport</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#each hostsPlan.hosts as h (h.listenerKey)}
                  <Table.Row>
                    <Table.Cell class="font-mono text-xs">{h.listenerKey}</Table.Cell>
                    <Table.Cell class="font-mono text-xs">
                      {h.remark}<CopyButton value={h.remark} label="Copy remark" />
                    </Table.Cell>
                    <Table.Cell class="font-mono text-xs">
                      {h.address}:{h.port}<CopyButton value={h.address} label="Copy address" />
                    </Table.Cell>
                    <Table.Cell class="font-mono text-xs">{h.sni ?? 'none'}</Table.Cell>
                    <Table.Cell class="font-mono text-xs">{h.host ?? 'none'}</Table.Cell>
                    <Table.Cell class="font-mono text-xs">
                      {h.inbound.configProfileInboundUuid}
                    </Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          </div>
        {/if}
      </Card.Content>
    </Card.Root>
  {/if}
</div>

{#if dialogOpen}
  <AddListenerDialog
    bind:open={dialogOpen}
    relayId={relay.id}
    relaySlug={relay.slug}
    originKind={relay.origin.kind}
    existing={editing}
    onSaved={() => {
      invalidateRelay(qc, relay.slug);
      if (editing) setSearchParams({ listener: editing.listenerKey });
    }}
  />
{/if}
<ProvisionDialog
  bind:open={provisionOpen}
  {relay}
  {listeners}
  listenerKey={provisionKey}
  onStarted={(rotationId) => setSearchParams({ rotation: rotationId, edge: null })}
/>
