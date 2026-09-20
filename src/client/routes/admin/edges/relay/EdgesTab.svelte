<script lang="ts">
  /**
   * The Edges tab: every edge of the origin in one table, with names joined from
   * the provider accounts and the listeners. A row opens the edge drawer
   * (`?edge=`); the row menu holds every edge action.
   *
   * Props: origin; edges; listeners; accounts; loading; error; onRetry; onOpenEdge; onRotationStarted
   */
  import type {
    EdgeAdmin,
    EdgeProviderAccountAdmin,
    RelayAdmin,
    RelayListenerAdmin,
  } from '@shared/contracts/edges';
  import * as Table from '@client/components/ui/table';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import { Label } from '@client/components/ui/label';
  import { codeLabel } from '@client/lib/edgeCodes';
  import AdminListState from '../../AdminListState.svelte';
  import LayerBadge from '../components/LayerBadge.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import { providerLabel } from '../lib/format';
  import { relativeTime } from '../lib/time';
  import EdgeActionsMenu from './EdgeActionsMenu.svelte';
  import ImportFrontDialog from './ImportFrontDialog.svelte';
  import ProvisionDialog from './ProvisionDialog.svelte';
  import { edgeAddress } from './relayLogic';

  interface Props {
    relay: RelayAdmin;
    edges: EdgeAdmin[];
    listeners: RelayListenerAdmin[];
    accounts: EdgeProviderAccountAdmin[];
    loading: boolean;
    error: unknown;
    onRetry: () => void;
    onOpenEdge: (edgeId: string) => void;
    onRotationStarted: (rotationId: string) => void;
  }
  let {
    relay,
    edges,
    listeners,
    accounts,
    loading,
    error,
    onRetry,
    onOpenEdge,
    onRotationStarted,
  }: Props = $props();

  let showGone = $state(false);
  let importOpen = $state(false);
  let provisionOpen = $state(false);

  const accountName = (e: EdgeAdmin): string => {
    const a = e.accountId ? accounts.find((x) => x.id === e.accountId) : null;
    if (a) return a.name;
    return e.managed ? 'An account that was deleted' : 'Not managed by FCP';
  };
  const listenerKey = (e: EdgeAdmin): string =>
    listeners.find((l) => l.id === e.listenerId)?.listenerKey ?? 'A retired listener';

  const PUBLICATION_ORDER = { published: 0, draining: 1, unpublished: 2 } as const;
  const goneCount = $derived(edges.filter((e) => e.status === 'destroyed').length);
  const rows = $derived(
    edges
      .filter((e) => showGone || e.status !== 'destroyed')
      .sort(
        (a, b) =>
          PUBLICATION_ORDER[a.publication] - PUBLICATION_ORDER[b.publication] ||
          (a.poolIndex ?? 99) - (b.poolIndex ?? 99) ||
          b.createdAt.localeCompare(a.createdAt),
      ),
  );

  function qualification(
    e: EdgeAdmin,
  ): { label: string; tone: 'success' | 'warning' | 'danger' | 'muted'; title: string } | null {
    if (e.layer !== 'l7') return null;
    const q = e.frontQualification;
    if (!q)
      return {
        label: 'Not checked',
        tone: 'muted',
        title: 'No end-to-end check has run for this front yet.',
      };
    if (!q.ok)
      return {
        label: 'Failed',
        tone: 'danger',
        title: `${q.code ? codeLabel(q.code) : 'The check failed'}, ${relativeTime(q.checkedAt)}.`,
      };
    if (!q.current)
      return {
        label: 'Stale',
        tone: 'warning',
        title:
          'The listener or the front changed since the check, or the proof expired. Qualify again.',
      };
    return {
      label: 'Proven',
      tone: 'success',
      title: `Checked ${relativeTime(q.checkedAt)}, expires ${relativeTime(q.expiresAt)}.`,
    };
  }
</script>

<div class="space-y-3">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <p class="text-sm text-muted-foreground">
      Published edges are handed to members. Unpublished ones are standbys, ready for the next
      rotation.
    </p>
    <div class="flex flex-wrap items-center gap-2">
      {#if goneCount > 0}
        <div class="flex items-center gap-2">
          <Switch id="edges-show-gone" bind:checked={showGone} />
          <Label for="edges-show-gone" class="text-sm font-normal">
            Show {goneCount} destroyed
          </Label>
        </div>
      {/if}
      <Button variant="outline" disabled={relay.deleting} onclick={() => (importOpen = true)}>
        Import an existing front
      </Button>
      <Button disabled={relay.deleting} onclick={() => (provisionOpen = true)}>Provision</Button>
    </div>
  </div>

  {#if loading}
    <Skeleton class="h-40 w-full" />
  {:else if error}
    <AdminListState {error} {onRetry} />
  {:else if rows.length === 0}
    <AdminListState
      emptyText={edges.length === 0
        ? 'This relay has no edge yet. Use Provision to create one at a provider, or import a front you already run.'
        : 'Every edge of this relay is destroyed. Use Provision to create a new one.'}
    />
  {:else}
    <div class="overflow-x-auto rounded-lg border">
      <Table.Root>
        <Table.Header>
          <Table.Row>
            <Table.Head>Layer</Table.Head>
            <Table.Head>Address</Table.Head>
            <Table.Head>Account</Table.Head>
            <Table.Head>Listener</Table.Head>
            <Table.Head>State</Table.Head>
            <Table.Head>Position</Table.Head>
            <Table.Head>Front check</Table.Head>
            <Table.Head><span class="sr-only">Actions</span></Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each rows as e (e.id)}
            {@const q = qualification(e)}
            <Table.Row
              class="cursor-pointer"
              tabindex={0}
              onclick={() => onOpenEdge(e.id)}
              onkeydown={(ev: KeyboardEvent) => {
                if (ev.key === 'Enter' && ev.target === ev.currentTarget) onOpenEdge(e.id);
              }}
            >
              <Table.Cell><LayerBadge layer={e.layer} /></Table.Cell>
              <Table.Cell class="font-mono text-xs">
                {edgeAddress(e) || 'No address yet'}
                {#if e.addresses.v6 && e.addresses.v4}
                  <span class="block text-muted-foreground">{e.addresses.v6}</span>
                {/if}
              </Table.Cell>
              <Table.Cell>
                <span class="block">{accountName(e)}</span>
                {#if e.provider}
                  <span class="block text-xs text-muted-foreground"
                    >{providerLabel(e.provider)}</span
                  >
                {/if}
              </Table.Cell>
              <Table.Cell class="font-mono text-xs">{listenerKey(e)}</Table.Cell>
              <Table.Cell>
                <div class="flex flex-wrap gap-1">
                  <StatusBadge kind="status" value={e.status} />
                  <StatusBadge kind="health" value={e.health} />
                  <StatusBadge kind="publication" value={e.publication} />
                </div>
                {#if e.failure?.code}
                  <span class="mt-1 block text-xs text-destructive"
                    >{codeLabel(e.failure.code)}</span
                  >
                {/if}
              </Table.Cell>
              <Table.Cell>{e.poolIndex !== null ? e.poolIndex + 1 : ''}</Table.Cell>
              <Table.Cell>
                {#if q}
                  <Badge variant={q.tone} title={q.title}>{q.label}</Badge>
                {:else}
                  <span
                    class="text-xs text-muted-foreground"
                    title="Only L7 fronts are checked end to end.">Not needed</span
                  >
                {/if}
              </Table.Cell>
              <Table.Cell class="text-right">
                <EdgeActionsMenu {relay} edge={e} {onOpenEdge} {onRotationStarted} />
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
</div>

<ImportFrontDialog bind:open={importOpen} {relay} {listeners} {accounts} onImported={onOpenEdge} />
<ProvisionDialog bind:open={provisionOpen} {relay} {listeners} onStarted={onRotationStarted} />
