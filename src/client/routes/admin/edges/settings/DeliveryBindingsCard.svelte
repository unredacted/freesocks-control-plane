<script lang="ts">
  /**
   * Edge-required places (delivery bindings). A binding outlives its origin on
   * purpose: deleting an origin with "keep dark" leaves members on that node
   * answered "temporarily unavailable" until another origin claims the node or
   * an operator releases the binding HERE, which restores direct delivery.
   * Only a binding whose origin is gone can be released.
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as Table from '@client/components/ui/table';
  import {
    deliveryBindingsQuery,
    edgeKeys,
    invalidateOverview,
    releaseDeliveryBinding,
  } from '@client/lib/edgesApi';
  import Link from '@client/components/Link.svelte';
  import AdminListState from '../../AdminListState.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import { assertEdgeOk } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';

  const qc = useQueryClient();
  const bindings = deliveryBindingsQuery();

  let target = $state<{ id: string; place: string } | null>(null);
  let open = $state(false);

  const placeOf = (b: { nodeName: string | null; relaySlug: string }): string =>
    b.nodeName ? `node ${b.nodeName}` : `the whole backend server of ${b.relaySlug}`;

  async function release(): Promise<void> {
    if (!target) return;
    assertEdgeOk(await releaseDeliveryBinding(target.id));
    void qc.invalidateQueries({ queryKey: edgeKeys.deliveryBindings });
    invalidateOverview(qc);
    toast.success('Direct delivery is restored for that place.');
    target = null;
  }
</script>

<section
  id="settings-delivery"
  class="bg-card ring-foreground/15 scroll-mt-20 rounded-xl ring-1"
  aria-labelledby="settings-delivery-title"
>
  <header class="px-4 py-3">
    <h2 id="settings-delivery-title" class="font-medium">Edge-required places</h2>
    <p class="text-muted-foreground mt-0.5 text-sm">
      Members on these places receive edge addresses or nothing, never the origin address. A place
      stays listed after its origin is deleted with "keep dark", until you release it here.
    </p>
  </header>
  <div class="border-t px-4 py-4">
    {#if bindings.isPending}
      <Skeleton class="h-16" />
    {:else if bindings.isError}
      <AdminListState error={bindings.error} onRetry={() => bindings.refetch()} />
    {:else if (bindings.data?.bindings ?? []).length === 0}
      <p class="text-muted-foreground text-sm">
        No place is edge-required yet. Registering an origin makes its node one.
      </p>
    {:else}
      <Table.Root>
        <Table.Header>
          <Table.Row>
            <Table.Head>Place</Table.Head>
            <Table.Head>Origin</Table.Head>
            <Table.Head>State</Table.Head>
            <Table.Head>Changed</Table.Head>
            <Table.Head class="text-right">Action</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each bindings.data?.bindings ?? [] as b (b.id)}
            <Table.Row>
              <Table.Cell>{b.nodeName ? `Node ${b.nodeName}` : 'Whole backend server'}</Table.Cell>
              <Table.Cell>
                {#if b.relayPresent}
                  <Link href={edgesPaths.relay(b.relaySlug)} class="text-primary hover:underline">
                    {b.relaySlug}
                  </Link>
                {:else}
                  <span class="text-muted-foreground">{b.relaySlug} (deleted)</span>
                {/if}
              </Table.Cell>
              <Table.Cell>
                {#if b.state === 'released'}
                  <StatusBadge kind="readiness" value="released" label="Released" tone="neutral" />
                {:else if b.relayPresent}
                  <StatusBadge kind="readiness" value="active" label="In force" tone="success" />
                {:else}
                  <StatusBadge
                    kind="readiness"
                    value="dark"
                    label="Members unavailable"
                    tone="danger"
                  />
                {/if}
              </Table.Cell>
              <Table.Cell class="text-muted-foreground">{relativeTime(b.updatedAt)}</Table.Cell>
              <Table.Cell class="text-right">
                {#if b.state === 'active' && !b.relayPresent}
                  <Button
                    size="sm"
                    variant="outline"
                    onclick={() => {
                      target = { id: b.id, place: placeOf(b) };
                      open = true;
                    }}
                  >
                    Release
                  </Button>
                {:else}
                  <span class="text-muted-foreground text-xs">
                    {b.state === 'released' ? 'Nothing to do' : 'Delete the relay first'}
                  </span>
                {/if}
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    {/if}
  </div>
</section>

<ConfirmDialog
  bind:open
  title="Restore direct delivery?"
  body={target
    ? `Members on ${target.place} will receive the origin's own addresses again, because no edge fronts it any more. Do this only when the origin address may be handed out.`
    : ''}
  confirmLabel="Release"
  danger
  onConfirm={release}
  onCancel={() => (target = null)}
/>
