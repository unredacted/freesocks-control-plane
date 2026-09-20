<script lang="ts">
  /**
   * The Rotations tab: every provision / publish / replace run of the origin. A
   * row opens the rotation drawer (`?rotation=`); the running one can be cancelled.
   *
   * Props: origin; onOpenRotation(rotationId)
   */
  import * as Table from '@client/components/ui/table';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import type { RelayAdmin } from '@shared/contracts/edges';
  import { cancelRelayRotation, edgeKeys, relayRotationsQuery } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import { ROTATION_KIND_LABELS, ROTATION_TRIGGER_LABELS } from '../lib/rotation';
  import { durationLabel, relativeTime } from '../lib/time';
  import ActionConfirm from './ActionConfirm.svelte';
  import { relayAction } from './actions.svelte';
  import { rotationDurationMs, rotationOutcomeWords } from './relayLogic';

  interface Props {
    relay: RelayAdmin;
    onOpenRotation: (rotationId: string) => void;
  }
  let { relay, onOpenRotation }: Props = $props();

  const act = relayAction(() => relay.slug);
  const rotationsQ = relayRotationsQuery({
    slug: () => relay.slug,
    id: () => relay.id,
    rotating: () => !!relay.activeRotationId,
  });
  const rotations = $derived(
    [...(rotationsQ.data ?? [])].sort((a, b) => b.startedAt.localeCompare(a.startedAt)),
  );
  let cancelId = $state<string | null>(null);
</script>

<div class="space-y-3">
  <p class="text-sm text-muted-foreground">
    A rotation is one run of the machine that provisions, publishes or replaces an edge. Finished
    runs are kept for 90 days.
  </p>
  {#if rotationsQ.isPending}
    <Skeleton class="h-40 w-full" />
  {:else if rotationsQ.error}
    <AdminListState error={rotationsQ.error} onRetry={() => void rotationsQ.refetch()} />
  {:else if rotations.length === 0}
    <AdminListState
      emptyText="No rotation has run for this relay yet. Provision an edge from the Actions menu to start the first one."
    />
  {:else}
    <div class="overflow-x-auto rounded-lg border">
      <Table.Root>
        <Table.Header>
          <Table.Row>
            <Table.Head>Kind</Table.Head>
            <Table.Head>Started by</Table.Head>
            <Table.Head>Phase</Table.Head>
            <Table.Head>Started</Table.Head>
            <Table.Head>Duration</Table.Head>
            <Table.Head>Outcome</Table.Head>
            <Table.Head><span class="sr-only">Actions</span></Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each rotations as r (r.id)}
            <Table.Row
              class="cursor-pointer"
              tabindex={0}
              onclick={() => onOpenRotation(r.id)}
              onkeydown={(ev: KeyboardEvent) => {
                if (ev.key === 'Enter' && ev.target === ev.currentTarget) onOpenRotation(r.id);
              }}
            >
              <Table.Cell>
                {ROTATION_KIND_LABELS[r.kind]}
                {#if r.burn}<Badge variant="warning">Burn</Badge>{/if}
                {#if r.force}<Badge variant="outline">Forced</Badge>{/if}
              </Table.Cell>
              <Table.Cell>{ROTATION_TRIGGER_LABELS[r.trigger]}</Table.Cell>
              <Table.Cell>
                <StatusBadge kind="phase" value={r.phase} />
                {#if !r.terminal}
                  <span class="ms-1 text-xs text-muted-foreground">{r.progress.percent}%</span>
                {/if}
              </Table.Cell>
              <Table.Cell title={new Date(r.startedAt).toLocaleString()}>
                {relativeTime(r.startedAt)}
              </Table.Cell>
              <Table.Cell>{durationLabel(rotationDurationMs(r))}</Table.Cell>
              <Table.Cell>{rotationOutcomeWords(r)}</Table.Cell>
              <Table.Cell class="text-right">
                {#if r.cancellable}
                  <Button
                    variant="outline"
                    size="sm"
                    onclick={(ev: MouseEvent) => {
                      ev.stopPropagation();
                      cancelId = r.id;
                    }}
                  >
                    Cancel
                  </Button>
                {:else if r.cancelRequested && !r.terminal}
                  <Badge variant="warning">Cancel requested</Badge>
                {/if}
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
</div>

{#if cancelId}
  {@const id = cancelId}
  <ActionConfirm
    open={true}
    title="Cancel the running rotation?"
    body="The run stops at its next safe point. If it already published an edge or switched a panel Host, it rolls that back first, so members end up where they were before it started. A half-built edge is destroyed."
    confirmLabel="Cancel rotation"
    danger
    onClose={() => (cancelId = null)}
    run={() =>
      act.mutateAsync({
        run: () => cancelRelayRotation(relay.id),
        success: 'Cancel requested. The run stops at the next safe point.',
        also: (qc) => void qc.invalidateQueries({ queryKey: edgeKeys.rotation(id) }),
        quiet: true,
      })}
  />
{/if}
