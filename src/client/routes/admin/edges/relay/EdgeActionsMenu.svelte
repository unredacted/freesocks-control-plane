<script lang="ts">
  /**
   * Every action on ONE edge, as a dropdown: used by the edges table rows
   * (`variant="row"`, an icon trigger) and by the edge drawer footer
   * (`variant="drawer"`, an "Actions" button). Dialogs are mounted only while open.
   *
   * Props:
   *   origin: RelayAdmin
   *   edge: EdgeAdmin
   *   variant?: 'row' | 'drawer'
   *   onOpenEdge?: (edgeId) => void            "Live" opens the drawer (row variant)
   *   onRotationStarted: (rotationId) => void
   */
  import Ellipsis from '@lucide/svelte/icons/ellipsis';
  import type { EdgeAdmin, RelayAdmin } from '@shared/contracts/edges';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import {
    deleteEdge,
    invalidateEdge,
    invalidateProbes,
    probeEdge,
    qualifyEdge,
    resolveEdgeOperator,
    retryDestroyEdge,
    unpublishEdge,
    type ResolveOperatorAction,
  } from '@client/lib/edgesApi';
  import { codeLabel } from '@client/lib/edgeCodes';
  import KeyValue from '../components/KeyValue.svelte';
  import PublishDialog from '../forms/PublishDialog.svelte';
  import ActionConfirm from './ActionConfirm.svelte';
  import ReplaceDialog from './ReplaceDialog.svelte';
  import { relayAction } from './actions.svelte';
  import { edgeAddress, operatorFactsRows } from './relayLogic';

  interface Props {
    relay: RelayAdmin;
    edge: EdgeAdmin;
    variant?: 'row' | 'drawer';
    onOpenEdge?: (edgeId: string) => void;
    onRotationStarted: (rotationId: string) => void;
  }
  let { relay, edge, variant = 'row', onOpenEdge, onRotationStarted }: Props = $props();

  const act = relayAction(() => relay.slug);

  const published = $derived(edge.publication === 'published');
  const canPublish = $derived(edge.publication === 'unpublished' && edge.status === 'active');
  const needsOperator = $derived(edge.status === 'needs_operator');
  const canRetryDestroy = $derived(
    !published && ['destroying', 'failed', 'cancelled'].includes(edge.status),
  );
  const gone = $derived(edge.status === 'destroyed');
  const name = $derived(edgeAddress(edge) || edge.name);

  let publishOpen = $state(false);
  let unpublishOpen = $state(false);
  let keepActive = $state(true);
  let deleteOpen = $state(false);
  let replaceKind = $state<'rotate' | 'burn' | null>(null);
  let resolveAction = $state<ResolveOperatorAction | null>(null);

  const RESOLVE_COPY: Record<
    ResolveOperatorAction,
    { title: string; body: string; confirm: string; danger: boolean; done: string }
  > = {
    destroy: {
      title: 'Destroy this edge at the provider?',
      body: 'FCP trusts its record of what it created and walks the destroy path again, from the start. Choose this when the resources below still exist and should go.',
      confirm: 'Destroy',
      danger: true,
      done: 'Destroy restarted.',
    },
    reactivate: {
      title: 'Put this edge back into service?',
      body: 'Choose this when you checked the provider and the resource is fine. The edge becomes an unpublished standby again. Nothing is called at the provider.',
      confirm: 'Reactivate',
      danger: false,
      done: 'Edge reactivated as a standby.',
    },
    forget: {
      title: 'Forget this edge without calling the provider?',
      body: 'Choose this only after you removed the resources below at the provider by hand. FCP marks the edge destroyed and makes no call. Anything still there keeps running, and billing, without FCP knowing about it.',
      confirm: 'Forget',
      danger: true,
      done: 'Edge forgotten.',
    },
  };

  function qualify(): void {
    act.mutate({
      run: () => qualifyEdge(edge.id),
      success: 'The front passed the end-to-end check.',
      also: (qc) => invalidateEdge(qc, edge.id),
    });
  }
  function probe(): void {
    act.mutate({
      run: () => probeEdge(edge.id),
      success: (res: { runIds: string[] }) =>
        res.runIds.length > 0
          ? `${res.runIds.length} probe run(s) requested. Results arrive within a minute or two.`
          : 'No probe was started. Check that a probe source is on and the hourly budget is not used up.',
      also: invalidateProbes,
    });
  }
  function retryDestroy(): void {
    act.mutate({
      run: () => retryDestroyEdge(edge.id),
      success: 'Destroy will be tried again.',
      also: (qc) => invalidateEdge(qc, edge.id),
    });
  }
</script>

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<span onclick={(e) => e.stopPropagation()}>
  <DropdownMenu.Root>
    <DropdownMenu.Trigger>
      {#snippet child({ props })}
        {#if variant === 'row'}
          <Button {...props} variant="ghost" size="icon" aria-label={`Actions for edge ${name}`}>
            <Ellipsis />
          </Button>
        {:else}
          <Button {...props} variant="outline" size="sm">Actions</Button>
        {/if}
      {/snippet}
    </DropdownMenu.Trigger>
    <DropdownMenu.Content align="end" class="w-56">
      {#if canPublish}
        <DropdownMenu.Item onSelect={() => (publishOpen = true)}>Publish</DropdownMenu.Item>
      {/if}
      {#if published}
        <DropdownMenu.Item onSelect={() => (replaceKind = 'rotate')}>
          Rotate (replace it)
        </DropdownMenu.Item>
        <DropdownMenu.Item onSelect={() => (replaceKind = 'burn')}>
          Burn (replace, short drain)
        </DropdownMenu.Item>
        <DropdownMenu.Item
          onSelect={() => {
            keepActive = true;
            unpublishOpen = true;
          }}
        >
          Unpublish
        </DropdownMenu.Item>
      {/if}
      {#if edge.layer === 'l7' && !gone}
        <DropdownMenu.Item onSelect={qualify} disabled={act.isPending}>
          Qualify now
        </DropdownMenu.Item>
      {/if}
      {#if variant === 'row' && onOpenEdge}
        <DropdownMenu.Item onSelect={() => onOpenEdge?.(edge.id)}>
          Live view and details
        </DropdownMenu.Item>
      {/if}
      {#if !gone}
        <DropdownMenu.Item onSelect={probe} disabled={act.isPending}>Probe now</DropdownMenu.Item>
      {/if}
      {#if canRetryDestroy}
        <DropdownMenu.Item onSelect={retryDestroy} disabled={act.isPending}>
          Retry destroy
        </DropdownMenu.Item>
      {/if}
      {#if needsOperator}
        <DropdownMenu.Separator />
        <DropdownMenu.Label>Resolve "needs operator"</DropdownMenu.Label>
        <DropdownMenu.Item onSelect={() => (resolveAction = 'destroy')}>
          Destroy at the provider
        </DropdownMenu.Item>
        <DropdownMenu.Item onSelect={() => (resolveAction = 'reactivate')}>
          Reactivate
        </DropdownMenu.Item>
        <DropdownMenu.Item variant="destructive" onSelect={() => (resolveAction = 'forget')}>
          Forget
        </DropdownMenu.Item>
      {/if}
      {#if !gone}
        <DropdownMenu.Separator />
        <DropdownMenu.Item
          variant="destructive"
          disabled={published}
          onSelect={() => (deleteOpen = true)}
        >
          {published ? 'Delete (unpublish first)' : 'Delete'}
        </DropdownMenu.Item>
      {/if}
    </DropdownMenu.Content>
  </DropdownMenu.Root>

  {#if publishOpen}
    <PublishDialog
      bind:open={publishOpen}
      relayId={relay.id}
      relaySlug={relay.slug}
      edgeId={edge.id}
      onStarted={onRotationStarted}
    />
  {/if}

  {#if replaceKind}
    <ReplaceDialog
      open={true}
      kind={replaceKind}
      {relay}
      {edge}
      onClose={() => (replaceKind = null)}
      onStarted={onRotationStarted}
    />
  {/if}

  {#if unpublishOpen}
    <ActionConfirm
      bind:open={unpublishOpen}
      title={`Unpublish ${name}?`}
      body="New subscriptions stop selecting this edge right away. Members who already hold it keep working until their client refreshes. If it is the last published edge of the relay, members on this origin go dark until another edge is published."
      confirmLabel="Unpublish"
      danger
      run={() =>
        act.mutateAsync({
          run: () => unpublishEdge(edge.id, keepActive),
          success: keepActive
            ? 'Unpublished. The edge is a standby now.'
            : 'Unpublished. Draining.',
          also: (qc) => invalidateEdge(qc, edge.id),
          quiet: true,
        })}
    >
      <div class="flex items-start gap-2">
        <Checkbox id={`keep-${edge.id}`} bind:checked={keepActive} class="mt-0.5" />
        <div>
          <Label for={`keep-${edge.id}`}>Keep it as a standby</Label>
          <p class="text-xs text-muted-foreground">
            On: the edge stays provisioned and can be published again at once. Off: it drains for
            the origin's drain time and is then destroyed at the provider.
          </p>
        </div>
      </div>
    </ActionConfirm>
  {/if}

  {#if resolveAction}
    {@const copy = RESOLVE_COPY[resolveAction]}
    {@const action = resolveAction}
    <ActionConfirm
      open={true}
      title={copy.title}
      body={copy.body}
      confirmLabel={copy.confirm}
      danger={copy.danger}
      onClose={() => (resolveAction = null)}
      run={() =>
        act.mutateAsync({
          run: () => resolveEdgeOperator(edge.id, action),
          success: copy.done,
          also: (qc) => invalidateEdge(qc, edge.id),
          quiet: true,
        })}
    >
      <KeyValue
        title="What FCP saw"
        description={edge.failure?.code
          ? `FCP stopped because: ${codeLabel(edge.failure.code)}.`
          : 'FCP could not tell whether its last call took effect, so it stopped instead of guessing.'}
        rows={operatorFactsRows(edge)}
        columns={1}
      />
    </ActionConfirm>
  {/if}

  {#if deleteOpen}
    <ActionConfirm
      bind:open={deleteOpen}
      title={`Delete edge ${name}?`}
      body={edge.managed
        ? 'FCP destroys the provider resources of this edge and removes it from the relay. This cannot be undone.'
        : 'FCP only observes this edge, so nothing is destroyed at the provider. The edge is removed from the relay.'}
      typed={name}
      confirmLabel="Delete edge"
      danger
      run={() =>
        act.mutateAsync({
          run: () => deleteEdge(edge.id),
          success: 'Edge deleted.',
          also: (qc) => invalidateEdge(qc, edge.id),
          quiet: true,
        })}
    />
  {/if}
</span>
