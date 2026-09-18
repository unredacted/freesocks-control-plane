<script lang="ts">
  /**
   * Step 5, first edge: provision a test edge (the bootstrap path that accepts a
   * tested, not yet qualified account) or import a front that already exists.
   *
   * Props: StepBodyProps + onRotation(rotationId)
   */
  import { Button, buttonVariants } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import TestProvisionDialog from '../forms/TestProvisionDialog.svelte';
  import { edgesPaths } from '../lib/routes';
  import AdoptEdgeForm from './AdoptEdgeForm.svelte';
  import StepIssues from './StepIssues.svelte';
  import { factBool, factNumber, type StepBodyProps } from './types';

  interface Props extends StepBodyProps {
    onRotation: (rotationId: string) => void;
  }
  let { step, status, relay, linkCtx, onRotation }: Props = $props();

  let provisionOpen = $state(false);
  let adopting = $state(false);
  const edges = $derived(factNumber(step.facts, 'edges') ?? 0);
  const rotating = $derived(factBool(step.facts, 'rotating') === true);
</script>

<div class="space-y-4">
  <StepIssues {step} ctx={linkCtx} hide={['no_relay']} />

  {#if !relay}
    <p class="text-muted-foreground text-sm">
      Create the relay first (step 4). An edge always belongs to a listener of a relay.
    </p>
  {:else}
    {#if edges > 0}
      <p class="text-sm">
        This relay has {edges} active {edges === 1 ? 'edge' : 'edges'}.
        <Link
          class="underline underline-offset-2"
          href={edgesPaths.relay(relay.slug, { tab: 'edges' })}
        >
          See them on the relay page
        </Link>.
      </p>
    {/if}
    {#if rotating && relay.activeRotationId}
      <div class="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-sm">
        <span>An operation is running on this relay.</span>
        <Button size="sm" variant="outline" onclick={() => onRotation(relay.activeRotationId!)}>
          Watch it
        </Button>
      </div>
    {/if}

    <div class="grid gap-3 sm:grid-cols-2">
      <div class="space-y-2 rounded-lg border p-3">
        <h4 class="text-sm font-semibold">Provision a test edge</h4>
        <p class="text-muted-foreground text-xs">
          Creates one real resource from a tested account and leaves it unpublished. This is how a
          new account gets its first edge, since ordinary provisioning only uses qualified accounts.
        </p>
        <Button disabled={rotating} onclick={() => (provisionOpen = true)}>
          Provision a test edge
        </Button>
      </div>
      <div class="space-y-2 rounded-lg border p-3">
        <h4 class="text-sm font-semibold">Import an existing front</h4>
        <p class="text-muted-foreground text-xs">
          You already run a load balancer or a CDN front for this origin. Record it as an edge
          instead of creating a new one.
        </p>
        <Button variant="outline" disabled={adopting} onclick={() => (adopting = true)}>
          Import an existing front
        </Button>
      </div>
    </div>

    {#if adopting}
      <AdoptEdgeForm
        relayId={relay.id}
        relaySlug={relay.slug}
        listenerKey={status.context.listenerKey}
        onAdopted={() => (adopting = false)}
        onCancel={() => (adopting = false)}
      />
    {/if}

    <Link
      href={edgesPaths.relay(relay.slug, { tab: 'rotations' })}
      class={buttonVariants({ size: 'sm', variant: 'ghost' })}
    >
      Earlier operations on this relay
    </Link>

    <TestProvisionDialog
      bind:open={provisionOpen}
      relayId={relay.id}
      relaySlug={relay.slug}
      accountId={status.context.accountId}
      listenerKey={status.context.listenerKey}
      onStarted={onRotation}
    />
  {/if}
</div>
