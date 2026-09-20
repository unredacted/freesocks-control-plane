<script lang="ts">
  /**
   * Step 7, publish: put the edge in the pool (preflight first), then follow
   * the rotation. With operator-managed Hosts, show the Host to create.
   *
   * Props: StepBodyProps + onRotation(rotationId)
   */
  import { Button, buttonVariants } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import PublishDialog from '../forms/PublishDialog.svelte';
  import { edgesPaths } from '../lib/routes';
  import { shortId } from '../lib/time';
  import HostsPlanCard from './HostsPlanCard.svelte';
  import StepIssues from './StepIssues.svelte';
  import { factNumber, type StepBodyProps } from './types';

  interface Props extends StepBodyProps {
    onRotation: (rotationId: string) => void;
  }
  let { step, status, relay, linkCtx, onRotation }: Props = $props();

  let open = $state(false);
  const published = $derived(factNumber(step.facts, 'published') ?? 0);
  const edgeId = $derived(status.context.edgeId);
</script>

<div class="space-y-4">
  <StepIssues {step} ctx={linkCtx} hide={['no_relay']} />

  {#if !relay}
    <p class="text-muted-foreground text-sm">Create the origin first (step 4).</p>
  {:else}
    {#if published > 0}
      <p class="text-sm">
        {published}
        {published === 1 ? 'edge is' : 'edges are'} published for this relay.
      </p>
    {:else if edgeId}
      <p class="text-sm">
        Publishing points the client-facing Host at edge {shortId(edgeId)} and starts sending members
        to it. The check that runs first changes nothing.
      </p>
      <div class="flex flex-wrap gap-2">
        <Button disabled={relay.activeRotationId !== null} onclick={() => (open = true)}>
          Publish this edge
        </Button>
        {#if relay.activeRotationId}
          <Button variant="outline" onclick={() => onRotation(relay.activeRotationId!)}>
            Watch the running operation
          </Button>
        {/if}
      </div>
    {:else}
      <p class="text-muted-foreground text-sm">
        There is no edge to publish yet. Provision or import one first (step 5).
      </p>
    {/if}

    {#if relay.hostMode === 'operator'}
      <HostsPlanCard relaySlug={relay.slug} />
    {:else if relay.hostMode === 'none'}
      <p class="text-muted-foreground text-xs">
        This origin has no backend Host. Publishing only changes what FCP renders and the connection
        plan.
      </p>
    {/if}

    <Link
      href={edgesPaths.relay(relay.slug, { tab: 'edges' })}
      class={buttonVariants({ size: 'sm', variant: 'ghost' })}
    >
      Choose a different edge on the origin page
    </Link>

    {#if edgeId}
      <PublishDialog
        bind:open
        relayId={relay.id}
        relaySlug={relay.slug}
        {edgeId}
        onStarted={onRotation}
      />
    {/if}
  {/if}
</div>
