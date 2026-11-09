<script lang="ts">
  /**
   * What an origin says before anything else: the quarantine resolver when it
   * is quarantined, that it is being deleted, and a running rotation with
   * "Watch it". The Overview tab of its technical details shows them first;
   * a node's page shows them in its Summary instead.
   *
   * Props: relay; onOpenEdge; onOpenRotation
   */
  import type { OriginAdmin } from '@shared/contracts/edges';
  import { Button } from '@client/components/ui/button';
  import QuarantineResolver from './QuarantineResolver.svelte';

  interface Props {
    relay: OriginAdmin;
    onOpenEdge: (edgeId: string) => void;
    onOpenRotation: (rotationId: string) => void;
  }
  let { relay, onOpenEdge, onOpenRotation }: Props = $props();
</script>

{#if relay.quarantine}
  <QuarantineResolver {relay} {onOpenEdge} {onOpenRotation} />
{/if}

{#if relay.deleting}
  <div class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
    This origin is being deleted. The page disappears once its last edge is destroyed.
  </div>
{/if}

{#if relay.activeRotationId}
  <div
    class="flex flex-wrap items-center justify-between gap-3 rounded-md border border-sky-500/40 bg-sky-500/10 p-3 text-sm"
    role="status"
  >
    <span>
      <span class="font-medium">A rotation is running.</span>
      Other pool changes wait until it finishes. This page refreshes every ten seconds.
    </span>
    <Button
      size="sm"
      onclick={() => relay.activeRotationId && onOpenRotation(relay.activeRotationId)}
    >
      Watch it
    </Button>
  </div>
{/if}
