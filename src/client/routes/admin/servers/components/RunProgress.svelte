<script lang="ts">
  /**
   * A fronting run's progress inline in a node page's Summary (`?run=<id>`),
   * instead of a jump to the protect sheet on another page: the same
   * ProtectProgress the sheet shows (stages, the live line, the card that
   * needs you), in a bordered card with Close.
   *
   * Props:
   *   runId: string
   *   onClose: () => void
   */
  import XIcon from '@lucide/svelte/icons/x';
  import { Button } from '@client/components/ui/button';
  import ProtectProgress from '../../edges/simple/ProtectProgress.svelte';

  interface Props {
    runId: string;
    onClose: () => void;
  }
  let { runId, onClose }: Props = $props();
</script>

<section class="rounded-lg border p-4" aria-label="Fronting progress">
  <div class="mb-2 flex items-center justify-between gap-3">
    <h3 class="text-sm font-semibold">Fronting progress</h3>
    <Button variant="ghost" size="icon-sm" aria-label="Close the progress" onclick={onClose}>
      <XIcon aria-hidden="true" />
    </Button>
  </div>
  {#key runId}
    <ProtectProgress {runId} {onClose} />
  {/key}
</section>
