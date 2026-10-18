<script lang="ts">
  /**
   * "Updated 25 s ago" beside a live admin panel (lib/livePoll.ts), with a
   * small button that reads it again now. The words tick every 5 s while
   * mounted; nothing shows until the panel has data (`at` 0).
   *
   * Props:
   *   at: number                        when the oldest data on the panel was read (ms)
   *   onRefresh?: () => Promise<unknown> read the panel again; the icon spins until it settles
   */
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import { Button } from '@client/components/ui/button';
  import { updatedAgoWords } from '@client/lib/livePoll';
  import { cn } from '@client/lib/utils';

  interface Props {
    at: number;
    onRefresh?: () => Promise<unknown>;
  }
  let { at, onRefresh }: Props = $props();

  let now = $state(Date.now());
  $effect(() => {
    const timer = setInterval(() => (now = Date.now()), 5_000);
    return () => clearInterval(timer);
  });

  let refreshing = $state(false);
  async function refresh() {
    if (!onRefresh || refreshing) return;
    refreshing = true;
    try {
      await onRefresh();
    } finally {
      refreshing = false;
      now = Date.now();
    }
  }
</script>

{#if at > 0}
  <span
    class="text-muted-foreground inline-flex items-center gap-1 text-xs font-normal"
    title={new Date(at).toLocaleTimeString()}
  >
    {updatedAgoWords(now - at)}
    {#if onRefresh}
      <Button
        variant="ghost"
        size="icon-xs"
        aria-label="Refresh now"
        disabled={refreshing}
        onclick={refresh}
      >
        <RefreshCw aria-hidden="true" class={cn(refreshing && 'animate-spin')} />
      </Button>
    {/if}
  </span>
{/if}
