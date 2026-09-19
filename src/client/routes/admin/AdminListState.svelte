<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import { ApiCallError } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';

  /**
   * Shared error/empty scaffolding for admin list pages. Before this existed,
   * the destructive error box was copy-pasted 8x and the dashed empty state 4x,
   * each reading `err.message` raw (bypassing apiErrorMessage, so a 429 showed
   * a server string instead of the friendly copy). Error mode wins when both
   * props are set; `onRetry` adds an inline retry affordance.
   */
  interface Props {
    error?: unknown;
    emptyText?: string;
    onRetry?: () => void;
  }
  let { error, emptyText, onRetry }: Props = $props();

  // The generic copy hides two failures an admin can act on: the browser
  // rejecting the shape of a successful answer (field names only, no values),
  // and an error thrown before any answer arrived.
  const technical = $derived(
    error instanceof ApiCallError
      ? error.payload.error.code === 'client.parse_error'
        ? error.payload.error.message
        : null
      : error instanceof Error
        ? `${error.name}: ${error.message}`
        : null,
  );
</script>

{#if error !== undefined && error !== null}
  <div
    class="flex flex-wrap items-center gap-3 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
  >
    <span class="min-w-0 flex-1">
      {apiErrorMessage(error)}
      {#if technical}
        <span class="mt-1 block font-mono text-xs break-words opacity-80">{technical}</span>
      {/if}
    </span>
    {#if onRetry}
      <Button size="sm" variant="outline" onclick={onRetry}>Retry</Button>
    {/if}
  </div>
{:else if emptyText}
  <div class="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
    {emptyText}
  </div>
{/if}
