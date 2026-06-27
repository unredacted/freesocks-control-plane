<script lang="ts">
  /**
   * Wraps the route tree with `<svelte:boundary>` so a render-time crash in
   * any child does not blank the entire SPA. Mirrors the React class-based
   * ErrorBoundary the codebase had pre-Svelte: catches the throw, logs it,
   * shows a "Something went wrong" panel with a reload affordance.
   *
   * Note: Svelte 5's <svelte:boundary> only catches errors during render and
   * effect runs. Async event-handler errors must still be caught explicitly
   * by the call site.
   */
  import { Button } from '@client/components/ui/button';
  import { t } from '../lib/i18n/index.svelte';

  interface Props {
    children?: import('svelte').Snippet;
  }
  let { children }: Props = $props();
</script>

<svelte:boundary
  onerror={(err: unknown) => {
    console.error('Render-time error caught by ErrorBoundary', err);
  }}
>
  {#if children}{@render children()}{/if}

  {#snippet failed(_err: unknown, reset: () => void)}
    <div class="max-w-lg mx-auto py-16 text-center space-y-4">
      <h1 class="text-2xl font-bold">{t('error.renderTitle')}</h1>
      <p class="text-muted-foreground">
        {t('error.renderBody')}
      </p>
      <div class="flex gap-2 justify-center pt-2">
        <Button onclick={() => window.location.reload()}>{t('error.reloadPage')}</Button>
        <Button variant="ghost" onclick={reset}>{t('error.tryAgain')}</Button>
      </div>
    </div>
  {/snippet}
</svelte:boundary>
