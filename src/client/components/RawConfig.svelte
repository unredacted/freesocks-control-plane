<script lang="ts">
  import { slide } from 'svelte/transition';
  import { Button } from '@client/components/ui/button';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import FileCode from '@lucide/svelte/icons/file-code';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { subscriptionContentQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import { apiErrorMessage } from '../lib/errors';

  /**
   * Lazy, E2EE-preserving raw-config viewer. The proxy config is fetched
   * server-side and delivered over the SEALED reveal-leg channel (the CDN sees
   * ciphertext), so a member can copy it by hand WITHOUT their proxy client
   * pulling the subscription URL through a CDN in plaintext. Fetched only while
   * the panel is open — a deliberate, on-demand reveal, not auto-loaded.
   */
  const content = subscriptionContentQuery(() => open);
  let open = $state(false);
  let copied = $state(false);

  function copy(text: string) {
    void navigator.clipboard.writeText(text).then(() => {
      copied = true;
      setTimeout(() => (copied = false), 1500);
    });
  }
</script>

<div class="rounded-xl border border-border/60 bg-muted/20">
  <button
    type="button"
    class="flex w-full items-center justify-between gap-2 px-4 py-3 text-left text-sm font-medium"
    onclick={() => (open = !open)}
    aria-expanded={open}
  >
    <span class="flex items-center gap-2 text-muted-foreground">
      <FileCode class="size-4 shrink-0" />
      {t('rawconfig.disclosure')}
    </span>
    <ChevronDown class="size-4 shrink-0 transition-transform {open ? 'rotate-180' : ''}" />
  </button>

  {#if open}
    <div class="space-y-3 px-4 pb-4 text-sm" transition:slide={{ duration: 180 }}>
      <p class="text-muted-foreground">{t('rawconfig.explainer')}</p>

      {#if content.isPending}
        <p class="text-xs text-muted-foreground">{t('common.loading')}</p>
      {:else if content.isError}
        <p class="text-xs text-destructive">{apiErrorMessage(content.error)}</p>
      {:else if content.data}
        {@const cfg = content.data}
        <div class="flex justify-end">
          <Button variant="outline" size="sm" onclick={() => copy(cfg.content)}>
            {#if copied}
              <Check class="size-3.5" />
            {:else}
              <Copy class="size-3.5" />
            {/if}
            <span class="ms-1">{t('common.copy')}</span>
          </Button>
        </div>
        <pre
          class="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 font-mono text-xs leading-relaxed text-foreground">{cfg.content}</pre>
        <p class="text-xs text-muted-foreground/80">{t('rawconfig.addHint')}</p>
      {/if}
    </div>
  {/if}
</div>
