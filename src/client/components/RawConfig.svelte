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
  interface Props {
    /** Open on mount + auto-open when promoted (privacy mode makes this the
     *  recommended delivery method, so it starts expanded). */
    startOpen?: boolean;
    /** Render as the PRIMARY config panel: always open, titled, no collapse
     *  toggle, primary border. Privacy mode makes the raw config the headline. */
    prominent?: boolean;
  }
  let { startOpen = false, prominent = false }: Props = $props();

  // `open` MUST be declared before the query: subscriptionContentQuery evaluates
  // its `enabled` getter synchronously at creation, so reading `open` first would
  // hit the temporal dead zone and throw during render. `prominent` implies open
  // (no toggle) so the content actually fetches.
  let open = $state(startOpen || prominent);
  let copied = $state(false);
  const content = subscriptionContentQuery(() => open);
  // Expand when the parent promotes us (e.g. the member switches to privacy);
  // never force-collapse, so a manual collapse sticks.
  $effect(() => {
    if (startOpen) open = true;
  });

  function copy(text: string) {
    void navigator.clipboard.writeText(text).then(() => {
      copied = true;
      setTimeout(() => (copied = false), 1500);
    });
  }

  // Remnawave's default subscription is base64(newline-joined links). Decode it
  // so the user sees readable vless://… entries they can add by hand; fall back
  // to the raw text for any other format (clash YAML, already-plaintext, etc.).
  function prettify(raw: string): string {
    const trimmed = raw.trim();
    if (trimmed.length >= 8 && /^[A-Za-z0-9+/=\s]+$/.test(trimmed)) {
      try {
        const decoded = atob(trimmed.replace(/\s+/g, ''));
        if (decoded.includes('://')) return decoded.trim();
      } catch {
        /* not base64 — show raw */
      }
    }
    return raw;
  }
</script>

<div class="rounded-xl border {prominent ? 'border-primary/30' : 'border-border/60'} bg-muted/30">
  {#if prominent}
    <div class="flex items-center gap-2 px-4 py-3 text-sm font-semibold text-foreground">
      <FileCode class="size-4 shrink-0 text-primary" />
      {t('rawconfig.title')}
    </div>
  {:else}
    <button
      type="button"
      class="flex w-full items-center justify-between gap-2 rounded-xl px-4 py-3 text-start text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
      onclick={() => (open = !open)}
      aria-expanded={open}
    >
      <span class="flex items-center gap-2 text-muted-foreground">
        <FileCode class="size-4 shrink-0" />
        {t('rawconfig.disclosure')}
      </span>
      <ChevronDown class="size-4 shrink-0 transition-transform {open ? 'rotate-180' : ''}" />
    </button>
  {/if}

  {#if open}
    <div class="space-y-3 px-4 pb-4 text-sm" transition:slide={{ duration: 180 }}>
      <p class="text-muted-foreground">{t('rawconfig.explainer')}</p>

      {#if content.isPending}
        <p class="text-xs text-muted-foreground">{t('common.loading')}</p>
      {:else if content.isError}
        <p class="text-xs text-destructive">{apiErrorMessage(content.error)}</p>
      {:else if content.data}
        {@const text = prettify(content.data.content)}
        <div class="flex justify-end">
          <Button variant="outline" size="sm" class="min-h-11" onclick={() => copy(text)}>
            {#if copied}
              <Check class="size-3.5" />
            {:else}
              <Copy class="size-3.5" />
            {/if}
            <span class="ms-1">{t('common.copy')}</span>
          </Button>
        </div>
        <pre
          class="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 font-mono text-xs leading-relaxed text-foreground">{text}</pre>
        <p class="text-xs text-muted-foreground/80">{t('rawconfig.addHint')}</p>
      {/if}
    </div>
  {/if}
</div>
