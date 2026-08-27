<script lang="ts">
  import CodeXml from '@lucide/svelte/icons/code-xml';
  import { t } from '../lib/i18n/index.svelte';
  import { configQuery } from '../lib/queries';

  /**
   * Compact "Source" badge for the app chrome, beside the HPKE badge: the
   * always-visible pointer to the source code (open source is a trust signal
   * this audience actively checks for, not footer trivia). Reuses the admin's
   * footer repo config - same toggle + https-only URL - so there's exactly one
   * place the operator sets where "the source" lives; hidden until both are set.
   */
  const cfg = configQuery();
  const site = $derived(cfg.data?.site);
</script>

{#if site?.repoEnabled && site.repoUrl}
  <a
    href={site.repoUrl}
    target="_blank"
    rel="noopener noreferrer"
    title={t('nav.sourceTitle')}
    class="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-2 py-1 text-xs font-medium text-muted-foreground transition-all hover:scale-105 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
  >
    <CodeXml class="size-3.5 shrink-0" aria-hidden="true" />
    <span>{t('nav.source')}</span>
  </a>
{/if}
