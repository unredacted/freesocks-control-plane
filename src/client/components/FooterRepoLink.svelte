<script lang="ts">
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Footer links — admin-configurable via publicConfig.site: a "View source" repo
   * link (toggle + https URL) plus optional Terms of Service / Privacy Policy links
   * (https URL only — an empty URL hides the link). Its own component (not inline in
   * App.svelte's footer) because App hosts the QueryClientProvider, so configQuery()
   * can only run from a child inside the provider tree. The server sanitizes each URL
   * to https-only, so '' (or an unsafe value) → hidden.
   */
  const cfg = configQuery();
  const site = $derived(cfg.data?.site);
</script>

{#if site?.repoEnabled && site.repoUrl}
  <a class="hover:text-foreground" href={site.repoUrl} target="_blank" rel="noopener noreferrer">
    {t('footer.viewSource')}
  </a>
{/if}
{#if site?.tosUrl}
  <a class="hover:text-foreground" href={site.tosUrl} target="_blank" rel="noopener noreferrer">
    {t('footer.terms')}
  </a>
{/if}
{#if site?.privacyUrl}
  <a class="hover:text-foreground" href={site.privacyUrl} target="_blank" rel="noopener noreferrer">
    {t('footer.privacy')}
  </a>
{/if}
