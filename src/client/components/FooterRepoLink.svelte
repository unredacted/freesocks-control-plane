<script lang="ts">
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Footer "View source" link — admin-configurable (toggle + https URL via
   * publicConfig.site). Its own component (not inline in App.svelte's footer)
   * because App hosts the QueryClientProvider, so configQuery() can only run from
   * a child inside the provider tree. Renders nothing unless enabled + a URL is
   * set (the server sanitizes the URL to https-only, so '' when unsafe → hidden).
   */
  const cfg = configQuery();
  const site = $derived(cfg.data?.site);
</script>

{#if site?.repoEnabled && site.repoUrl}
  <a class="hover:text-foreground" href={site.repoUrl} target="_blank" rel="noopener noreferrer">
    {t('footer.viewSource')}
  </a>
{/if}
