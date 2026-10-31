<script lang="ts">
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import SocialLinks from './SocialLinks.svelte';

  /**
   * Footer links - admin-configurable via publicConfig.site: a support mailto
   * link (email; blank hides it), a "View source" repo link (toggle + https URL),
   * plus optional Terms of Service / Privacy Policy / Transparency Report links
   * and the social profile icons (SocialLinks; https URL only - an empty URL
   * hides the link). Its own component (not inline in
   * App.svelte's footer) because App addresses the QueryClientProvider, so configQuery()
   * can only run from a child inside the provider tree. The server sanitizes each URL
   * to https-only, so '' (or an unsafe value) → hidden.
   */
  const cfg = configQuery();
  const site = $derived(cfg.data?.site);
</script>

{#if site?.supportEmail}
  <a class="hover:text-foreground" href="mailto:{site.supportEmail}">
    {t('footer.support')}
  </a>
{/if}
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
{#if site?.transparencyUrl}
  <a
    class="hover:text-foreground"
    href={site.transparencyUrl}
    target="_blank"
    rel="noopener noreferrer"
  >
    {t('footer.transparency')}
  </a>
{/if}
<SocialLinks />
