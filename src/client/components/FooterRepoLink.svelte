<script lang="ts">
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Footer links - admin-configurable via publicConfig.site: a support mailto
   * link (email; blank hides it), a "View source" repo link (toggle + https URL),
   * plus optional Terms of Service / Privacy Policy / Transparency Report links
   * and X / Mastodon / Bluesky profile icons (https URL only - an empty URL hides
   * the link). Its own component (not inline in
   * App.svelte's footer) because App hosts the QueryClientProvider, so configQuery()
   * can only run from a child inside the provider tree. The server sanitizes each URL
   * to https-only, so '' (or an unsafe value) → hidden.
   *
   * The social glyphs are inline SVG paths (from simple-icons, CC0) - lucide ships
   * no brand icons and the CSP is 'self'-only, so everything must be bundled.
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
{#if site?.socialXUrl}
  <a
    class="hover:text-foreground"
    href={site.socialXUrl}
    target="_blank"
    rel="noopener noreferrer"
    aria-label={t('footer.socialX')}
  >
    <svg viewBox="0 0 24 24" fill="currentColor" class="size-4" aria-hidden="true">
      <path
        d="M18.901 1.153h3.68l-8.04 9.19L24 22.846h-7.406l-5.8-7.584-6.638 7.584H.474l8.6-9.83L0 1.154h7.594l5.243 6.932ZM17.61 20.644h2.039L6.486 3.24H4.298Z"
      />
    </svg>
  </a>
{/if}
{#if site?.socialMastodonUrl}
  <!-- rel="me" lets the operator pass Mastodon profile-link verification. -->
  <a
    class="hover:text-foreground"
    href={site.socialMastodonUrl}
    target="_blank"
    rel="me noopener noreferrer"
    aria-label={t('footer.socialMastodon')}
  >
    <svg viewBox="0 0 24 24" fill="currentColor" class="size-4" aria-hidden="true">
      <path
        d="M23.268 5.313c-.35-2.578-2.617-4.61-5.304-5.004C17.51.242 15.792 0 11.813 0h-.03c-3.98 0-4.835.242-5.288.309C3.882.692 1.496 2.518.917 5.127.64 6.412.61 7.837.661 9.143c.074 1.874.088 3.745.26 5.611.118 1.24.325 2.47.62 3.68.55 2.237 2.777 4.098 4.96 4.857 2.336.792 4.849.923 7.256.38.265-.061.527-.132.786-.213.585-.184 1.27-.39 1.774-.753a.057.057 0 0 0 .023-.043v-1.809a.052.052 0 0 0-.02-.041.053.053 0 0 0-.046-.01 20.282 20.282 0 0 1-4.709.545c-2.73 0-3.463-1.284-3.674-1.818a5.593 5.593 0 0 1-.319-1.433.053.053 0 0 1 .066-.054c1.517.363 3.072.546 4.632.546.376 0 .75 0 1.125-.01 1.57-.044 3.224-.124 4.768-.422.038-.008.077-.015.11-.024 2.435-.464 4.753-1.92 4.989-5.604.008-.145.03-1.52.03-1.67.002-.512.167-3.63-.024-5.545zm-3.748 9.195h-2.561V8.29c0-1.309-.55-1.976-1.67-1.976-1.23 0-1.846.79-1.846 2.35v3.403h-2.546V8.663c0-1.56-.617-2.35-1.848-2.35-1.112 0-1.668.668-1.67 1.977v6.218H4.822V8.102c0-1.31.337-2.35 1.011-3.12.696-.77 1.608-1.164 2.74-1.164 1.311 0 2.302.5 2.962 1.498l.638 1.06.638-1.06c.66-.999 1.65-1.498 2.96-1.498 1.13 0 2.043.395 2.74 1.164.675.77 1.012 1.81 1.012 3.12z"
      />
    </svg>
  </a>
{/if}
{#if site?.socialBlueskyUrl}
  <a
    class="hover:text-foreground"
    href={site.socialBlueskyUrl}
    target="_blank"
    rel="noopener noreferrer"
    aria-label={t('footer.socialBluesky')}
  >
    <svg viewBox="0 0 24 24" fill="currentColor" class="size-4" aria-hidden="true">
      <path
        d="M12 10.8c-1.087-2.114-4.046-6.053-6.798-7.995C2.566.944 1.561 1.266.902 1.565.139 1.908 0 3.08 0 3.768c0 .69.378 5.65.624 6.479.815 2.736 3.713 3.66 6.383 3.364.136-.02.275-.039.415-.056-.138.022-.276.04-.415.056-3.912.58-7.387 2.005-2.83 7.078 5.013 5.19 6.87-1.113 7.823-4.308.953 3.195 2.05 9.271 7.733 4.308 4.267-4.308 1.172-6.498-2.74-7.078a8.741 8.741 0 0 1-.415-.056c.14.017.279.036.415.056 2.67.297 5.568-.628 6.383-3.364.246-.828.624-5.79.624-6.478 0-.69-.139-1.861-.902-2.206-.659-.298-1.664-.62-4.3 1.24C16.046 4.748 13.087 8.687 12 10.8Z"
      />
    </svg>
  </a>
{/if}
