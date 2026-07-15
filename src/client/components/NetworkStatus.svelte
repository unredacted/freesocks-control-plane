<script lang="ts">
  /**
   * Slim live network-status strip for the home page: every server location
   * from publicConfig.locations with an online/offline dot. Transparent,
   * verifiable, live data as a trust signal - VPN sites rarely show this.
   * Reuses the page's configQuery (zero extra requests); hides entirely when
   * no located instances exist. The dot color is never the only signal
   * (sr-only text + the visible "(offline)" suffix carry it too).
   */
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';

  const config = configQuery();
  const locations = $derived(config.data?.locations ?? []);
</script>

{#if locations.length > 0}
  <section
    class="rounded-xl border border-border bg-card px-5 py-3 flex flex-wrap items-center gap-x-6 gap-y-2"
    aria-label={t('home.network.title')}
  >
    <span
      class="font-mono text-[11px] font-medium uppercase tracking-[0.18em] text-muted-foreground"
    >
      {t('home.network.title')}
    </span>
    {#each locations as loc (loc.code)}
      <span class="inline-flex items-center gap-2 text-sm">
        <span
          class="size-2 shrink-0 rounded-full {loc.online
            ? 'bg-primary status-pulse'
            : 'bg-muted-foreground/40'}"
          aria-hidden="true"
        ></span>
        <span class="sr-only"
          >{loc.online ? t('home.network.srOnline') : t('home.network.srOffline')}</span
        >
        <span class="font-mono text-xs uppercase text-muted-foreground">{loc.code}</span>
        <span>{loc.label}</span>
        {#if !loc.online}
          <span class="text-xs text-muted-foreground">({t('home.network.offline')})</span>
        {/if}
      </span>
    {/each}
    <span class="ms-auto text-[11px] text-muted-foreground">{t('home.network.note')}</span>
  </section>
{/if}
