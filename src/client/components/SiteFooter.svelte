<script lang="ts">
  import Link from './Link.svelte';
  import BrandMark from './BrandMark.svelte';
  import SocialLinks from './SocialLinks.svelte';
  import { configQuery, meQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import { FAQ_ID, goToSection, THREAT_MODEL_ID } from '../lib/homeSections.svelte';

  /**
   * The member-facing footer: the brand, three link columns, and who
   * operates the service. Every external link is admin-configured
   * (publicConfig.site, https-only, blank hides it). Donate is routed in-app
   * (a member's Membership tab, else the public /donate page) so gifts feed
   * the free-user bandwidth pool. The admin CMS keeps its own short footer.
   */
  let { class: klass = '' }: { class?: string } = $props();

  const cfg = configQuery();
  const me = meQuery();
  const site = $derived(cfg.data?.site);
  const billingEnabled = $derived(!!cfg.data?.billing?.enabled);
  const donateEnabled = $derived(billingEnabled && !!cfg.data?.billing?.donation?.enabled);
  const donateHref = $derived(me.data?.authenticated ? '/account?tab=membership' : '/donate');

  const linkCls = 'hover:text-primary';
</script>

{#snippet external(href: string, label: string)}
  <li><a class={linkCls} {href} target="_blank" rel="noopener noreferrer">{label}</a></li>
{/snippet}

{#snippet section(id: string, label: string)}
  <li>
    <a class={linkCls} href="/#{id}" onclick={(e) => void goToSection(e, id)}>{label}</a>
  </li>
{/snippet}

<footer class="border-t border-border/70 bg-band {klass}">
  <div class="site-wrap grid gap-10 pt-14 pb-10 sm:grid-cols-2 md:grid-cols-[1.4fr_repeat(3,1fr)]">
    <div>
      <Link href="/" class="inline-flex items-center gap-2.5" aria-label={t('nav.home')}>
        <BrandMark class="size-[30px]" />
        <span class="font-display text-[21px] font-extrabold tracking-[-0.02em] text-foreground">
          FreeSocks
        </span>
      </Link>
      <p class="mt-3.5 max-w-[18em] text-muted-foreground">{t('home.hero.variants.freedom')}</p>
      {#if site?.socialXUrl || site?.socialMastodonUrl || site?.socialBlueskyUrl}
        <div class="mt-4 -ms-2.5 flex items-center text-muted-foreground">
          <SocialLinks
            linkClass="inline-flex size-10 items-center justify-center rounded-sm hover:text-primary"
            iconClass="size-[18px]"
          />
        </div>
      {/if}
    </div>

    <div>
      <h2 class="mb-3 text-[15px] font-bold">FreeSocks</h2>
      <ul class="grid gap-1.5 text-[15px]">
        {@render section('how', t('home.how.title'))}
        <li><Link class={linkCls} href="/status">{t('status.title')}</Link></li>
        {#if billingEnabled}
          {@render section('membership', t('home.membership.title'))}
        {/if}
        {#if donateEnabled}
          <li><Link class={linkCls} href={donateHref}>{t('renew.donate')}</Link></li>
        {/if}
      </ul>
    </div>

    <div>
      <h2 class="mb-3 text-[15px] font-bold">{t('footer.support')}</h2>
      <ul class="grid gap-1.5 text-[15px]">
        {@render section(FAQ_ID, t('home.sections.faq'))}
        {@render section(THREAT_MODEL_ID, t('faq.tabThreat'))}
        {#if site?.supportEmail}
          <li><a class={linkCls} href="mailto:{site.supportEmail}">{site.supportEmail}</a></li>
        {/if}
      </ul>
    </div>

    <div>
      <h2 class="mb-3 text-[15px] font-bold">{t('home.sections.about')}</h2>
      <ul class="grid gap-1.5 text-[15px]">
        {#if site?.repoEnabled && site.repoUrl}
          {@render external(site.repoUrl, t('footer.viewSource'))}
        {/if}
        {#if site?.transparencyUrl}
          {@render external(site.transparencyUrl, t('footer.transparency'))}
        {/if}
        {#if site?.tosUrl}
          {@render external(site.tosUrl, t('footer.terms'))}
        {/if}
        {#if site?.privacyUrl}
          {@render external(site.privacyUrl, t('footer.privacy'))}
        {/if}
      </ul>
    </div>
  </div>

  <div class="site-wrap">
    <p class="border-t border-border/70 py-5 text-sm text-muted-foreground">
      {t('footer.operatedPrefix')}
      <a
        class="link-brand text-foreground"
        href="https://unredacted.org"
        target="_blank"
        rel="noopener noreferrer">Unredacted</a
      >{t('footer.operatedSuffix')}
    </p>
  </div>
</footer>
