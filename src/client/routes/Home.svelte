<script lang="ts">
  /**
   * Main landing page for FreeSocks. This deployment IS the primary public
   * surface for the service: what was formerly a separate "marketing site"
   * has been folded in here, so there's no upstream to defer to.
   *
   * Voice principle: factual, plain. No invented stats, no marketing
   * flourishes, no claims about Unredacted's other programs (we link to
   * unredacted.org for that; they own that copy, not us).
   *
   * Layout: full-width sections on the site-wrap column, alternating the page
   * and band backgrounds, each separated by a top rule. In order: the hero
   * with its poster, what donations are doing for free accounts right now,
   * how it works, what we store, membership, the FAQ (general + threat
   * model), and the donate box. Each claim appears exactly once.
   *
   * Fully localized: every visible string resolves through t() so the
   * censored-region (mostly non-English) audience gets the page in their
   * language. DB-driven values (tier name/description, prices) stay dynamic
   * and are deliberately NOT translated.
   */
  import Link from '../components/Link.svelte';
  import { Button } from '@client/components/ui/button';
  import * as Tabs from '@client/components/ui/tabs';
  import TierComparison from '../components/TierComparison.svelte';
  import PixelPoster from '../components/PixelPoster.svelte';
  import CountUp from '../components/CountUp.svelte';
  import { meQuery, configQuery } from '../lib/queries';
  import { membershipTier, tierLimits, deviceLimitsShown, type TierLimits } from '../lib/tiers';
  import { t, getLocale, type MessageKey } from '../lib/i18n/index.svelte';
  import { goToSection, homeFaq, THREAT_MODEL_ID } from '../lib/homeSections.svelte';
  import { router } from '../stores/router.svelte';
  import { slide, fly, fade } from 'svelte/transition';
  import { onMount } from 'svelte';
  import Plus from '@lucide/svelte/icons/plus';
  import Minus from '@lucide/svelte/icons/minus';

  const me = meQuery();
  const config = configQuery();

  // The membership upgrade entry point: an authed member goes straight to their
  // account (the upgrade backend); an anon visitor creates a free account first.
  const billingEnabled = $derived(config.data?.billing?.enabled ?? false);
  // Admin-configured site chrome (hero overrides, repo link, support email).
  const site = $derived(config.data?.site);
  function goUpgrade() {
    router.navigate(me.data?.authenticated ? '/account' : '/get-account');
  }

  // Animated hero title: the operator's DB list wins (verbatim, like heroTitle);
  // a single heroTitle is a static override; else the built-in translated set.
  // 2+ variants rotate on a 4s cadence (paused for reduced-motion users).
  const heroVariants = $derived.by(() => {
    const fromDb = (site?.heroTitles ?? []).map((s) => s.trim()).filter(Boolean);
    if (fromDb.length > 0) return fromDb;
    if (site?.heroTitle?.trim()) return [site.heroTitle.trim()];
    return [
      t('home.hero.variants.freedom'),
      t('home.hero.variants.dissidents'),
      t('home.hero.variants.privacy'),
      t('home.hero.variants.world'),
    ];
  });
  let heroIdx = $state(0);
  let reducedMotion = $state(false);
  onMount(() => {
    // A #threat-model deep link lands on the FAQ's threat tab.
    if (window.location.hash === `#${THREAT_MODEL_ID}`) homeFaq.tab = 'threat';
    reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reducedMotion) return;
    const id = window.setInterval(() => {
      if (!document.hidden) heroIdx = heroIdx + 1;
    }, 4000);
    return () => window.clearInterval(id);
  });

  // Donation impact (GB + user counts only - no dollar figures on the public
  // page). The in-app donate controls live on the account Membership tab; an
  // anon visitor gets the public donate page, which also carries the
  // month's chart and recent gifts.
  const donation = $derived(config.data?.billing?.donation);
  const donationsLive = $derived(billingEnabled && !!donation?.enabled);
  const bonusGb = $derived(donation?.currentBonusGb ?? 0);
  // Operator-tunable (1-365); never hardcode the window into donor-facing copy.
  const impactWindowDays = $derived(donation?.bonusWindowDays ?? 30);
  function goDonate() {
    // Anonymous visitors get the public donate page (sign in OR give
    // anonymously) - not the account-creation funnel.
    router.navigate(me.data?.authenticated ? '/account?tab=membership' : '/donate');
  }

  // Compose a localized limits phrase from the structured (DB-driven) tier
  // limits: the numbers come from config, the words from the catalog. Reading
  // t() inside makes any $derived that calls this re-run on a locale change.
  function limitsText(info: TierLimits, showDevices: boolean): string {
    const bandwidth = info.unlimitedBandwidth
      ? t('home.limits.unlimitedBandwidth')
      : t('tiers.gbPerMonth', { gb: info.gb });
    // Device limits are an opt-in, Remnawave-only feature; when enforcement is
    // off (the default) the whole device dimension is hidden - everyone is
    // effectively unlimited - so the phrase is bandwidth-only.
    if (!showDevices) return bandwidth;
    if (info.unlimitedBandwidth && info.unlimitedDevices) return t('home.limits.unlimitedBoth');
    const devices = info.unlimitedDevices
      ? t('home.limits.unlimitedDevices')
      : t('home.limits.upToDevices', { count: info.devices });
    return t('home.limits.bandwidthAndDevices', { bandwidth, devices });
  }

  // Live free-tier allowance from /api/v1/config (the DB-enforced number):
  // 0 means unlimited.
  const freeTier = $derived(config.data?.tiers.find((tier) => tier.slug === 'free'));
  const freeGb = $derived(freeTier?.monthlyTrafficGb ?? 0);

  // Paid-tier limits, DB-driven: drives the membership prose below so it never
  // contradicts the admin-set tier. `description` is the admin-editable line;
  // `membershipLimits` is the localized phrase from the tier's limits.
  const memberTier = $derived(membershipTier(config.data));
  const memberInfo = $derived(tierLimits(memberTier));
  const membershipLimits = $derived(limitsText(memberInfo, deviceLimitsShown(config.data)));

  // Step numbers in the visitor's own digits (Persian and Arabic included).
  const stepNumber = $derived(new Intl.NumberFormat(getLocale()));

  const steps = [
    { n: 1, title: 'home.how.s1.title', body: 'home.how.s1.body' },
    { n: 2, title: 'home.how.s2.title', body: 'home.how.s2.body' },
    { n: 3, title: 'home.how.s3.title', body: 'home.how.s3.body' },
  ] as const;

  // "What we store" - factual claims about how the system is built (hash-only,
  // no PII, no traffic logs). The strongest trust signal we can give an anxious,
  // surveillance-wary visitor, and copy the org can stand behind without legal
  // sign-off.
  const privacyPoints = [
    'home.privacy.point1',
    'home.privacy.point2',
    'home.privacy.point3',
    'home.privacy.point4',
  ] as const;

  // FAQ - single-open accordion, the first answer open on arrival.
  const FAQ = [
    { q: 'faq.q1.question', a: 'faq.q1.answer' },
    { q: 'faq.q2.question', a: 'faq.q2.answer' },
    { q: 'faq.q3.question', a: 'faq.q3.answer' },
    { q: 'faq.q4.question', a: 'faq.q4.answer' },
    { q: 'faq.q5.question', a: 'faq.q5.answer' },
    { q: 'faq.q6.question', a: 'faq.q6.answer' },
    { q: 'faq.q7.question', a: 'faq.q7.answer' },
    { q: 'faq.q8.question', a: 'faq.q8.answer' },
    { q: 'faq.q9.question', a: 'faq.q9.answer' },
    { q: 'faq.q10.question', a: 'faq.q10.answer' },
  ] as const;
  let openFaq = $state(0);

  // Threat-model FAQ - the honest what-we-can-and-cannot-do section. Same
  // single-open accordion pattern as the general FAQ, separate open state.
  const THREAT_FAQ = [
    { q: 'threat.q1.question', a: 'threat.q1.answer' },
    { q: 'threat.q2.question', a: 'threat.q2.answer' },
    { q: 'threat.q3.question', a: 'threat.q3.answer' },
    { q: 'threat.q4.question', a: 'threat.q4.answer' },
    { q: 'threat.q5.question', a: 'threat.q5.answer' },
    { q: 'threat.q6.question', a: 'threat.q6.answer' },
    { q: 'threat.q7.question', a: 'threat.q7.answer' },
  ] as const;
  let openThreat = $state(-1);

  const FAQ_TABS = [
    { value: 'general', label: 'faq.tabGeneral' },
    { value: 'threat', label: 'faq.tabThreat' },
  ] as const;

  // Shared section chrome. Negative tracking is dropped for right-to-left
  // scripts, where letter-spacing breaks the joins between letters.
  const H2 =
    'text-[clamp(28px,2.9vw,35px)] font-bold leading-[1.1] tracking-[-0.02em] rtl:tracking-normal';
  const SECTION = 'border-t border-border/70';
  const BAND = 'border-t border-border/70 bg-band';
  const PAD = 'py-16 md:py-24';
</script>

{#snippet accordion(items: readonly { q: MessageKey; a: MessageKey }[], prefix: 'faq' | 'tm')}
  <ul>
    {#each items as item, i (item.q)}
      {@const isOpen = (prefix === 'faq' ? openFaq : openThreat) === i}
      <li class="border-b border-border/70">
        <button
          type="button"
          id="{prefix}-trigger-{i}"
          class="flex min-h-[60px] w-full items-center justify-between gap-4 py-3 text-start font-bold text-foreground transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
          aria-expanded={isOpen}
          aria-controls="{prefix}-panel-{i}"
          onclick={() => {
            const next = isOpen ? -1 : i;
            if (prefix === 'faq') openFaq = next;
            else openThreat = next;
          }}
        >
          <span>{t(item.q)}</span>
          {#if isOpen}
            <Minus class="size-[18px] shrink-0" aria-hidden="true" />
          {:else}
            <Plus class="size-[18px] shrink-0" aria-hidden="true" />
          {/if}
        </button>
        {#if isOpen}
          <div
            id="{prefix}-panel-{i}"
            role="region"
            aria-labelledby="{prefix}-trigger-{i}"
            class="max-w-[38em] pb-5 leading-relaxed text-body"
            transition:slide={{ duration: 180 }}
          >
            {t(item.a)}
          </div>
        {/if}
      </li>
    {/each}
  </ul>
{/snippet}

{#snippet allowanceRow(label: string, value: string, swatch: string)}
  <div class="flex items-center justify-between gap-4 border-b border-border/70 py-3">
    <dt class="flex items-center gap-3">
      <span class="size-[11px] shrink-0 {swatch}" aria-hidden="true"></span>{label}
    </dt>
    <!-- <bdi>: "+12 GB" keeps its order inside right-to-left text. -->
    <dd class="font-bold text-foreground tabular-nums"><bdi>{value}</bdi></dd>
  </div>
{/snippet}

<!-- HERO: the headline, the subtitle, one primary action, and the poster. -->
<section>
  <div
    class="site-wrap grid items-center gap-12 py-14 md:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)] md:gap-16 md:pt-[88px] md:pb-24"
  >
    <div>
      <h1
        class="text-[clamp(44px,6.2vw,76px)] font-bold leading-[1.02] tracking-[-0.03em] rtl:leading-[1.25] rtl:tracking-normal"
      >
        {#if heroVariants.length > 1 && !reducedMotion}
          {@const shown = heroVariants[heroIdx % heroVariants.length]!}
          <!-- Zero layout shift: invisible copies of EVERY variant stack in
               one grid cell, so the tallest one pins the h1's box constant
               while only the visible text transitions on top of it. -->
          <span class="grid">
            {#each heroVariants as v (v)}
              <span class="invisible [grid-area:1/1]" aria-hidden="true">{v}</span>
            {/each}
            {#key shown}
              <span
                class="[grid-area:1/1] self-start"
                in:fly={{ y: '0.35em', duration: 320 }}
                out:fade={{ duration: 120 }}
              >
                {shown}
              </span>
            {/key}
          </span>
        {:else}
          {heroVariants[heroIdx % heroVariants.length]}
        {/if}
      </h1>

      <p class="mt-6 max-w-[32em] text-lg leading-[1.55] text-body md:text-xl">
        {site?.heroSubtitle?.trim() || t('home.hero.subtitle', { limits: membershipLimits })}
      </p>

      <div class="mt-8 flex flex-wrap gap-3">
        {#if !me.isPending && me.data?.authenticated}
          <Link href="/account">
            <Button size="lg" class="h-12 text-base">{t('nav.account')}</Button>
          </Link>
          {#if billingEnabled}
            <Button size="lg" variant="outline" class="h-12 text-base" onclick={goUpgrade}>
              {t('home.cta.getMembership')}
            </Button>
          {/if}
        {:else}
          <Link href="/get-account">
            <Button size="lg" class="h-12 text-base">{t('nav.getAccount')}</Button>
          </Link>
          <Link href="/login">
            <Button size="lg" variant="outline" class="h-12 text-base">{t('nav.signIn')}</Button>
          </Link>
        {/if}
      </div>
    </div>

    <PixelPoster />
  </div>
</section>

<!-- WHAT DONATIONS ARE DOING: free accounts reached, and what every free
     account gets this month (the free allowance plus the shared donation
     bonus, as a stacked bar). GB and account counts only, never money. -->
{#if donationsLive && donation}
  <section id="impact" class="scroll-mt-6 {BAND}">
    <div class="site-wrap grid items-start gap-12 {PAD} md:grid-cols-2 md:gap-16 md:py-20">
      <div>
        <h2 class={H2}>{t('home.impact.title')}</h2>
        <p class="mt-7 flex flex-wrap items-baseline gap-x-3.5 gap-y-1">
          <span
            class="font-display text-[clamp(56px,7vw,92px)] font-bold leading-none tracking-[-0.04em] text-foreground rtl:tracking-normal"
          >
            <CountUp value={donation.freeUsersHelped} start />
          </span>
          <span class="font-display text-[26px] font-bold text-primary">
            {t('impact.usersHelped')}
          </span>
        </p>
        <p class="mt-4 max-w-[28em] text-body">
          {t('impact.collectiveBody', { days: impactWindowDays })}
        </p>
      </div>

      <div>
        <p class="mt-1.5 mb-3.5 text-[15px] text-muted-foreground">
          {t('home.impact.allowanceTitle')}
        </p>
        {#if freeGb > 0}
          <div class="flex h-3.5 gap-[3px]" aria-hidden="true">
            <div class="bg-primary" style="flex: {freeGb}"></div>
            {#if bonusGb > 0}
              <div class="bg-primary/45" style="flex: {bonusGb}"></div>
            {/if}
          </div>
        {/if}
        <dl class="mt-4">
          {@render allowanceRow(
            t('home.freeCard.title'),
            freeGb > 0 ? t('tiers.gbPerMonth', { gb: freeGb }) : t('hero.unlimited'),
            'bg-primary',
          )}
          {#if bonusGb > 0}
            {@render allowanceRow(
              t('home.impact.allowanceDonations'),
              t('home.impact.bonusGb', { gb: bonusGb }),
              'bg-primary/45',
            )}
          {/if}
          {#if memberTier}
            {@render allowanceRow(
              t('home.membership.title'),
              memberInfo.unlimitedBandwidth
                ? t('hero.unlimited')
                : t('tiers.gbPerMonth', { gb: memberInfo.gb }),
              '',
            )}
          {/if}
        </dl>
        {#if bonusGb <= 0}
          <p class="mt-4 text-sm text-muted-foreground">{t('impact.empty')}</p>
        {/if}
        <p class="mt-4 text-[15px]">
          <Link class="link-brand text-foreground" href="/donate">{t('home.hero.impactLink')}</Link>
        </p>
      </div>
    </div>
  </section>
{/if}

<!-- HOW IT WORKS -->
<section id="how" class="scroll-mt-6 {SECTION}">
  <div class="site-wrap {PAD}">
    <h2 class={H2}>{t('home.how.title')}</h2>
    <ol class="mt-10 grid gap-10 md:grid-cols-3">
      {#each steps as step (step.n)}
        <li class="border-t-2 border-border pt-5">
          <p class="font-display text-[15px] font-bold text-primary tabular-nums">
            {stepNumber.format(step.n)}
          </p>
          <h3 class="mt-1.5 font-display text-[21px] font-bold leading-tight">{t(step.title)}</h3>
          <p class="mt-2.5 text-body">{t(step.body)}</p>
        </li>
      {/each}
    </ol>
    <div class="mt-11">
      <Link href="/get-account">
        <Button size="lg" class="text-base">{t('home.how.cta')}</Button>
      </Link>
    </div>
  </div>
</section>

<!-- WHAT WE STORE: the privacy case, as plain statements in a ruled list. -->
<section id="privacy" class="scroll-mt-6 {BAND}">
  <div class="site-wrap grid gap-10 {PAD} md:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)] md:gap-16">
    <div>
      <h2 class={H2}>{t('home.privacy.title')}</h2>
      <p class="mt-4 max-w-[20em] text-lg text-body md:text-[19px]">
        {t('home.privacy.subtitle')}
      </p>
      <p class="mt-6">
        <a
          class="link-brand text-foreground"
          href="/#{THREAT_MODEL_ID}"
          onclick={(e) => void goToSection(e, THREAT_MODEL_ID)}>{t('faq.tabThreat')}</a
        >
      </p>
    </div>
    <ul>
      {#each privacyPoints as point (point)}
        <li class="border-t border-border py-[18px] text-foreground last:border-b">
          {t(point)}
        </li>
      {/each}
    </ul>
  </div>
</section>

<!-- MEMBERSHIP: what the paid tier adds, and how to pay privately. -->
{#if billingEnabled}
  <section id="membership" class="scroll-mt-6 {SECTION}">
    <div class="site-wrap space-y-10 {PAD}">
      <div class="max-w-2xl">
        <h2 class={H2}>{t('home.membership.title')}</h2>
        <p class="mt-4 text-body">
          {t('home.membership.lead')}
          {memberTier?.description ?? t('home.membership.descriptionFallback')}
          {t('home.membership.payNote')}
        </p>
      </div>
      <TierComparison currentTierSlug="" onUpgrade={goUpgrade} hideHeader />
    </div>
  </section>
{/if}

<!-- FAQ - one section with two tabs: the general basics, and the threat model
     (what this service can and cannot protect against; deliberately honest,
     since overclaiming security gets people hurt). A #threat-model deep link
     lands on the threat tab. -->
<section id="faq" class="scroll-mt-6 {SECTION}">
  <div
    id={THREAT_MODEL_ID}
    class="site-wrap grid scroll-mt-6 gap-10 {PAD} md:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)] md:gap-16"
  >
    <div>
      <h2 class={H2}>{t('faq.title')}</h2>
      {#if site?.supportEmail}
        <p class="mt-4 max-w-[22em] text-body">
          {t('faq.contactPrefix')}
          <a class="link-brand text-foreground" href="mailto:{site.supportEmail}"
            >{site.supportEmail}</a
          >
          {t('faq.contactSuffix')}
        </p>
      {/if}
    </div>
    <Tabs.Root bind:value={homeFaq.tab} class="gap-0">
      <Tabs.List variant="line">
        {#each FAQ_TABS as tab (tab.value)}
          <Tabs.Trigger variant="line" value={tab.value}>{t(tab.label)}</Tabs.Trigger>
        {/each}
      </Tabs.List>
      <Tabs.Content value="general">
        {@render accordion(FAQ, 'faq')}
      </Tabs.Content>
      <Tabs.Content value="threat">
        <p class="mt-5 max-w-[38em] text-body">{t('threat.subtitle')}</p>
        {@render accordion(THREAT_FAQ, 'tm')}
      </Tabs.Content>
    </Tabs.Root>
  </div>
</section>

<!-- DONATE: the one solid-green box on the page. -->
{#if donationsLive}
  <section>
    <div class="site-wrap pb-16 md:pb-24">
      <div
        class="grid items-center gap-8 rounded-lg bg-primary p-[clamp(28px,4vw,48px)] text-primary-foreground md:grid-cols-[minmax(0,1.5fr)_auto]"
      >
        <div>
          <h2
            class="text-[clamp(26px,2.6vw,32px)] font-bold leading-[1.15] tracking-[-0.02em] rtl:tracking-normal"
          >
            {t('home.donate.title')}
          </h2>
          <p class="mt-3 max-w-[34em]">{t('home.hero.impactNote')}</p>
        </div>
        <div class="flex flex-wrap gap-3">
          <Button
            size="lg"
            class="bg-[#1f1f1d] text-[15px] text-[#f5f4ef] hover:bg-[#1f1f1d]/85"
            onclick={goDonate}
          >
            {t('home.impact.cta')}
          </Button>
          <Link href="/donate">
            <Button
              size="lg"
              variant="outline"
              class="border-current text-[15px] text-primary-foreground hover:bg-black/10 hover:text-primary-foreground"
            >
              {t('home.hero.impactLink')}
            </Button>
          </Link>
        </div>
      </div>
    </div>
  </section>
{/if}
