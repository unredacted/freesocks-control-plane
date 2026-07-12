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
   * Fully localized: every visible string resolves through t() so the
   * censored-region (mostly non-English) audience gets the page in their
   * language. DB-driven values (tier name/description, prices) stay dynamic
   * and are deliberately NOT translated.
   */
  import Link from '../components/Link.svelte';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import TierComparison from '../components/TierComparison.svelte';
  import { meQuery, configQuery } from '../lib/queries';
  import { membershipTier, tierLimits, deviceLimitsShown, type TierLimits } from '../lib/tiers';
  import { baselinePerMonth } from '../lib/billing';
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';
  import { router } from '../stores/router.svelte';
  import { fly, fade, slide } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import SocksIcon from '../components/SocksIcon.svelte';
  import Lock from '@lucide/svelte/icons/lock';
  import Globe from '@lucide/svelte/icons/globe';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ArrowRight from '@lucide/svelte/icons/arrow-right';
  import Heart from '@lucide/svelte/icons/heart';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import DitherChart from '../components/DitherChart.svelte';
  import { impactChartSeries } from '../lib/impact';

  const me = meQuery();
  const config = configQuery();

  // The membership upgrade entry point: an authed member goes straight to their
  // account (the upgrade panel); an anon visitor creates a free account first.
  const billingEnabled = $derived(config.data?.billing?.enabled ?? false);
  function goUpgrade() {
    router.navigate(me.data?.authenticated ? '/account' : '/get-account');
  }

  // Donation impact (GB + user counts only — no dollar figures on the public
  // page). The in-app donate controls live on the account Membership tab; an
  // anon visitor creates a free account first.
  const donation = $derived(config.data?.billing?.donation);
  const donationHistory = $derived(donation?.history ?? []);
  // The chart always renders: real history, or a flat zero baseline while
  // there is none yet (the note under it explains).
  const impactSeries = $derived(impactChartSeries(donationHistory));
  function goDonate() {
    router.navigate(me.data?.authenticated ? '/account?tab=membership' : '/get-account');
  }

  // Compose a localized limits phrase from the structured (DB-driven) tier
  // limits: the numbers come from config, the words from the catalog. Reading
  // t() inside makes any $derived that calls this re-run on a locale change.
  function limitsText(info: TierLimits, showDevices: boolean): string {
    const bandwidth = info.unlimitedBandwidth
      ? t('home.limits.unlimitedBandwidth')
      : t('tiers.gbPerMonth', { gb: info.gb });
    // Device limits are an opt-in, Remnawave-only feature; when enforcement is
    // off (the default) the whole device dimension is hidden — everyone is
    // effectively unlimited — so the phrase is bandwidth-only.
    if (!showDevices) return bandwidth;
    if (info.unlimitedBandwidth && info.unlimitedDevices) return t('home.limits.unlimitedBoth');
    const devices = info.unlimitedDevices
      ? t('home.limits.unlimitedDevices')
      : t('home.limits.upToDevices', { count: info.devices });
    return t('home.limits.bandwidthAndDevices', { bandwidth, devices });
  }

  // Live free-tier limits from /api/v1/config (the DB-enforced numbers).
  const freeTier = $derived(config.data?.tiers.find((tier) => tier.slug === 'free'));
  const freeTierLine = $derived.by(() => {
    const ft = freeTier;
    if (!ft) return '';
    const bandwidth =
      ft.monthlyTrafficGb === 0
        ? t('hero.unlimited')
        : t('tiers.gbPerMonth', { gb: ft.monthlyTrafficGb });
    // Hide the device count when device-limit enforcement is off (the default).
    if (!deviceLimitsShown(config.data)) return bandwidth;
    const devices = t('common.deviceCount', { count: ft.deviceLimit });
    return `${devices} · ${bandwidth}`;
  });

  // Paid-tier limits, DB-driven: drives the membership prose below so it never
  // contradicts the admin-set tier. `description` is the admin-editable line;
  // `membershipLimits` is the localized phrase from the tier's limits.
  const memberTier = $derived(membershipTier(config.data));
  const membershipLimits = $derived(
    limitsText(tierLimits(memberTier), deviceLimitsShown(config.data)),
  );

  // Headline membership price = the shortest term's per-month rate (the standard
  // monthly), DB-driven + locale-formatted — mirrors TierComparison's "from $X/mo".
  // Null until the billing config loads.
  const membershipFromPrice = $derived.by(() => {
    const cents = baselinePerMonth(config.data?.billing?.durations ?? []);
    return cents !== null
      ? formatMoney(Math.round(cents), config.data?.billing?.currency ?? 'USD')
      : null;
  });

  // Data arrays carry message *keys* (the FAQ pattern) so the markup just t()s
  // them. `as const` keeps the keys literal so they type-check as MessageKeys.
  const features = [
    { icon: Lock, title: 'home.features.noAuth.title', body: 'home.features.noAuth.body' },
    { icon: Globe, title: 'home.features.mirrors.title', body: 'home.features.mirrors.body' },
    {
      icon: Smartphone,
      title: 'home.features.protocols.title',
      body: 'home.features.protocols.body',
    },
  ] as const;

  const steps = [
    { n: 1, title: 'home.how.s1.title', body: 'home.how.s1.body' },
    { n: 2, title: 'home.how.s2.title', body: 'home.how.s2.body' },
    { n: 3, title: 'home.how.s3.title', body: 'home.how.s3.body' },
  ] as const;

  // "What we store" — factual claims about how the system is built (hash-only,
  // no PII, no traffic logs). The strongest trust signal we can give an anxious,
  // surveillance-wary visitor, and copy the org can stand behind without legal
  // sign-off.
  const privacyPoints = [
    'home.privacy.point1',
    'home.privacy.point2',
    'home.privacy.point3',
    'home.privacy.point4',
  ] as const;

  // FAQ — single-open accordion. Answers ride the same catalog as the rest of
  // the page (auto-translated).
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
  ] as const;
  let openFaq = $state(-1);
</script>

<div class="space-y-20 md:space-y-28 pb-12">
  <!-- HERO -->
  <section
    class="grid gap-10 md:grid-cols-[1.2fr_1fr] md:gap-16 items-center pt-8 md:pt-16"
    in:fade={{ duration: 300 }}
  >
    <div class="space-y-6 md:space-y-8" in:fly={{ y: 20, duration: 500, easing: quintOut }}>
      <div
        class="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/5 text-primary px-3 py-1 text-xs font-medium"
      >
        {t('home.hero.eyebrow')}
      </div>

      <h1
        class="text-4xl md:text-6xl font-display font-bold tracking-tight leading-[1.05] bg-gradient-to-br from-foreground to-foreground/70 bg-clip-text text-transparent"
      >
        {t('home.hero.title')}
      </h1>

      <p class="text-lg md:text-xl text-muted-foreground leading-relaxed max-w-xl">
        {t('home.hero.subtitle', { limits: membershipLimits })}
      </p>

      <div class="flex flex-wrap gap-3">
        {#if !me.isPending && me.data?.authenticated}
          <Link href="/account">
            <Button size="lg" class="text-base">
              <SocksIcon class="size-4" />
              {t('nav.account')}
              <ArrowRight class="size-4" />
            </Button>
          </Link>
          {#if billingEnabled}
            <Button size="lg" variant="outline" class="text-base" onclick={goUpgrade}>
              {t('home.cta.getMembership')}
            </Button>
          {/if}
        {:else}
          <Link href="/get-account">
            <Button size="lg" class="text-base">
              <SocksIcon class="size-4" />
              {t('nav.getAccount')}
              <ArrowRight class="size-4" />
            </Button>
          </Link>
          <Link href="/login">
            <Button size="lg" variant="outline" class="text-base">{t('nav.signIn')}</Button>
          </Link>
        {/if}
      </div>
    </div>

    <!--
      Hero card. Earlier versions of this card showed a fake "Subscription
      URL" with a placeholder vless:// string + a green "Subscription ready"
      pip, which was confusing: visitors landing here for the first time
      assumed they'd already been issued something. This version is a
      plain at-a-glance summary of what a free account gets you, labeled
      "Free tier" so the framing is obvious, and a small footnote that
      makes clear the numbers come from the seeded defaults (not a live
      account).
    -->
    <!-- Shown on every viewport: mobile is the majority of our audience, and this
         card is the at-a-glance "what you get" summary they'd otherwise miss. Not
         aria-hidden — the specifics (limits, no-email) are informative. -->
    <div class="relative" in:fly={{ x: 20, duration: 600, delay: 150, easing: quintOut }}>
      <div
        class="absolute inset-0 bg-gradient-to-br from-primary/10 to-transparent rounded-2xl blur-3xl"
      ></div>
      <div
        class="relative rounded-2xl border border-border bg-card/80 backdrop-blur p-6 md:p-7 shadow-2xl space-y-5"
      >
        <div class="flex items-baseline justify-between">
          <h2 class="text-base font-display font-semibold tracking-tight">
            {t('home.freeCard.title')}
          </h2>
          <span
            class="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold rounded bg-secondary px-1.5 py-0.5"
          >
            {t('home.freeCard.badge')}
          </span>
        </div>
        <ul class="space-y-3">
          <li class="flex items-start gap-3">
            <Globe class="size-4 text-primary mt-0.5 shrink-0" />
            <div>
              <p class="text-sm font-medium">{t('home.freeCard.urlTitle')}</p>
              <p class="text-xs text-muted-foreground leading-snug">
                {t('home.freeCard.urlBody')}
              </p>
            </div>
          </li>
          <li class="flex items-start gap-3">
            <Smartphone class="size-4 text-primary mt-0.5 shrink-0" />
            <div>
              <!-- DB-driven; empty until /api/v1/config resolves. A skeleton bar
                   holds the line's place so it doesn't pop in from blank. -->
              {#if freeTierLine}
                <p class="text-sm font-medium tabular-nums">{freeTierLine}</p>
              {:else}
                <Skeleton class="h-5 w-32" />
              {/if}
              <p class="text-xs text-muted-foreground leading-snug">
                {t('home.freeCard.membershipLine', { limits: membershipLimits })}
              </p>
            </div>
          </li>
          <li class="flex items-start gap-3">
            <Lock class="size-4 text-primary mt-0.5 shrink-0" />
            <div>
              <p class="text-sm font-medium">{t('home.freeCard.noAuthTitle')}</p>
              <p class="text-xs text-muted-foreground leading-snug">
                {t('home.freeCard.noAuthBody')}
              </p>
            </div>
          </li>
        </ul>
        <p class="text-[11px] text-muted-foreground leading-snug border-t border-border/60 pt-3">
          {t('home.freeCard.footnote')}
        </p>
        {#if billingEnabled}
          <!-- Upgrade nudge: the free summary stays primary; this footer offers the
               paid tier with a DB-derived price + the existing goUpgrade entry point. -->
          <div class="space-y-2 rounded-xl border border-primary/30 bg-primary/5 p-3">
            <div class="flex items-baseline justify-between gap-2">
              <p class="text-sm font-semibold">{t('home.freeCard.upsellTitle')}</p>
              {#if membershipFromPrice}
                <span class="text-xs font-semibold tabular-nums text-primary">
                  {t('home.freeCard.fromPerMonth', { price: membershipFromPrice })}
                </span>
              {/if}
            </div>
            <p class="text-[11px] text-muted-foreground">{t('home.freeCard.cryptoNote')}</p>
            <p class="text-xs text-muted-foreground leading-snug">
              {t('home.freeCard.upsellBody', { limits: membershipLimits })}
            </p>
            <Button size="sm" class="w-full" onclick={goUpgrade}>
              {t('home.cta.getMembership')}
            </Button>
          </div>
        {/if}
      </div>
    </div>
  </section>

  <!-- FEATURES -->
  <section class="space-y-8">
    <div class="max-w-2xl space-y-2">
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
        {t('home.features.title')}
      </h2>
    </div>
    <div class="grid gap-4 md:grid-cols-3">
      {#each features as f, i (f.title)}
        <div
          class="rounded-xl border border-border bg-card p-5 space-y-2 transition-[transform,box-shadow] duration-200 hover:-translate-y-0.5 hover:shadow-md"
          in:fly={{ y: 16, duration: 400, delay: i * 60, easing: quintOut }}
        >
          <div
            class="inline-flex items-center justify-center rounded-md bg-primary/10 text-primary p-2"
          >
            <f.icon class="size-5" />
          </div>
          <h3 class="text-base font-semibold">{t(f.title)}</h3>
          <p class="text-sm text-muted-foreground leading-relaxed">{t(f.body)}</p>
        </div>
      {/each}
    </div>
  </section>

  <!-- WHAT WE STORE: the privacy reassurance this audience needs, stated plainly. -->
  <section class="space-y-8">
    <div class="max-w-2xl space-y-2">
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
        {t('home.privacy.title')}
      </h2>
      <p class="text-muted-foreground leading-relaxed">
        {t('home.privacy.subtitle')}
      </p>
    </div>
    <ul class="grid gap-4 sm:grid-cols-2">
      {#each privacyPoints as point, i (point)}
        <li
          class="flex items-start gap-3 rounded-xl border border-border bg-card p-5 transition-[transform,box-shadow] duration-200 hover:-translate-y-0.5 hover:shadow-md"
          in:fly={{ y: 16, duration: 400, delay: i * 60, easing: quintOut }}
        >
          <ShieldCheck class="size-5 text-primary mt-0.5 shrink-0" aria-hidden="true" />
          <p class="text-sm text-muted-foreground leading-relaxed">{t(point)}</p>
        </li>
      {/each}
    </ul>
  </section>

  <!-- HOW IT WORKS -->
  <section class="space-y-8">
    <div class="max-w-xl space-y-2">
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
        {t('home.how.title')}
      </h2>
    </div>
    <div class="grid gap-6 md:grid-cols-3 max-w-4xl">
      {#each steps as step, i (step.n)}
        <div
          class="space-y-3 relative"
          in:fly={{ y: 16, duration: 400, delay: i * 100, easing: quintOut }}
        >
          <div
            class="size-10 rounded-full bg-primary/10 text-primary font-display font-bold flex items-center justify-center tabular-nums"
          >
            {step.n}
          </div>
          <h3 class="font-semibold">{t(step.title)}</h3>
          <p class="text-sm text-muted-foreground leading-relaxed">{t(step.body)}</p>
        </div>
      {/each}
    </div>
    <div class="pt-2">
      <Link href="/get-account">
        <Button size="lg">
          {t('home.how.cta')}
          <ArrowRight class="size-4" />
        </Button>
      </Link>
    </div>
  </section>

  <!-- MEMBERSHIP / pricing — only when billing is live (reuses the comparison
       card, which shows "from <price>/mo" + an Upgrade CTA). -->
  {#if billingEnabled}
    <section class="space-y-6">
      <div class="max-w-2xl space-y-2">
        <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
          {t('home.membership.title')}
        </h2>
        <p class="text-muted-foreground leading-relaxed">
          {t('home.membership.lead')}
          {memberTier?.description ?? t('home.membership.descriptionFallback')}
          {t('home.membership.payNote')}
        </p>
      </div>
      <TierComparison currentTierSlug="" onUpgrade={goUpgrade} />
    </section>
  {/if}

  <!-- DONATION IMPACT: what donors' giving is doing for free users right now
       (live bonus + reach + the per-month history as a dithered chart). Renders
       whenever donations are live; before the first donation the chart shows a
       flat zero baseline with the "first one starts the counter" note. All
       numbers are GB / user counts (no dollar figures). -->
  {#if billingEnabled && donation?.enabled}
    <section class="rounded-2xl border border-border bg-card p-6 md:p-10">
      <div class="grid gap-8 md:grid-cols-2 md:items-center">
        <div class="max-w-xl space-y-3">
          <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
            {t('home.impact.title')}
          </h2>
          <p class="text-muted-foreground leading-relaxed">{t('home.impact.body')}</p>
          <div class="flex flex-wrap gap-x-6 gap-y-2 pt-1">
            <div>
              <span
                class="text-xl font-display font-bold tabular-nums text-amber-600 dark:text-amber-300"
                >+{donation.currentBonusGb}</span
              >
              <span class="text-sm text-muted-foreground"> {t('impact.bonusThisMonth')}</span>
            </div>
            <div>
              <span class="text-xl font-display font-bold tabular-nums"
                >{donation.freeUsersHelped.toLocaleString()}</span
              >
              <span class="text-sm text-muted-foreground"> {t('impact.usersHelped')}</span>
            </div>
          </div>
          <div class="pt-2">
            <Button onclick={goDonate}>
              <Heart class="size-4" />
              {t('home.impact.cta')}
            </Button>
          </div>
        </div>
        <div class="donation-sheen rounded-xl border border-amber-500/30 bg-background/60 p-4">
          <DitherChart
            values={impactSeries.map((h) => h.bonusGb)}
            labels={impactSeries.map((h) => h.month)}
            variant="bars"
            height={120}
            ariaLabel={t('home.impact.chartAria')}
          />
          {#if donationHistory.length === 0}
            <p class="mt-2 text-xs text-muted-foreground text-center">{t('impact.empty')}</p>
          {/if}
        </div>
      </div>
    </section>
  {/if}

  <!-- FAQ — single-open accordion, localized like the rest of the page. -->
  <section class="space-y-8">
    <div class="max-w-2xl space-y-2">
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">{t('faq.title')}</h2>
      <p class="text-muted-foreground leading-relaxed">{t('faq.subtitle')}</p>
    </div>
    <ul class="max-w-3xl divide-y divide-border rounded-xl border border-border bg-card">
      {#each FAQ as item, i (item.q)}
        {@const isOpen = openFaq === i}
        <li>
          <button
            type="button"
            id="faq-trigger-{i}"
            class="flex w-full items-center justify-between gap-3 px-5 py-4 text-start text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
            aria-expanded={isOpen}
            aria-controls="faq-panel-{i}"
            onclick={() => (openFaq = isOpen ? -1 : i)}
          >
            <span>{t(item.q)}</span>
            <ChevronDown
              class="size-4 shrink-0 text-muted-foreground transition-transform {isOpen
                ? 'rotate-180'
                : ''}"
              aria-hidden="true"
            />
          </button>
          {#if isOpen}
            <div
              id="faq-panel-{i}"
              role="region"
              aria-labelledby="faq-trigger-{i}"
              class="px-5 pb-4 text-sm leading-relaxed text-muted-foreground"
              transition:slide={{ duration: 180 }}
            >
              {t(item.a)}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  </section>

  <!-- ABOUT: short, factual, no invented programs -->
  <section class="rounded-2xl border border-border bg-card p-6 md:p-10">
    <div class="max-w-2xl space-y-3">
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
        {t('home.about.title')}
      </h2>
      <p class="text-muted-foreground leading-relaxed">
        {t('home.about.bodyPrefix')}{' '}
        <a
          href="https://unredacted.org"
          class="underline hover:text-foreground"
          target="_blank"
          rel="noopener noreferrer">Unredacted</a
        >{t('home.about.bodySuffix')}
      </p>
      <div class="flex flex-wrap gap-3 pt-2">
        <!--
          Donations fund free accounts (hosted on unredacted.org). When billing
          is live, the membership CTA routes to the in-app upgrade panel
          (authed → /account, else create a free account first via /get-account).
        -->
        <a href="https://unredacted.org/donate" target="_blank" rel="noopener noreferrer">
          <Button>
            <Heart class="size-4" />
            {t('renew.donate')}
          </Button>
        </a>
        <a href="https://unredacted.org" target="_blank" rel="noopener noreferrer">
          <Button variant="outline">{t('home.about.siteLink')}</Button>
        </a>
        {#if billingEnabled}
          <Button variant="ghost" onclick={goUpgrade}>{t('home.cta.getMembership')}</Button>
        {/if}
      </div>
    </div>
  </section>
</div>
