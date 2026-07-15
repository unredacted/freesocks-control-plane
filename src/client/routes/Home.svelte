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
  import * as Tabs from '@client/components/ui/tabs';
  import TierComparison from '../components/TierComparison.svelte';
  import NetworkStatus from '../components/NetworkStatus.svelte';
  import CountUp from '../components/CountUp.svelte';
  import { reveal } from '../lib/actions/reveal';
  import { meQuery, configQuery } from '../lib/queries';
  import { membershipTier, tierLimits, deviceLimitsShown, type TierLimits } from '../lib/tiers';
  import { baselinePerMonth } from '../lib/billing';
  import { t, type MessageKey } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';
  import { router } from '../stores/router.svelte';
  import { fly, fade, slide } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import SocksIcon from '../components/SocksIcon.svelte';
  import Landmark from '@lucide/svelte/icons/landmark';
  import Lock from '@lucide/svelte/icons/lock';
  import Globe from '@lucide/svelte/icons/globe';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ArrowRight from '@lucide/svelte/icons/arrow-right';
  import Heart from '@lucide/svelte/icons/heart';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import CodeXml from '@lucide/svelte/icons/code-xml';
  import DitherChart from '../components/DitherChart.svelte';
  import { impactChartSeries } from '../lib/impact';

  const me = meQuery();
  const config = configQuery();

  // The membership upgrade entry point: an authed member goes straight to their
  // account (the upgrade panel); an anon visitor creates a free account first.
  const billingEnabled = $derived(config.data?.billing?.enabled ?? false);
  // Admin-configured site chrome; the ABOUT open-source callout renders only when
  // the footer "View source" repo link is enabled (same toggle + URL).
  const site = $derived(config.data?.site);
  function goUpgrade() {
    router.navigate(me.data?.authenticated ? '/account' : '/get-account');
  }

  // Donation impact (GB + user counts only - no dollar figures on the public
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
  // In-page anchors (hero callout + quick-nav chips). Smooth only when the user
  // hasn't asked for reduced motion (JS scrolls bypass the CSS clamp).
  function scrollToId(id: string) {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    document.getElementById(id)?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth' });
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
  // monthly), DB-driven + locale-formatted - mirrors TierComparison's "from $X/mo".
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

  // FAQ - single-open accordion. Answers ride the same catalog as the rest of
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

  // The two FAQ groups share one tabbed section; a #threat-model deep link
  // lands on the threat tab directly.
  let faqTab = $state(window.location.hash === '#threat-model' ? 'threat' : 'general');

  // Section kickers: a short accent bar + small label above each heading.
  const SECTION_LABELS = {
    features: 'home.sections.features',
    privacy: 'home.sections.privacy',
    how: 'home.sections.how',
    membership: 'home.sections.membership',
    impact: 'home.sections.impact',
    faq: 'home.sections.faq',
    about: 'home.sections.about',
  } as const satisfies Record<string, MessageKey>;
  type SectionId = keyof typeof SECTION_LABELS;

  // Count-up trigger: the impact stats animate once the section scrolls into view.
  let impactRevealed = $state(false);
</script>

{#snippet eyebrow(id: SectionId)}
  <div class="flex items-center gap-2.5">
    <span class="h-0.5 w-6 rounded-full bg-primary" aria-hidden="true"></span>
    <p class="text-xs font-semibold uppercase tracking-wide text-primary">
      {t(SECTION_LABELS[id])}
    </p>
  </div>
{/snippet}

{#snippet accordion(items: readonly { q: MessageKey; a: MessageKey }[], prefix: 'faq' | 'tm')}
  <ul class="max-w-3xl divide-y divide-border rounded-xl border border-border bg-card">
    {#each items as item, i (item.q)}
      {@const isOpen = (prefix === 'faq' ? openFaq : openThreat) === i}
      <li>
        <button
          type="button"
          id="{prefix}-trigger-{i}"
          class="flex w-full items-center justify-between gap-3 px-5 py-4 text-start text-sm font-medium transition-colors hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
          aria-expanded={isOpen}
          aria-controls="{prefix}-panel-{i}"
          onclick={() => {
            const next = isOpen ? -1 : i;
            if (prefix === 'faq') openFaq = next;
            else openThreat = next;
          }}
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
            id="{prefix}-panel-{i}"
            role="region"
            aria-labelledby="{prefix}-trigger-{i}"
            class="px-5 pb-4 text-sm leading-relaxed text-muted-foreground"
            transition:slide={{ duration: 180 }}
          >
            {t(item.a)}
          </div>
        {/if}
      </li>
    {/each}
  </ul>
{/snippet}

<div class="space-y-20 md:space-y-28 pb-12">
  <!-- HERO -->
  <section
    class="relative grid gap-10 md:grid-cols-[1.2fr_1fr] md:gap-16 items-center pt-8 md:pt-16"
    in:fade={{ duration: 300 }}
  >
    <!-- Ambient brand glow + dither dot grid behind the headline (pure CSS, static). -->
    <div class="hero-glow absolute -inset-x-6 -top-8 bottom-0 -z-10" aria-hidden="true"></div>
    <div
      class="dot-grid absolute -inset-x-6 -top-8 bottom-0 -z-10 opacity-40 dark:opacity-25"
      aria-hidden="true"
    ></div>
    <div class="space-y-6 md:space-y-8" in:fly={{ y: 20, duration: 500, easing: quintOut }}>
      <h1 class="text-4xl md:text-6xl font-display font-bold tracking-tight leading-[1.05]">
        {t('home.hero.title')}
      </h1>

      <p class="text-lg md:text-xl text-muted-foreground leading-relaxed max-w-xl">
        {t('home.hero.subtitle', { limits: membershipLimits })}
      </p>

      <!-- Social-impact callout: what makes this VPN different - donations made
           in-app buy bandwidth for every free user that month. Links down to the
           live impact section. Renders only while donations are live. -->
      {#if billingEnabled && donation?.enabled}
        <div
          class="donation-sheen max-w-xl rounded-lg border border-amber-500/40 bg-amber-500/5 px-4 py-3 text-sm leading-relaxed"
        >
          <Heart
            class="inline size-3.5 -mt-0.5 me-1.5 text-amber-600 dark:text-amber-300"
            aria-hidden="true"
          />{t('home.hero.impactNote')}
          <button
            type="button"
            class="ms-1.5 rounded-sm font-medium underline text-amber-700 dark:text-amber-300 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            onclick={() => scrollToId('impact')}
          >
            {t('home.hero.impactLink')}
          </button>
        </div>
      {/if}

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

      <!-- Trust row: the strongest verifiable facts at the decision point, not
           buried at the bottom of the page. -->
      <ul class="flex flex-wrap gap-x-5 gap-y-2 pt-1 text-xs text-muted-foreground">
        <li class="inline-flex items-center gap-1.5">
          <Landmark class="size-3.5 text-primary" aria-hidden="true" />
          {t('home.trust.nonprofit')}
        </li>
        {#if site?.repoEnabled && site.repoUrl}
          <li class="inline-flex items-center gap-1.5">
            <CodeXml class="size-3.5 text-primary" aria-hidden="true" />
            <a
              class="underline hover:text-foreground"
              href={site.repoUrl}
              target="_blank"
              rel="noopener noreferrer">{t('home.trust.openSource')}</a
            >
          </li>
        {/if}
        <li class="inline-flex items-center gap-1.5">
          <ShieldCheck class="size-3.5 text-primary" aria-hidden="true" />
          {t('home.trust.noLogs')}
        </li>
      </ul>

      <!-- Quick-nav: the page is long and the content a cautious visitor needs
           most (threat model, privacy) is many viewports down. -->
      <nav class="flex flex-wrap gap-2" aria-label={t('home.quicknav.label')}>
        <button
          type="button"
          class="rounded-full border border-border bg-card px-3 py-1 text-xs text-muted-foreground transition-colors hover:text-foreground hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          onclick={() => scrollToId('privacy')}
        >
          {t('home.quicknav.privacy')}
        </button>
        <button
          type="button"
          class="rounded-full border border-border bg-card px-3 py-1 text-xs text-muted-foreground transition-colors hover:text-foreground hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          onclick={() => {
            faqTab = 'threat';
            scrollToId('threat-model');
          }}
        >
          {t('home.quicknav.threat')}
        </button>
        <button
          type="button"
          class="rounded-full border border-border bg-card px-3 py-1 text-xs text-muted-foreground transition-colors hover:text-foreground hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          onclick={() => scrollToId('faq')}
        >
          {t('home.quicknav.faq')}
        </button>
        {#if billingEnabled && donation?.enabled}
          <button
            type="button"
            class="rounded-full border border-border bg-card px-3 py-1 text-xs text-muted-foreground transition-colors hover:text-foreground hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            onclick={() => scrollToId('impact')}
          >
            {t('home.quicknav.impact')}
          </button>
        {/if}
      </nav>
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
         aria-hidden - the specifics (limits, no-email) are informative. -->
    <div class="relative" in:fly={{ x: 20, duration: 600, delay: 150, easing: quintOut }}>
      <div class="rounded-2xl border border-border bg-card p-6 md:p-7 shadow-sm space-y-5">
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

  <!-- LIVE NETWORK STATUS: transparent, verifiable, live data (hides when no
       located instances exist). -->
  <NetworkStatus />

  <!-- FEATURES -->
  <section class="space-y-8">
    <div class="max-w-2xl space-y-2">
      {@render eyebrow('features')}
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
        {t('home.features.title')}
      </h2>
    </div>
    <div class="grid gap-4 md:grid-cols-3">
      {#each features as f, i (f.title)}
        <div
          class="rounded-xl border border-border bg-card p-5 space-y-2 transition-colors hover:border-primary/40"
          use:reveal
          style="--reveal-delay: {i * 60}ms"
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
  <section id="privacy" class="scroll-mt-24 space-y-8">
    <div class="max-w-2xl space-y-2">
      {@render eyebrow('privacy')}
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
          class="flex items-start gap-3 rounded-xl border border-border bg-card p-5 transition-colors hover:border-primary/40"
          use:reveal
          style="--reveal-delay: {i * 60}ms"
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
      {@render eyebrow('how')}
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
        {t('home.how.title')}
      </h2>
    </div>
    <div class="grid gap-6 md:grid-cols-3 max-w-4xl">
      {#each steps as step, i (step.n)}
        <div class="space-y-3 relative" use:reveal style="--reveal-delay: {i * 100}ms">
          <div
            class="size-10 rounded-full bg-primary/10 ring-1 ring-primary/25 text-primary font-display font-bold flex items-center justify-center tabular-nums"
          >
            {step.n}
            {#if i < steps.length - 1}
              <!-- Dashed connector to the next step, positioned against the step
                   wrapper (relative); logical offsets mirror in RTL. -->
              <div
                class="hidden md:block absolute top-5 start-12 -end-3 border-t border-dashed border-border"
                aria-hidden="true"
              ></div>
            {/if}
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

  <!-- MEMBERSHIP / pricing - only when billing is live (reuses the comparison
       card, which shows "from <price>/mo" + an Upgrade CTA). -->
  {#if billingEnabled}
    <section class="space-y-6">
      <div class="max-w-2xl space-y-2">
        {@render eyebrow('membership')}
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
    <!-- Full-bleed warm band (breaks out of the container's px-4): the one
         donor-facing gold interlude between the emerald service sections. -->
    <section
      id="impact"
      class="scroll-mt-24 -mx-4 px-4 py-10 md:py-12 border-y border-amber-500/20 bg-gradient-to-b from-amber-500/[0.05] to-transparent"
      use:reveal={{ onReveal: () => (impactRevealed = true) }}
    >
      <div class="grid gap-8 md:grid-cols-2 md:items-center">
        <div class="max-w-xl space-y-3">
          {@render eyebrow('impact')}
          <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
            {t('home.impact.title')}
          </h2>
          <p class="text-muted-foreground leading-relaxed">{t('home.impact.body')}</p>
          <div class="flex flex-wrap gap-x-6 gap-y-2 pt-1">
            <div>
              <span
                class="text-xl font-display font-bold tabular-nums text-amber-600 dark:text-amber-300"
                >+<CountUp value={donation.currentBonusGb} start={impactRevealed} /></span
              >
              <span class="text-sm text-muted-foreground"> {t('impact.bonusThisMonth')}</span>
            </div>
            <div>
              <span class="text-xl font-display font-bold tabular-nums"
                ><CountUp value={donation.freeUsersHelped} start={impactRevealed} /></span
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
          <!-- Only in-app donations feed the counter; direct nonprofit gifts don't. -->
          <p class="text-xs text-muted-foreground leading-relaxed">
            {t('impact.externalNote')}
          </p>
        </div>
        <!-- Soft warm glow anchors the chart as the band's focal point. -->
        <div
          class="donation-sheen rounded-xl border border-amber-500/30 bg-background/60 p-4 shadow-[0_0_70px_-12px_rgba(245,158,11,0.45)]"
        >
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

  <!-- FAQ - one tabbed section: the general basics plus the threat model (what
       this service can and cannot protect against; deliberately honest, since
       overclaiming security gets people hurt). Both tabs are single-open
       accordions with separate state + id prefix. A #threat-model deep link
       (or the hero quick-nav chip) lands on the threat tab. -->
  <section id="faq" class="scroll-mt-24 space-y-8">
    <div id="threat-model" class="scroll-mt-24 max-w-2xl space-y-2">
      {@render eyebrow('faq')}
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">{t('faq.title')}</h2>
      <p class="text-muted-foreground leading-relaxed">{t('faq.subtitle')}</p>
    </div>
    <Tabs.Root bind:value={faqTab} class="gap-6">
      <Tabs.List class="w-full min-w-max sm:w-fit h-12 sm:h-9">
        <Tabs.Trigger value="general" class="h-11 sm:h-7">
          {t('faq.tabGeneral')}
        </Tabs.Trigger>
        <Tabs.Trigger value="threat" class="h-11 sm:h-7">
          <ShieldCheck class="size-4" aria-hidden="true" />
          {t('faq.tabThreat')}
        </Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content value="general">
        {@render accordion(FAQ, 'faq')}
      </Tabs.Content>
      <Tabs.Content value="threat">
        <div class="space-y-4">
          <p class="max-w-2xl text-sm text-muted-foreground leading-relaxed">
            {t('threat.subtitle')}
          </p>
          {@render accordion(THREAT_FAQ, 'tm')}
        </div>
      </Tabs.Content>
    </Tabs.Root>
    {#if site?.supportEmail}
      <p class="text-sm text-muted-foreground">
        {t('faq.contactPrefix')}
        <a class="text-primary underline" href="mailto:{site.supportEmail}">
          {site.supportEmail}
        </a>
        {t('faq.contactSuffix')}
      </p>
    {/if}
  </section>

  <!-- ABOUT: short, factual, no invented programs. Two columns: the story +
       CTAs on the left, fact rows on the right. The operator/nonprofit line
       appears once (the body); the fact rows carry what the body doesn't. -->
  <section>
    <div class="rounded-2xl border border-border bg-card p-6 md:p-10">
      <div class="grid gap-8 md:grid-cols-[1.2fr_1fr] md:items-center">
        <div class="max-w-2xl space-y-3">
          {@render eyebrow('about')}
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
            {#if site?.repoEnabled && site.repoUrl}
              <a href={site.repoUrl} target="_blank" rel="noopener noreferrer">
                <Button variant="outline">
                  <CodeXml class="size-4" />
                  {t('home.about.viewSourceCta')}
                </Button>
              </a>
            {/if}
            {#if billingEnabled}
              <Button variant="ghost" onclick={goUpgrade}>{t('home.cta.getMembership')}</Button>
            {/if}
          </div>
        </div>
        <ul class="space-y-5 md:border-s md:border-border md:ps-8">
          {#if site?.repoEnabled && site.repoUrl}
            <li class="flex items-start gap-3">
              <CodeXml class="size-4 text-primary mt-0.5 shrink-0" aria-hidden="true" />
              <div>
                <p class="text-sm font-semibold">{t('home.about.fact2Title')}</p>
                <p class="text-sm text-muted-foreground leading-relaxed">
                  {t('home.about.openSource')}
                </p>
              </div>
            </li>
          {/if}
          <li class="flex items-start gap-3">
            <Heart class="size-4 text-primary mt-0.5 shrink-0" aria-hidden="true" />
            <div>
              <p class="text-sm font-semibold">{t('home.about.fact3Title')}</p>
              <p class="text-sm text-muted-foreground leading-relaxed">
                {t('home.about.fact3Body')}
              </p>
            </div>
          </li>
        </ul>
      </div>
    </div>
  </section>
</div>
