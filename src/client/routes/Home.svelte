<script lang="ts">
  /**
   * Main landing page for FreeSocks. This deployment IS the primary public
   * surface for the service: what was formerly a separate "marketing site"
   * has been folded in here, so there's no upstream to defer to.
   *
   * Voice principle: factual, plain. No invented stats, no marketing
   * flourishes, no claims about Unredacted's other programs (we link to
   * unredacted.org for that; they own that copy, not us).
   */
  import Link from '../components/Link.svelte';
  import { Button } from '@client/components/ui/button';
  import TierComparison from '../components/TierComparison.svelte';
  import { meQuery, configQuery } from '../lib/queries';
  import { membershipTier, limitsPhrase } from '../lib/tiers';
  import { t } from '../lib/i18n/index.svelte';
  import { router } from '../stores/router.svelte';
  import { fly, fade, slide } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import KeyIcon from '@lucide/svelte/icons/key-round';
  import Lock from '@lucide/svelte/icons/lock';
  import Globe from '@lucide/svelte/icons/globe';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ArrowRight from '@lucide/svelte/icons/arrow-right';
  import Heart from '@lucide/svelte/icons/heart';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';

  const me = meQuery();
  const config = configQuery();

  // The membership upgrade entry point: an authed member goes straight to their
  // account (the upgrade panel); an anon visitor creates a free account first.
  const billingEnabled = $derived(config.data?.billing?.enabled ?? false);
  function goUpgrade() {
    router.navigate(me.data?.authenticated ? '/account' : '/get-account');
  }

  // Live free-tier limits from /api/v1/config (the DB-enforced numbers), with
  // the seed values as a fallback while config loads.
  const freeTier = $derived(config.data?.tiers.find((t) => t.slug === 'free'));
  const freeTierLine = $derived(
    freeTier
      ? `${freeTier.deviceLimit} device${freeTier.deviceLimit === 1 ? '' : 's'} · ${
          freeTier.monthlyTrafficGb === 0 ? 'Unlimited' : `${freeTier.monthlyTrafficGb} GB / month`
        }`
      : '',
  );

  // Paid-tier limits, DB-driven: drives the membership prose below so it never
  // contradicts the admin-set tier. `description` is the admin-editable line;
  // `membershipLimits` is computed from the tier's monthlyTrafficGb/deviceLimit.
  const memberTier = $derived(membershipTier(config.data));
  const membershipLimits = $derived(limitsPhrase(memberTier));

  const features = [
    {
      icon: Lock,
      title: 'No email or password',
      body: 'One human-check and you are in. We mint a 32-digit account number you save to sign back in. No email collected.',
    },
    {
      icon: Globe,
      title: 'Mirror URLs',
      body: 'Subscriptions are mirrored across multiple providers so a single block does not cut you off.',
    },
    {
      icon: Smartphone,
      title: 'Standard protocols',
      body: 'Xray-powered VLESS / Trojan / Shadowsocks. Works in most VPN clients.',
    },
  ];

  const steps = [
    {
      n: 1,
      title: 'Create a free account',
      body: 'Solve a quick human-check. You get a 32-digit account number to save: it is how you sign back in.',
    },
    {
      n: 2,
      title: 'Create your subscription',
      body: 'Once you are signed in, create a subscription URL, with a QR code for handoff to a phone.',
    },
    {
      n: 3,
      title: 'Paste it into a VPN client',
      body: 'Add the URL as a subscription in any compatible client.',
    },
  ];

  // "What we store" — factual claims about how the system is built (hash-only,
  // no PII, no traffic logs). The strongest trust signal we can give an anxious,
  // surveillance-wary visitor, and copy the org can stand behind without legal
  // sign-off. English-only, like the rest of this landing page.
  const privacyPoints = [
    'We store only a hashed version of your account number — never the number itself.',
    'No email, phone number, or name. We never ask for them.',
    'No logs of the sites you visit or the traffic you send.',
  ];

  // FAQ — the one i18n'd section on this otherwise English-only page: the answers
  // are exactly what non-English visitors need, so they ride the Paraglide
  // catalog (auto-translated). Single-open accordion.
  const FAQ = [
    { q: 'faq.q1.question', a: 'faq.q1.answer' },
    { q: 'faq.q2.question', a: 'faq.q2.answer' },
    { q: 'faq.q3.question', a: 'faq.q3.answer' },
    { q: 'faq.q4.question', a: 'faq.q4.answer' },
    { q: 'faq.q5.question', a: 'faq.q5.answer' },
    { q: 'faq.q6.question', a: 'faq.q6.answer' },
    { q: 'faq.q7.question', a: 'faq.q7.answer' },
    { q: 'faq.q8.question', a: 'faq.q8.answer' },
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
        class="inline-flex items-center gap-2 rounded-full border border-border bg-card text-muted-foreground px-3 py-1 text-xs font-medium"
      >
        Operated by Unredacted, a US 501(c)(3) nonprofit
      </div>

      <h1 class="text-4xl md:text-6xl font-display font-bold tracking-tight leading-[1.05]">
        Free proxies for users in heavily-censored regions.
      </h1>

      <p class="text-lg md:text-xl text-muted-foreground leading-relaxed max-w-xl">
        Create a free account with one human-check, then get a subscription URL for any modern VPN
        client. No email or password. A FreeSocks membership unlocks {membershipLimits}.
      </p>

      <div class="flex flex-wrap gap-3">
        {#if !me.isPending && me.data?.authenticated}
          <Link href="/account">
            <Button size="lg" class="text-base">
              <KeyIcon class="size-4" />
              My account
              <ArrowRight class="size-4" />
            </Button>
          </Link>
          {#if billingEnabled}
            <Button size="lg" variant="outline" class="text-base" onclick={goUpgrade}>
              Get a membership
            </Button>
          {/if}
        {:else}
          <Link href="/get-account">
            <Button size="lg" class="text-base">
              <KeyIcon class="size-4" />
              Get a free account
              <ArrowRight class="size-4" />
            </Button>
          </Link>
          <Link href="/login">
            <Button size="lg" variant="outline" class="text-base">Sign in</Button>
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
          <h2 class="text-base font-display font-semibold tracking-tight">Free tier</h2>
          <span
            class="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold rounded bg-secondary px-1.5 py-0.5"
          >
            What you get
          </span>
        </div>
        <ul class="space-y-3">
          <li class="flex items-start gap-3">
            <Globe class="size-4 text-primary mt-0.5 shrink-0" />
            <div>
              <p class="text-sm font-medium">Xray subscription URL</p>
              <p class="text-xs text-muted-foreground leading-snug">
                Multi-protocol (VLESS / Trojan / Shadowsocks). Paste into any compatible client.
              </p>
            </div>
          </li>
          <li class="flex items-start gap-3">
            <Smartphone class="size-4 text-primary mt-0.5 shrink-0" />
            <div>
              <p class="text-sm font-medium tabular-nums">{freeTierLine}</p>
              <p class="text-xs text-muted-foreground leading-snug">
                A FreeSocks membership gives you {membershipLimits}.
              </p>
            </div>
          </li>
          <li class="flex items-start gap-3">
            <Lock class="size-4 text-primary mt-0.5 shrink-0" />
            <div>
              <p class="text-sm font-medium">No email or password</p>
              <p class="text-xs text-muted-foreground leading-snug">
                One human-check. Save your account number to sign in. No email collected.
              </p>
            </div>
          </li>
        </ul>
        <p class="text-[11px] text-muted-foreground leading-snug border-t border-border/60 pt-3">
          Numbers reflect the current free-tier configuration. Solve the check to get yours.
        </p>
      </div>
    </div>
  </section>

  <!-- FEATURES -->
  <section class="space-y-8">
    <div class="max-w-2xl space-y-2">
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">What FreeSocks is</h2>
    </div>
    <div class="grid gap-4 md:grid-cols-3">
      {#each features as f, i (f.title)}
        <div
          class="rounded-xl border border-border bg-card p-5 space-y-2"
          in:fly={{ y: 16, duration: 400, delay: i * 60, easing: quintOut }}
        >
          <div
            class="inline-flex items-center justify-center rounded-md bg-primary/10 text-primary p-2"
          >
            <f.icon class="size-5" />
          </div>
          <h3 class="text-base font-semibold">{f.title}</h3>
          <p class="text-sm text-muted-foreground leading-relaxed">{f.body}</p>
        </div>
      {/each}
    </div>
  </section>

  <!-- WHAT WE STORE: the privacy reassurance this audience needs, stated plainly. -->
  <section class="space-y-8">
    <div class="max-w-2xl space-y-2">
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">What we store</h2>
      <p class="text-muted-foreground leading-relaxed">
        FreeSocks is built to know as little about you as possible.
      </p>
    </div>
    <ul class="grid gap-4 md:grid-cols-3">
      {#each privacyPoints as point, i (point)}
        <li
          class="flex items-start gap-3 rounded-xl border border-border bg-card p-5"
          in:fly={{ y: 16, duration: 400, delay: i * 60, easing: quintOut }}
        >
          <ShieldCheck class="size-5 text-primary mt-0.5 shrink-0" aria-hidden="true" />
          <p class="text-sm text-muted-foreground leading-relaxed">{point}</p>
        </li>
      {/each}
    </ul>
  </section>

  <!-- HOW IT WORKS -->
  <section class="space-y-8">
    <div class="max-w-xl space-y-2">
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">How it works</h2>
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
          <h3 class="font-semibold">{step.title}</h3>
          <p class="text-sm text-muted-foreground leading-relaxed">{step.body}</p>
        </div>
      {/each}
    </div>
    <div class="pt-2">
      <Link href="/get-account">
        <Button size="lg">
          Try it now
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
        <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">Membership</h2>
        <p class="text-muted-foreground leading-relaxed">
          Free covers the basics. {memberTier?.description ??
            'A FreeSocks membership lifts every limit.'}
          Pay with crypto (Monero & more), card, or PayPal.
        </p>
      </div>
      <TierComparison currentTierSlug="" onUpgrade={goUpgrade} />
    </section>
  {/if}

  <!-- FAQ — DB-of-record is the Paraglide catalog (auto-translated), so this is
       the one localized section on the page. Single-open accordion. -->
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
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">About</h2>
      <p class="text-muted-foreground leading-relaxed">
        FreeSocks is operated by{' '}
        <a
          href="https://unredacted.org"
          class="underline hover:text-foreground"
          target="_blank"
          rel="noopener noreferrer">Unredacted</a
        >, a US 501(c)(3) nonprofit. Free accounts are funded by donations and paying members.
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
            Donate
          </Button>
        </a>
        <a href="https://unredacted.org" target="_blank" rel="noopener noreferrer">
          <Button variant="outline">unredacted.org</Button>
        </a>
        {#if billingEnabled}
          <Button variant="ghost" onclick={goUpgrade}>Get a membership</Button>
        {/if}
      </div>
    </div>
  </section>
</div>
