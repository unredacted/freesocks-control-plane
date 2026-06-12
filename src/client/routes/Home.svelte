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
  import { router } from '../stores/router.svelte';
  import { fly, fade } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import KeyIcon from '@lucide/svelte/icons/key-round';
  import Lock from '@lucide/svelte/icons/lock';
  import Globe from '@lucide/svelte/icons/globe';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ArrowRight from '@lucide/svelte/icons/arrow-right';
  import Heart from '@lucide/svelte/icons/heart';

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
      : '1 device · 50 GB / month',
  );

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
        client. No email or password. A FreeSocks membership unlocks unlimited bandwidth and
        devices.
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
                A FreeSocks membership makes these unlimited.
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
          Free covers the basics. A FreeSocks membership lifts every limit — unlimited bandwidth and
          devices — and you can pay with crypto (Monero & more), card, or PayPal.
        </p>
      </div>
      <TierComparison currentTierSlug="" onUpgrade={goUpgrade} />
    </section>
  {/if}

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
