<script lang="ts">
  /**
   * Main landing page for FreeSocks. This deployment IS the primary public
   * surface for the service — what was formerly a separate "marketing site"
   * has been folded in here, so there's no upstream to defer to.
   *
   * Voice principle: factual, plain. No invented stats, no marketing
   * flourishes, no claims about Unredacted's other programs (we link to
   * unredacted.org for that — they own that copy, not us).
   */
  import Link from '../components/Link.svelte';
  import { Button } from '@client/components/ui/button';
  import { meQuery, configQuery } from '../lib/queries';
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
      title: 'No signup',
      body: 'A Turnstile human-check is the entire onboarding. No email, no account.',
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
      title: 'Solve a quick check',
      body: 'A Turnstile widget loads to confirm you are human.',
    },
    {
      n: 2,
      title: 'Get a subscription URL',
      body: 'A subscription URL is issued, with a QR code for handoff to a phone.',
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
        Get a subscription URL with no signup. Paste it into any modern VPN client. Higher tiers
        exist for users who want more bandwidth and more devices.
      </p>

      <div class="flex flex-wrap gap-3">
        <Link href="/get-key">
          <Button size="lg" class="text-base">
            <KeyIcon class="size-4" />
            Get a free key
            <ArrowRight class="size-4" />
          </Button>
        </Link>
        {#if !me.isPending && me.data?.authenticated}
          <Link href="/account">
            <Button size="lg" variant="outline" class="text-base">My account</Button>
          </Link>
        {:else}
          <Link href="/login">
            <Button size="lg" variant="outline" class="text-base">Sign in</Button>
          </Link>
        {/if}
      </div>
    </div>

    <!--
      Hero card. Earlier versions of this card showed a fake "Subscription
      URL" with a placeholder vless:// string + a green "Subscription ready"
      pip, which was confusing — visitors landing here for the first time
      assumed they'd already been issued something. This version is a
      plain at-a-glance summary of what a free key gets you, labeled
      "Free tier" so the framing is obvious, and a small footnote that
      makes clear the numbers come from the seeded defaults (not a live
      account).
    -->
    <div
      class="hidden md:block relative"
      in:fly={{ x: 20, duration: 600, delay: 150, easing: quintOut }}
      aria-hidden="true"
    >
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
                Higher tiers raise these (coming soon).
              </p>
            </div>
          </li>
          <li class="flex items-start gap-3">
            <Lock class="size-4 text-primary mt-0.5 shrink-0" />
            <div>
              <p class="text-sm font-medium">No account</p>
              <p class="text-xs text-muted-foreground leading-snug">
                One human-check, key in hand. No email collected.
              </p>
            </div>
          </li>
        </ul>
        <p class="text-[11px] text-muted-foreground/70 leading-snug border-t border-border/60 pt-3">
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
      <Link href="/get-key">
        <Button size="lg">
          Try it now
          <ArrowRight class="size-4" />
        </Button>
      </Link>
    </div>
  </section>

  <!-- ABOUT — short, factual, no invented programs -->
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
        >, a US 501(c)(3) nonprofit. Free keys are funded by donations and paying members.
      </p>
      <div class="flex flex-wrap gap-3 pt-2">
        <!--
          Donate is the primary "give back" CTA right now — membership signup
          isn't wired end-to-end yet (the in-house billing portal is still
          being designed), so we lead with donations and mark Membership as
          coming-soon. Donation flow is hosted on unredacted.org and works
          today.
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
        <Button
          variant="ghost"
          disabled
          aria-disabled="true"
          title="Membership signup is coming soon"
        >
          Membership (coming soon)
        </Button>
      </div>
    </div>
  </section>
</div>
