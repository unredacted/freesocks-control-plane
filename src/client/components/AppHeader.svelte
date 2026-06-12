<script lang="ts">
  import Link from './Link.svelte';
  import ThemeToggle from './ThemeToggle.svelte';
  import LanguageSwitcher from './LanguageSwitcher.svelte';
  import { Button } from '@client/components/ui/button';
  import { meQuery, configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import KeyIcon from '@lucide/svelte/icons/key-round';
  import User from '@lucide/svelte/icons/user-round';
  import LogIn from '@lucide/svelte/icons/log-in';
  import Heart from '@lucide/svelte/icons/heart';

  // TanStack query, fetched once on first render, cached across the SPA,
  // refetched on window focus (so the user gets fresh tier info when they
  // come back from a payment tab once the membership flow is live).
  const me = meQuery();
  const config = configQuery();

  let isFreeTierMember = $derived(!!me.data?.authenticated && me.data.member?.tier.slug === 'free');
  let billingEnabled = $derived(config.data?.billing?.enabled ?? false);
</script>

<header class="border-b border-border bg-background/80 backdrop-blur sticky top-0 z-10">
  <div class="container mx-auto px-4 py-3 flex items-center justify-between">
    <Link
      href="/"
      class="font-display text-xl font-bold tracking-tight flex items-center gap-2"
      aria-label="FreeSocks home"
    >
      <span
        class="inline-flex items-center justify-center size-7 rounded-md bg-primary text-primary-foreground"
        aria-hidden="true"
      >
        <KeyIcon class="size-4" />
      </span>
      FreeSocks
    </Link>
    <nav class="flex items-center gap-2">
      {#if !me.isPending && me.data?.authenticated}
        <!-- Signed in: account-relevant CTAs only (no "Get a free account"). -->
        {#if isFreeTierMember && billingEnabled}
          <!-- Free-tier member + billing live: route to the in-app upgrade panel. -->
          <Link href="/account">
            <Button variant="outline" size="sm" class="hidden sm:inline-flex">
              <Heart class="size-4" />
              Membership
            </Button>
          </Link>
        {/if}
        <Link href="/account">
          <Button variant="default" size="sm">
            <User class="size-4" />
            <span class="hidden sm:inline">{t('nav.account')}</span>
          </Button>
        </Link>
      {:else}
        <Link href="/get-account">
          <Button variant="ghost" size="sm">
            <KeyIcon class="size-4" />
            <span class="hidden sm:inline">{t('nav.getAccount')}</span>
          </Button>
        </Link>
        <Link href="/login">
          <Button variant="outline" size="sm">
            <LogIn class="size-4" />
            {t('nav.signIn')}
          </Button>
        </Link>
      {/if}
      <LanguageSwitcher />
      <ThemeToggle />
    </nav>
  </div>
</header>
