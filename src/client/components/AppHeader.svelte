<script lang="ts">
  import Link from './Link.svelte';
  import { Skeleton } from '@client/components/ui/skeleton';
  import ThemeToggle from './ThemeToggle.svelte';
  import LanguageSwitcher from './LanguageSwitcher.svelte';
  import E2eeBadge from './E2eeBadge.svelte';
  import { Button } from '@client/components/ui/button';
  import { meQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import { router } from '../stores/router.svelte';
  import { slide } from 'svelte/transition';
  import SocksIcon from './SocksIcon.svelte';
  import User from '@lucide/svelte/icons/user-round';
  import LogIn from '@lucide/svelte/icons/log-in';
  import Menu from '@lucide/svelte/icons/menu';
  import X from '@lucide/svelte/icons/x';

  // TanStack query, fetched once on first render, cached across the SPA.
  const me = meQuery();

  // Mobile accordion: on narrow viewports the bar keeps only the logo + the
  // E2EE (HPKE) badge + a menu toggle; everything else lives in a full-width,
  // fully-LABELED panel below. The old icon-only row was too condensed to tell
  // the controls apart. Desktop (sm+) keeps the inline nav.
  let menuOpen = $state(false);
  const closeMenu = () => (menuOpen = false);
  // Close on any route change too (covers back/forward, not just link taps).
  $effect(() => {
    void router.pathname;
    menuOpen = false;
  });
</script>

<header class="border-b border-border bg-background/80 backdrop-blur sticky top-0 z-10">
  <div class="container mx-auto px-4 py-3 flex items-center justify-between gap-2">
    <Link
      href="/"
      class="group font-display text-xl font-bold tracking-tight flex items-center gap-2"
      aria-label={t('nav.home')}
      onclick={closeMenu}
    >
      <span
        class="inline-flex items-center justify-center size-7 rounded-md bg-primary text-primary-foreground transition-transform group-hover:scale-105"
        aria-hidden="true"
      >
        <SocksIcon class="size-4" />
      </span>
      FreeSocks
    </Link>

    <!-- Desktop: the inline nav, unchanged. -->
    <nav class="hidden sm:flex items-center gap-2">
      <E2eeBadge />
      {#if me.isPending}
        <!-- Neutral placeholder while the auth check resolves: rendering the
             signed-out CTAs here flashed "Sign in" at authenticated users on
             every hard load. -->
        <Skeleton class="h-9 w-40 rounded-md" />
      {:else if me.data?.authenticated}
        <!-- Signed in: a single account CTA. The account page itself leads with
             the membership upsell for free-tier members, so a separate
             "Membership" button here would just be a second link to /account. -->
        <Link href="/account">
          <Button variant="default" size="sm" aria-label={t('nav.account')}>
            <User class="size-4" />
            {t('nav.account')}
          </Button>
        </Link>
      {:else}
        <Link href="/get-account">
          <Button variant="ghost" size="sm" aria-label={t('nav.getAccount')}>
            <SocksIcon class="size-4" />
            {t('nav.getAccount')}
          </Button>
        </Link>
        <Link href="/login">
          <Button variant="outline" size="sm" aria-label={t('nav.signIn')}>
            <LogIn class="size-4" />
            {t('nav.signIn')}
          </Button>
        </Link>
      {/if}
      <LanguageSwitcher />
      <ThemeToggle />
    </nav>

    <!-- Mobile: keep the E2EE badge visible; the rest folds into the panel. -->
    <div class="flex sm:hidden items-center gap-2">
      <E2eeBadge />
      <Button
        variant="outline"
        size="sm"
        class="min-h-11"
        aria-label={t('nav.menu')}
        aria-expanded={menuOpen}
        aria-controls="mobile-nav"
        onclick={() => (menuOpen = !menuOpen)}
      >
        {#if menuOpen}
          <X class="size-4" />
        {:else}
          <Menu class="size-4" />
        {/if}
        {t('nav.menu')}
      </Button>
    </div>
  </div>

  {#if menuOpen}
    <nav
      id="mobile-nav"
      class="sm:hidden border-t border-border bg-background/95 backdrop-blur"
      transition:slide={{ duration: 180 }}
    >
      <div class="container mx-auto px-4 py-3 flex flex-col gap-1.5">
        {#if me.isPending}
          <Skeleton class="h-11 w-full rounded-md" />
        {:else if me.data?.authenticated}
          <Link href="/account" onclick={closeMenu}>
            <Button variant="default" size="sm" class="w-full min-h-11 justify-start">
              <User class="size-4" />
              {t('nav.account')}
            </Button>
          </Link>
        {:else}
          <Link href="/get-account" onclick={closeMenu}>
            <Button variant="ghost" size="sm" class="w-full min-h-11 justify-start">
              <SocksIcon class="size-4" />
              {t('nav.getAccount')}
            </Button>
          </Link>
          <Link href="/login" onclick={closeMenu}>
            <Button variant="outline" size="sm" class="w-full min-h-11 justify-start">
              <LogIn class="size-4" />
              {t('nav.signIn')}
            </Button>
          </Link>
        {/if}
        <div class="mt-1 pt-2 border-t border-border flex items-center justify-between gap-2">
          <LanguageSwitcher />
          <div class="flex items-center gap-1">
            <span class="text-sm text-muted-foreground">{t('nav.theme')}</span>
            <ThemeToggle />
          </div>
        </div>
      </div>
    </nav>
  {/if}
</header>
