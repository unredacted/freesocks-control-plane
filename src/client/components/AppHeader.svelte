<script lang="ts">
  import Link from './Link.svelte';
  import { Skeleton } from '@client/components/ui/skeleton';
  import ThemeToggle from './ThemeToggle.svelte';
  import LanguageSwitcher from './LanguageSwitcher.svelte';
  import HpkeBadge from './HpkeBadge.svelte';
  import BrandMark from './BrandMark.svelte';
  import { Button } from '@client/components/ui/button';
  import { configQuery, meQuery } from '../lib/queries';
  import { t, type MessageKey } from '../lib/i18n/index.svelte';
  import { FAQ_ID, goToSection } from '../lib/homeSections.svelte';
  import { router } from '../stores/router.svelte';
  import { slide } from 'svelte/transition';
  import Menu from '@lucide/svelte/icons/menu';
  import X from '@lucide/svelte/icons/x';

  // TanStack queries, fetched once on first render, cached across the SPA.
  const me = meQuery();
  const config = configQuery();

  // Section links: home-page anchors plus the status page. Membership only
  // while billing is on (its section is hidden otherwise).
  type NavItem = { label: MessageKey } & ({ section: string } | { href: string });
  const items = $derived.by((): NavItem[] => [
    { label: 'home.how.title', section: 'how' },
    { label: 'status.title', href: '/status' },
    ...(config.data?.billing?.enabled
      ? [{ label: 'home.membership.title', section: 'membership' } as const]
      : []),
    { label: 'home.sections.faq', section: FAQ_ID },
  ]);

  // Below lg the section links and sign-in fold into a labeled panel under the
  // bar; the primary button stays in the bar from sm up.
  let menuOpen = $state(false);
  const closeMenu = () => (menuOpen = false);
  // Close on any route change too (covers back/forward, not just link taps).
  $effect(() => {
    void router.pathname;
    menuOpen = false;
  });
</script>

{#snippet navLink(item: NavItem, cls: string)}
  {#if 'section' in item}
    <a
      href="/#{item.section}"
      class={cls}
      onclick={(e) => {
        closeMenu();
        void goToSection(e, item.section);
      }}>{t(item.label)}</a
    >
  {:else}
    <Link href={item.href} class={cls} onclick={closeMenu}>{t(item.label)}</Link>
  {/if}
{/snippet}

{#snippet primaryAction(cls: string)}
  {#if me.isPending}
    <!-- Neutral placeholder while the auth check resolves, so signed-in
         members never see "Get a free account" flash on a hard load. -->
    <Skeleton class="h-11 w-44 rounded-sm" />
  {:else if me.data?.authenticated}
    <Link href="/account" onclick={closeMenu}>
      <Button size="lg" class="text-[15px] {cls}">{t('nav.account')}</Button>
    </Link>
  {:else}
    <Link href="/get-account" onclick={closeMenu}>
      <Button size="lg" class="text-[15px] {cls}">{t('nav.getAccount')}</Button>
    </Link>
  {/if}
{/snippet}

<!-- The family strip: who runs this, plus the page-wide controls. -->
<div class="border-b border-border/70 bg-band text-sm">
  <div class="site-wrap flex min-h-10 flex-wrap items-center justify-between gap-x-4 gap-y-1">
    <p class="text-muted-foreground">
      {t('footer.operatedPrefix')}
      <a
        class="link-brand text-foreground"
        href="https://unredacted.org"
        target="_blank"
        rel="noopener noreferrer">Unredacted</a
      >
    </p>
    <div class="flex items-center gap-2">
      <HpkeBadge />
      <LanguageSwitcher />
      <ThemeToggle />
    </div>
  </div>
</div>

<header class="border-b border-border/70">
  <div class="site-wrap flex min-h-[76px] items-center justify-between gap-6">
    <Link
      href="/"
      class="flex shrink-0 items-center gap-2.5"
      aria-label={t('nav.home')}
      onclick={closeMenu}
    >
      <BrandMark class="size-[34px]" />
      <span class="font-display text-[23px] font-extrabold tracking-[-0.02em] text-foreground">
        FreeSocks
      </span>
    </Link>

    <nav class="hidden items-center gap-7 text-[15.5px] lg:flex">
      {#each items as item (item.label)}
        {@render navLink(item, 'hover:text-primary')}
      {/each}
      {#if !me.isPending && !me.data?.authenticated}
        <Link href="/login" class="hover:text-primary">{t('nav.signIn')}</Link>
      {/if}
      {@render primaryAction('')}
    </nav>

    <div class="flex items-center gap-3 lg:hidden">
      <div class="hidden sm:block">{@render primaryAction('')}</div>
      <Button
        variant="outline"
        size="lg"
        class="text-[15px]"
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
      class="border-t border-border/70 lg:hidden"
      transition:slide={{ duration: 180 }}
    >
      <div class="site-wrap flex flex-col py-2 text-base">
        {#each items as item (item.label)}
          {@render navLink(item, 'flex min-h-11 items-center hover:text-primary')}
        {/each}
        {#if !me.isPending && !me.data?.authenticated}
          <Link
            href="/login"
            class="flex min-h-11 items-center hover:text-primary"
            onclick={closeMenu}>{t('nav.signIn')}</Link
          >
        {/if}
        <div class="pt-2 pb-2 sm:hidden">{@render primaryAction('w-full')}</div>
      </div>
    </nav>
  {/if}
</header>
