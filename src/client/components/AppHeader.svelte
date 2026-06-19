<script lang="ts">
  import Link from './Link.svelte';
  import ThemeToggle from './ThemeToggle.svelte';
  import LanguageSwitcher from './LanguageSwitcher.svelte';
  import { Button } from '@client/components/ui/button';
  import { meQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import KeyIcon from '@lucide/svelte/icons/key-round';
  import User from '@lucide/svelte/icons/user-round';
  import LogIn from '@lucide/svelte/icons/log-in';

  // TanStack query, fetched once on first render, cached across the SPA.
  const me = meQuery();
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
        <!-- Signed in: a single account CTA. The account page itself leads with
             the membership upsell for free-tier members, so a separate
             "Membership" button here would just be a second link to /account. -->
        <Link href="/account">
          <Button variant="default" size="sm" class="max-sm:min-h-11">
            <User class="size-4" />
            <span class="hidden sm:inline">{t('nav.account')}</span>
          </Button>
        </Link>
      {:else}
        <Link href="/get-account">
          <Button variant="ghost" size="sm" class="max-sm:min-h-11">
            <KeyIcon class="size-4" />
            <span class="hidden sm:inline">{t('nav.getAccount')}</span>
          </Button>
        </Link>
        <Link href="/login">
          <Button variant="outline" size="sm" class="max-sm:min-h-11">
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
