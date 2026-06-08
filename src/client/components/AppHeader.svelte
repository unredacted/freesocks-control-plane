<script lang="ts">
  import Link from './Link.svelte';
  import ThemeToggle from './ThemeToggle.svelte';
  import { Button } from '@client/components/ui/button';
  import { meQuery } from '../lib/queries';
  import KeyIcon from '@lucide/svelte/icons/key-round';
  import User from '@lucide/svelte/icons/user-round';
  import LogIn from '@lucide/svelte/icons/log-in';
  import Heart from '@lucide/svelte/icons/heart';

  // TanStack query, fetched once on first render, cached across the SPA,
  // refetched on window focus (so the user gets fresh tier info when they
  // come back from a payment tab once the membership flow is live).
  const me = meQuery();

  let isFreeTierMember = $derived(!!me.data?.authenticated && me.data.member?.tier.slug === 'free');
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
      <Link href="/get-key">
        <Button variant="ghost" size="sm">
          <KeyIcon class="size-4" />
          <span class="hidden sm:inline">Get a key</span>
        </Button>
      </Link>
      {#if !me.isPending && me.data?.authenticated}
        {#if isFreeTierMember}
          <!--
            Membership flow is not yet wired up end-to-end (the in-house
            billing portal is still being designed). Surface the CTA as
            "coming soon" so free-tier users see it's planned, but don't
            link out to a flow that doesn't work yet.
          -->
          <Button
            variant="outline"
            size="sm"
            class="text-muted-foreground border-border hidden sm:inline-flex"
            disabled
            aria-disabled="true"
            title="Membership signup is coming soon"
          >
            <Heart class="size-4" />
            Membership (coming soon)
          </Button>
        {/if}
        <Link href="/account">
          <Button variant="default" size="sm">
            <User class="size-4" />
            <span class="hidden sm:inline">Account</span>
          </Button>
        </Link>
      {:else}
        <Link href="/login">
          <Button variant="outline" size="sm">
            <LogIn class="size-4" />
            Sign in
          </Button>
        </Link>
      {/if}
      <ThemeToggle />
    </nav>
  </div>
</header>
