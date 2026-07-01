<script lang="ts">
  import { z } from 'zod';
  import Link from '../../components/Link.svelte';
  import E2eeBadge from '../../components/E2eeBadge.svelte';
  import { router } from '../../stores/router.svelte';
  import { cn } from '../../lib/utils';
  import { apiClient } from '../../lib/api';
  import { clearSessionKey } from '../../lib/pop';
  import LayoutDashboard from '@lucide/svelte/icons/layout-dashboard';
  import Palette from '@lucide/svelte/icons/palette';
  import Layers from '@lucide/svelte/icons/layers';
  import UsersIcon from '@lucide/svelte/icons/users';
  import KeyIcon from '@lucide/svelte/icons/key';
  import History from '@lucide/svelte/icons/history';
  import Menu from '@lucide/svelte/icons/menu';
  import X from '@lucide/svelte/icons/x';
  import Server from '@lucide/svelte/icons/server';
  import Settings from '@lucide/svelte/icons/settings';
  import Gauge from '@lucide/svelte/icons/gauge';
  import Ticket from '@lucide/svelte/icons/ticket';
  import CreditCard from '@lucide/svelte/icons/credit-card';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import Cloud from '@lucide/svelte/icons/cloud';
  import LogOut from '@lucide/svelte/icons/log-out';

  interface Props {
    children?: import('svelte').Snippet;
  }
  let { children }: Props = $props();

  let signingOut = $state(false);
  // Mirror the member logout (Account.svelte): the local clear + redirect must
  // run even if the network POST fails, so a flaky connection can't strand the
  // admin in a half-signed-out state. Clears the admin PoP key too, so the next
  // sign-in binds a fresh one. Lands on /admin, which shows the sign-in form.
  async function signOut() {
    signingOut = true;
    try {
      await apiClient.post('/api/admin/auth/logout', {}, z.object({ ok: z.boolean() }));
    } catch {
      /* best-effort server-side revoke; the cookie clears on redirect regardless */
    } finally {
      await clearSessionKey('admin').catch(() => {});
      window.location.href = '/admin';
    }
  }

  const NAV = [
    { to: '/admin/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/admin/tiers', label: 'Tiers', icon: Layers },
    { to: '/admin/users', label: 'Users', icon: UsersIcon },
    { to: '/admin/admins', label: 'Admins', icon: ShieldCheck },
    { to: '/admin/tokens', label: 'API tokens', icon: KeyIcon },
    { to: '/admin/backend-servers', label: 'Backend servers', icon: Server },
    { to: '/admin/storage', label: 'Storage mirrors', icon: Cloud },
    { to: '/admin/membership-codes', label: 'Membership codes', icon: Ticket },
    { to: '/admin/billing', label: 'Billing', icon: CreditCard },
    { to: '/admin/rate-limits', label: 'Rate limits', icon: Gauge },
    { to: '/admin/audit', label: 'Audit log', icon: History },
    { to: '/admin/settings', label: 'Settings', icon: Settings },
    { to: '/admin/theme', label: 'Theme', icon: Palette },
  ];

  let mobileOpen = $state(false);
</script>

<div class="md:grid md:grid-cols-[220px_1fr] md:gap-10 min-h-[80vh]">
  <!-- Mobile top bar with hamburger -->
  <div class="md:hidden flex items-center justify-between border-b border-border pb-3 mb-4">
    <div class="flex items-center gap-2">
      <Link href="/" class="font-display text-xl font-bold tracking-tight">FreeSocks</Link>
      <E2eeBadge context="admin" />
    </div>
    <button
      type="button"
      aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
      aria-expanded={mobileOpen}
      class="inline-flex items-center justify-center size-9 rounded-md border border-border text-muted-foreground hover:bg-accent transition-colors"
      onclick={() => (mobileOpen = !mobileOpen)}
    >
      {#if mobileOpen}
        <X class="size-4" />
      {:else}
        <Menu class="size-4" />
      {/if}
    </button>
  </div>

  <!-- Sidebar: drawer on mobile, fixed column on md+ -->
  <aside
    class={cn(
      'md:block md:border-r md:border-border md:pr-6',
      mobileOpen ? 'block mb-6 pb-3 border-b border-border' : 'hidden',
    )}
  >
    <Link
      href="/"
      class="hidden md:flex md:items-center md:gap-2 font-display text-xl font-bold tracking-tight mb-4"
    >
      FreeSocks
      <span
        class="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold rounded bg-secondary px-1.5 py-0.5"
      >
        Admin
      </span>
    </Link>
    <div class="mb-8 hidden md:block">
      <E2eeBadge context="admin" />
    </div>
    <nav class="space-y-0.5">
      {#each NAV as item (item.to)}
        {@const active = item.to === router.pathname}
        <Link
          href={item.to}
          onclick={() => (mobileOpen = false)}
          aria-current={active ? 'page' : undefined}
          class={cn(
            'flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors',
            active
              ? 'bg-accent text-accent-foreground font-medium'
              : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
          )}
        >
          <item.icon class="size-4 shrink-0" />
          {item.label}
        </Link>
      {/each}
    </nav>
    <div class="mt-2 border-t border-border pt-2">
      <button
        type="button"
        onclick={signOut}
        disabled={signingOut}
        class="flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent/50 hover:text-foreground disabled:opacity-60"
      >
        <LogOut class="size-4 shrink-0" />
        {signingOut ? 'Signing out…' : 'Sign out'}
      </button>
    </div>
  </aside>
  <section>
    {#if children}{@render children()}{/if}
  </section>
</div>
