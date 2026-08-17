<script lang="ts" module>
  /**
   * Nav-group open state, MODULE-scoped on purpose: App.svelte wraps the route in
   * `{#key router.pathname}`, so this layout is torn down and rebuilt on every
   * navigation. Component-local state would reset each click, discarding the
   * admin's manual open/close. Keyed by group name; `undefined` = never toggled,
   * so the route decides.
   */
  const groupOpen = $state<Record<string, boolean | undefined>>({});
</script>

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
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import Waypoints from '@lucide/svelte/icons/waypoints';
  import GitBranch from '@lucide/svelte/icons/git-branch';
  import HeartPulse from '@lucide/svelte/icons/heart-pulse';
  import LogOut from '@lucide/svelte/icons/log-out';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import type { LucideIcon } from '@lucide/svelte';
  import * as Collapsible from '@client/components/ui/collapsible';

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

  // Nav items are either a leaf link ({ to, label, icon }) or a collapsible group
  // ({ group, icon, children: [...] }). Backend servers + Remnawave (both server
  // config) live under one "Servers" group; the router is unaffected (children keep
  // their flat paths).
  type NavLeaf = { to: string; label: string; icon: LucideIcon };
  type NavGroup = { group: string; icon: LucideIcon; children: NavLeaf[] };
  const NAV: (NavLeaf | NavGroup)[] = [
    { to: '/admin/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/admin/tiers', label: 'Tiers', icon: Layers },
    { to: '/admin/users', label: 'Users', icon: UsersIcon },
    { to: '/admin/admins', label: 'Admins', icon: ShieldCheck },
    { to: '/admin/tokens', label: 'API tokens', icon: KeyIcon },
    {
      group: 'Servers',
      icon: Server,
      children: [
        { to: '/admin/backend-servers', label: 'Backend servers', icon: Server },
        { to: '/admin/connection-modes', label: 'Connection modes', icon: GitBranch },
        { to: '/admin/remnawave', label: 'Remnawave', icon: Waypoints },
        { to: '/admin/status', label: 'Status page', icon: HeartPulse },
      ],
    },
    { to: '/admin/storage', label: 'Storage mirrors', icon: Cloud },
    { to: '/admin/clients', label: 'Client apps', icon: Smartphone },
    { to: '/admin/membership-codes', label: 'Membership codes', icon: Ticket },
    { to: '/admin/billing', label: 'Billing', icon: CreditCard },
    { to: '/admin/rate-limits', label: 'Rate limits', icon: Gauge },
    { to: '/admin/audit', label: 'Audit log', icon: History },
    { to: '/admin/settings', label: 'Settings', icon: Settings },
    { to: '/admin/theme', label: 'Theme', icon: Palette },
  ];

  let mobileOpen = $state(false);

  /** Is the active route one of this group's children? Derived from the group's OWN
   *  children — a second hand-maintained path list drifted once already (it omitted
   *  /admin/connection-modes, so that page rendered the group collapsed). */
  const holdsActiveRoute = (item: NavGroup) => item.children.some((c) => c.to === router.pathname);

  /** Open when the admin has toggled it, else whenever the active route lives in it
   *  (initial deep-link + navigating in). */
  const isOpen = (item: NavGroup) => groupOpen[item.group] ?? holdsActiveRoute(item);

  // Entering a group's page opens it, so the active item is never hidden inside a
  // collapsed section. Closing it by hand sticks until the next navigation into
  // one of its pages (the module-scoped store survives the route remount).
  $effect(() => {
    for (const item of NAV) {
      if ('children' in item && holdsActiveRoute(item)) groupOpen[item.group] = true;
    }
  });
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
      {#each NAV as item, i (i)}
        {#if 'children' in item}
          <Collapsible.Root
            bind:open={() => isOpen(item), (open) => (groupOpen[item.group] = open)}
          >
            <Collapsible.Trigger
              class={cn(
                'group flex w-full items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors',
                holdsActiveRoute(item)
                  ? 'text-foreground font-medium'
                  : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
              )}
            >
              <item.icon class="size-4 shrink-0" />
              {item.group}
              <ChevronDown
                class="size-4 ms-auto shrink-0 transition-transform group-data-[state=open]:rotate-180"
              />
            </Collapsible.Trigger>
            <Collapsible.Content class="mt-0.5 ms-3 space-y-0.5 border-s border-border ps-2">
              {#each item.children as child (child.to)}
                {@const active = child.to === router.pathname}
                <Link
                  href={child.to}
                  onclick={() => (mobileOpen = false)}
                  aria-current={active ? 'page' : undefined}
                  class={cn(
                    'flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors',
                    active
                      ? 'bg-accent text-accent-foreground font-medium'
                      : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
                  )}
                >
                  <child.icon class="size-4 shrink-0" />
                  {child.label}
                </Link>
              {/each}
            </Collapsible.Content>
          </Collapsible.Root>
        {:else}
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
        {/if}
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
