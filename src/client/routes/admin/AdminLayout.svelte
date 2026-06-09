<script lang="ts">
  import Link from '../../components/Link.svelte';
  import { router } from '../../stores/router.svelte';
  import { cn } from '../../lib/utils';
  import Layers from '@lucide/svelte/icons/layers';
  import UsersIcon from '@lucide/svelte/icons/users';
  import KeyIcon from '@lucide/svelte/icons/key';
  import History from '@lucide/svelte/icons/history';
  import Menu from '@lucide/svelte/icons/menu';
  import X from '@lucide/svelte/icons/x';
  import Server from '@lucide/svelte/icons/server';
  import Settings from '@lucide/svelte/icons/settings';

  interface Props {
    children?: import('svelte').Snippet;
  }
  let { children }: Props = $props();

  const NAV = [
    { to: '/admin/tiers', label: 'Tiers', icon: Layers },
    { to: '/admin/users', label: 'Users', icon: UsersIcon },
    { to: '/admin/tokens', label: 'API tokens', icon: KeyIcon },
    { to: '/admin/backend-servers', label: 'Backend servers', icon: Server },
    { to: '/admin/audit', label: 'Audit log', icon: History },
    { to: '/admin/settings', label: 'Settings', icon: Settings },
  ];

  let mobileOpen = $state(false);
</script>

<div class="md:grid md:grid-cols-[220px_1fr] md:gap-10 min-h-[80vh]">
  <!-- Mobile top bar with hamburger -->
  <div class="md:hidden flex items-center justify-between border-b border-border pb-3 mb-4">
    <Link href="/" class="font-display text-xl font-bold tracking-tight">FreeSocks</Link>
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
      class="hidden md:flex md:items-center md:gap-2 font-display text-xl font-bold tracking-tight mb-8"
    >
      FreeSocks
      <span
        class="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold rounded bg-secondary px-1.5 py-0.5"
      >
        Admin
      </span>
    </Link>
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
  </aside>
  <section>
    {#if children}{@render children()}{/if}
  </section>
</div>
