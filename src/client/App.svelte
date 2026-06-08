<script lang="ts">
  import Link from './components/Link.svelte';
  import AppHeader from './components/AppHeader.svelte';
  import { Toaster } from '@client/components/ui/sonner';
  import { ModeWatcher } from 'mode-watcher';
  import ErrorBoundary from './components/ErrorBoundary.svelte';
  import Home from './routes/Home.svelte';
  import GetKey from './routes/GetKey.svelte';
  import Account from './routes/Account.svelte';
  import Login from './routes/Login.svelte';
  import AdminEntry from './routes/admin/AdminEntry.svelte';
  import AdminTiers from './routes/admin/AdminTiers.svelte';
  import AdminUsers from './routes/admin/AdminUsers.svelte';
  import AdminTokens from './routes/admin/AdminTokens.svelte';
  import AdminAudit from './routes/admin/AdminAudit.svelte';
  import AdminSettings from './routes/admin/AdminSettings.svelte';
  import AdminOutlineServers from './routes/admin/AdminOutlineServers.svelte';
  import { router } from './stores/router.svelte';
  import { QueryClientProvider } from '@tanstack/svelte-query';
  import { SvelteQueryDevtools } from '@tanstack/svelte-query-devtools';
  import { queryClient } from './lib/query-client';
  import { fade } from 'svelte/transition';

  let onAdminRoute = $derived(router.pathname.startsWith('/admin'));
  // DevTools only in development; in production it's tree-shaken away.
  const isDev = import.meta.env.DEV;
</script>

<!--
  ModeWatcher syncs the `dark` class on <html> with the user's preference
  (light/dark/system) and persists to localStorage. Toaster is the global
  Sonner outlet: anywhere in the tree can call `toast.success(...)` and
  it'll appear here. QueryClientProvider provides the cache to every
  createQuery/createMutation in the tree.
-->
<ModeWatcher defaultMode="dark" />
<Toaster richColors position="top-right" />

<QueryClientProvider client={queryClient}>
  <ErrorBoundary>
    <div class="min-h-screen flex flex-col">
      {#if !onAdminRoute}
        <AppHeader />
      {/if}

      <main class="flex-1 container mx-auto px-4 py-8">
        <!--
          Keying the wrapper by pathname forces a remount when the route
          changes, which lets the in/out fade transitions actually fire. The
          `prefers-reduced-motion` media query in globals.css clamps the
          duration for users who've opted out of motion.
        -->
        {#key router.pathname}
          <div in:fade={{ duration: 180 }}>
            {#if router.pathname === '/'}
              <Home />
            {:else if router.pathname === '/get-key'}
              <GetKey />
            {:else if router.pathname === '/account'}
              <Account />
            {:else if router.pathname === '/login'}
              <Login />
            {:else if router.pathname === '/admin'}
              <AdminEntry />
            {:else if router.pathname === '/admin/tiers'}
              <AdminTiers />
            {:else if router.pathname === '/admin/users'}
              <AdminUsers />
            {:else if router.pathname === '/admin/tokens'}
              <AdminTokens />
            {:else if router.pathname === '/admin/audit'}
              <AdminAudit />
            {:else if router.pathname === '/admin/settings'}
              <AdminSettings />
            {:else if router.pathname === '/admin/outline-servers'}
              <AdminOutlineServers />
            {:else}
              <div class="text-center py-16">
                <h1 class="text-3xl font-display font-bold mb-2">Not found</h1>
                <Link href="/" class="text-primary underline">Go home</Link>
              </div>
            {/if}
          </div>
        {/key}
      </main>

      <footer class="border-t border-border mt-12">
        <div
          class="container mx-auto px-4 py-8 flex flex-col md:flex-row gap-4 items-center justify-between text-sm text-muted-foreground"
        >
          <p>
            Operated by{' '}
            <a
              class="underline hover:text-foreground"
              href="https://unredacted.org"
              target="_blank"
              rel="noopener noreferrer"
            >
              Unredacted
            </a>, a US 501(c)(3) nonprofit
          </p>
          <nav class="flex flex-wrap items-center gap-4 text-xs">
            <a
              class="hover:text-foreground"
              href="https://unredacted.org/donate"
              target="_blank"
              rel="noopener noreferrer"
            >
              Donate
            </a>
            <a class="hover:text-foreground" href="/api/docs">API docs</a>
          </nav>
        </div>
      </footer>
    </div>
  </ErrorBoundary>

  {#if isDev}
    <SvelteQueryDevtools initialIsOpen={false} buttonPosition="bottom-right" />
  {/if}
</QueryClientProvider>
