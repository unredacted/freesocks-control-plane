<script lang="ts">
  import Link from './components/Link.svelte';
  import AppHeader from './components/AppHeader.svelte';
  import PopWarm from './components/PopWarm.svelte';
  import ThemeSync from './components/ThemeSync.svelte';
  import { Toaster } from '@client/components/ui/sonner';
  import { ModeWatcher } from 'mode-watcher';
  import ErrorBoundary from './components/ErrorBoundary.svelte';
  import Home from './routes/Home.svelte';
  import GetAccount from './routes/GetAccount.svelte';
  import Account from './routes/Account.svelte';
  import Login from './routes/Login.svelte';
  // The whole admin CMS is lazy-loaded (P1-18): public visitors never download it.
  const AdminRouter = () => import('./routes/admin/AdminRouter.svelte');
  import { router } from './stores/router.svelte';
  import { QueryClientProvider } from '@tanstack/svelte-query';
  import { SvelteQueryDevtools } from '@tanstack/svelte-query-devtools';
  import { queryClient } from './lib/query-client';
  import { t, getLocale } from './lib/i18n/index.svelte';
  import { dirForLocale } from './lib/i18n/locales';
  import { fade } from 'svelte/transition';

  let onAdminRoute = $derived(router.pathname.startsWith('/admin'));

  // Toasts originate from the leading edge: top-right for LTR, top-left for RTL.
  let dir = $derived(dirForLocale(getLocale()));
  let toasterPosition = $derived(dir === 'rtl' ? ('top-left' as const) : ('top-right' as const));

  // PoP boot-warm lives in <PopWarm/> inside the provider below — it calls
  // meQuery(), which reads the query client from context at init, so it CANNOT
  // run from this script (App hosts the provider; its script runs before the
  // provider child mounts).

  // DevTools only in development; in production it's tree-shaken away.
  const isDev = import.meta.env.DEV;

  // a11y: on a client-side route change, move focus to the main region so
  // keyboard + screen-reader users land in the new content (a SPA navigation
  // otherwise leaves focus on the clicked link and announces nothing). Skipped
  // on first paint (the page load already focuses the document).
  let mainEl = $state<HTMLElement | null>(null);
  let firstRoute = true;
  $effect(() => {
    void router.pathname;
    if (firstRoute) {
      firstRoute = false;
      return;
    }
    mainEl?.focus();
  });
</script>

<!--
  ModeWatcher syncs the `dark` class on <html> with the user's preference
  (light/dark/system) and persists to localStorage. Toaster is the global
  Sonner outlet: anywhere in the tree can call `toast.success(...)` and
  it'll appear here. QueryClientProvider provides the cache to every
  createQuery/createMutation in the tree.
-->
<ModeWatcher defaultMode="dark" />
<Toaster richColors position={toasterPosition} {dir} />

<QueryClientProvider client={queryClient}>
  <PopWarm />
  <ThemeSync />
  <ErrorBoundary>
    <div class="min-h-screen flex flex-col">
      <!-- a11y: first focusable element, lets keyboard users jump the header. -->
      <a
        href="#main"
        class="sr-only focus:not-sr-only focus:fixed focus:start-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:shadow focus:outline-none focus:ring-2 focus:ring-ring"
      >
        {t('app.skipToContent')}
      </a>
      {#if !onAdminRoute}
        <AppHeader />
      {/if}

      <main
        bind:this={mainEl}
        id="main"
        tabindex="-1"
        class="flex-1 container mx-auto px-4 py-8 outline-none"
      >
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
            {:else if router.pathname === '/get-account'}
              <GetAccount />
            {:else if router.pathname === '/account'}
              <Account />
            {:else if router.pathname === '/login'}
              <Login />
            {:else if onAdminRoute}
              {#await AdminRouter() then mod}
                {@const Admin = mod.default}
                <Admin />
              {:catch}
                <!-- The lazy admin chunk failed to load (flaky network / stale
                     cache) — without this branch the page is silently blank. -->
                <div class="text-center py-16 space-y-3">
                  <h1 class="text-xl font-display font-bold">{t('app.adminLoadFailedTitle')}</h1>
                  <p class="text-sm text-muted-foreground">
                    {t('app.adminLoadFailedBody')}
                  </p>
                  <button
                    type="button"
                    class="text-primary underline"
                    onclick={() => window.location.reload()}
                  >
                    {t('common.reload')}
                  </button>
                </div>
              {/await}
            {:else}
              <div class="text-center py-16">
                <h1 class="text-3xl font-display font-bold mb-2">{t('app.notFound')}</h1>
                <Link href="/" class="text-primary underline">{t('app.goHome')}</Link>
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
            {t('footer.operatedPrefix')}{' '}
            <a
              class="underline hover:text-foreground"
              href="https://unredacted.org"
              target="_blank"
              rel="noopener noreferrer"
            >
              Unredacted
            </a>{t('footer.operatedSuffix')}
          </p>
          <nav class="flex flex-wrap items-center gap-4 text-xs">
            <a
              class="hover:text-foreground"
              href="https://unredacted.org/donate"
              target="_blank"
              rel="noopener noreferrer"
            >
              {t('renew.donate')}
            </a>
            <a class="hover:text-foreground" href="/api/docs">{t('footer.apiDocs')}</a>
          </nav>
        </div>
      </footer>
    </div>
  </ErrorBoundary>

  {#if isDev}
    <SvelteQueryDevtools initialIsOpen={false} buttonPosition="bottom-right" />
  {/if}
</QueryClientProvider>
