<script lang="ts">
  /**
   * The account page's hint that an app on this key got the app notice lately:
   * a config whose only entries say the app can't connect (convex/lib/appNotice.ts).
   * Shown while the server says it is recent (the account view's
   * `subscription.appNotice`, a 7-day window), whatever the member's other apps
   * fetched meanwhile: one key may serve a working app and a too-old one. The
   * button takes the member to the supported apps (ConnectClient, `#setup-apps`).
   *
   * `clash` is an old Clash app (no VLESS); the other kinds read a format that
   * can't carry the member's mode (sing-box has no XHTTP).
   */
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import { Button } from '@client/components/ui/button';
  import { t } from '../lib/i18n/index.svelte';
  import type { AccountResponse } from '../../shared/contracts/account';

  type AppNotice = NonNullable<NonNullable<AccountResponse['subscription']>['appNotice']>;
  let { notice }: { notice: AppNotice } = $props();

  const tooOld = $derived(notice.family === 'clash');

  // Reduced-motion-aware, and focus follows so a keyboard or screen-reader
  // user lands where the page scrolled.
  function showApps() {
    const target = document.getElementById('setup-apps');
    if (!target) return;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    target.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    target.querySelector<HTMLElement>('[data-setup-title]')?.focus({ preventScroll: true });
  }
</script>

<div
  role="note"
  aria-labelledby="app-notice-title"
  class="flex items-start gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-5 py-4 text-amber-800 dark:text-amber-200"
>
  <TriangleAlert class="mt-0.5 size-5 shrink-0" aria-hidden="true" />
  <div class="min-w-0 space-y-2">
    <p id="app-notice-title" class="font-bold">
      {tooOld ? t('account.appNotice.oldTitle') : t('account.appNotice.modeTitle')}
    </p>
    <p class="text-[15px]">
      {tooOld ? t('account.appNotice.oldBody') : t('account.appNotice.modeBody')}
    </p>
    <Button variant="outline" size="sm" class="min-h-11" onclick={showApps}>
      {t('account.appNotice.action')}
    </Button>
  </div>
</div>
