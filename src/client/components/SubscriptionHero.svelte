<script lang="ts">
  import { fly, fade } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import { Button } from '@client/components/ui/button';
  import QrCode from './QrCode.svelte';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import Download from '@lucide/svelte/icons/download';
  import Calendar from '@lucide/svelte/icons/calendar';
  import Gauge from '@lucide/svelte/icons/gauge';
  import QrCodeIcon from '@lucide/svelte/icons/qr-code';
  import Link2 from '@lucide/svelte/icons/link-2';
  import Shield from '@lucide/svelte/icons/shield';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import { formatBytes, daysUntil } from '../lib/utils';
  import { IMPORT_APPS, IMPORT_PROFILE_NAME, type ImportApp } from '../lib/appLinks';
  import { t } from '../lib/i18n/index.svelte';
  import { formatDate } from '../lib/i18n/format';
  import { toast } from 'svelte-sonner';

  /**
   * Hero subscription block: the visual focal point of the page. Big URL,
   * one-click copy, QR code for cross-device handoff, expiry/traffic as
   * secondary metadata. Used on /get-account (anonymous result), /account
   * (signed-in dashboard), and anywhere else we hand someone a key.
   *
   * Design decisions:
   *  - URL is monospace, large, with a card border that visually separates
   *    it from the metadata.
   *  - Primary action is Copy (full-width on mobile, inline on desktop).
   *  - QR is on the right at desktop, below the URL on mobile.
   *  - Animated copy-success uses Check icon swap with a 1.5s rollback.
   *  - Traffic + expiry use tabular-nums so they don't jiggle on rerender.
   */
  interface Props {
    title?: string;
    eyebrow?: string;
    /** Display name for the backend (from config.backends.labels). Falls back
     *  to the built-in names so existing callers keep working. */
    backendLabel?: string;
    subscriptionUrl: string;
    fallbackUrl?: string;
    expiresAt: string | null;
    trafficLimitBytes: number | null;
    trafficUsedBytes: number;
    tierName: string;
    /** Soft amber banner shown above the card (e.g. "key already issued today"). */
    banner?: string;
    /** Whether to render the QR. Default true. Pass false for compact contexts. */
    showQr?: boolean;
    /**
     * Privacy mode: omit the big subscription URL + QR + copy block entirely and
     * show only the metadata (traffic/expiry/tier) + a pointer to the raw config
     * below. The subscription link is what a client fetches through a CDN, so
     * "maximize privacy" deliberately doesn't surface it as the headline.
     */
    hideUrl?: boolean;
    /**
     * Which backend issued the key. Drives label wording (Remnawave returns a
     * multi-protocol subscription URL; Outline returns a single `ss://` access
     * key) and the download filename. Defaults to `remnawave` so existing
     * callers keep their behavior.
     */
    backend?: 'remnawave' | 'outline';
    /** Live key state from the backend (undefined/'unknown' when unreachable).
     *  `limited`/`disabled`/`expired` surface a "why your VPN stopped" callout. */
    status?: 'active' | 'disabled' | 'limited' | 'expired' | 'unknown';
    /** Traffic reset cadence + last-reset anchor → the "resets in N days" hint. */
    resetStrategy?: 'NO_RESET' | 'DAY' | 'WEEK' | 'MONTH';
    lastResetAt?: string;
  }
  let {
    title,
    eyebrow,
    backendLabel,
    subscriptionUrl,
    fallbackUrl,
    expiresAt,
    trafficLimitBytes,
    trafficUsedBytes,
    tierName,
    banner,
    showQr = true,
    hideUrl = false,
    backend = 'remnawave',
    status,
    resetStrategy,
    lastResetAt,
  }: Props = $props();

  // Outline keys are bare `ss://` URLs that VPN clients import as a single
  // "access key", not as a multi-protocol subscription. Use the right noun in
  // the UI so the user knows what they're looking at. All labels resolve in
  // $derived so a locale switch re-renders them (t() reads $state).
  let resolvedTitle = $derived(title ?? t('hero.titleDefault'));
  let urlLabel = $derived(
    backend === 'outline' ? t('hero.urlLabelAccessKey') : t('hero.urlLabelSubscription'),
  );
  let resolvedBackendLabel = $derived(backendLabel ?? (backend === 'outline' ? 'Outline' : 'Xray'));
  let downloadFilename = $derived(
    backend === 'outline' ? 'freesocks-outline.txt' : 'freesocks-subscription.txt',
  );

  let copied = $state<'primary' | 'fallback' | null>(null);
  let qrOpen = $state(false);
  let qrFallbackOpen = $state(false);

  // One-tap import: when an app is picked, the QR + "Open" button carry that
  // client's deep-link import scheme so scanning/tapping imports directly — a
  // plain https QR just opens a browser. null = the plain link (default).
  let importApp = $state<ImportApp | null>(null);
  let qrValue = $derived(
    importApp ? importApp.build(subscriptionUrl, IMPORT_PROFILE_NAME) : subscriptionUrl,
  );

  async function copy(value: string, key: 'primary' | 'fallback') {
    try {
      // Explicit guard (mirrors AccountNumberReveal): clipboard is undefined in
      // insecure contexts / older in-region browsers — fail to the manual path.
      if (!navigator.clipboard) throw new Error('clipboard unavailable');
      await navigator.clipboard.writeText(value);
      copied = key;
      toast.success(t('common.copied'), { duration: 1500 });
      setTimeout(() => {
        if (copied === key) copied = null;
      }, 1500);
    } catch {
      toast.error(t('common.copyFailed'));
    }
  }

  function downloadConfig() {
    // Produce a tiny .txt with the URL. Useful for users airgapping the key
    // to a separate device, or just keeping a copy. We'll add Clash/Sing-Box
    // formats later when we wire up format conversion. Filename varies by
    // backend so users with both kinds of keys can tell them apart on disk.
    const blob = new Blob([subscriptionUrl + '\n'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = downloadFilename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success(t('hero.downloaded', { filename: downloadFilename }));
  }

  // Traffic percentage, only meaningful when there's a limit.
  let usagePct = $derived(
    trafficLimitBytes ? Math.min(100, (trafficUsedBytes / trafficLimitBytes) * 100) : 0,
  );
  let usageColor = $derived(
    usagePct >= 90 ? 'bg-destructive' : usagePct >= 70 ? 'bg-amber-500' : 'bg-primary',
  );

  // Live key status that explains a stopped connection (active/unknown ⇒ no callout).
  let keyIssue = $derived(
    status === 'disabled'
      ? 'disabled'
      : status === 'expired'
        ? 'expired'
        : status === 'limited'
          ? 'limited'
          : null,
  );

  // Next traffic reset from the cadence + last-reset anchor (null for NO_RESET / no anchor).
  let nextResetDays = $derived.by(() => {
    if (!lastResetAt || !resetStrategy || resetStrategy === 'NO_RESET') return null;
    const base = new Date(lastResetAt);
    if (Number.isNaN(base.getTime())) return null;
    const next = new Date(base);
    if (resetStrategy === 'MONTH') next.setMonth(next.getMonth() + 1);
    else if (resetStrategy === 'WEEK') next.setDate(next.getDate() + 7);
    else next.setDate(next.getDate() + 1);
    return daysUntil(next);
  });

  // Expiry: convert + classify (so we can hint when it's close).
  let expiryDate = $derived(expiresAt ? new Date(expiresAt) : null);
  let daysLeft = $derived(daysUntil(expiresAt));
  let expiryUrgency = $derived(
    daysLeft !== null && daysLeft <= 7
      ? 'text-amber-700 dark:text-amber-400'
      : 'text-muted-foreground',
  );
</script>

<section
  in:fly={{ y: 16, duration: 400, easing: quintOut }}
  class="rounded-xl border border-border bg-card text-card-foreground shadow-sm overflow-hidden"
>
  {#if banner}
    <div
      class="bg-amber-500/10 border-b border-amber-500/30 px-5 py-2.5 text-sm text-amber-700 dark:text-amber-300"
    >
      {banner}
    </div>
  {/if}

  <div class="p-6 md:p-8 space-y-6">
    <!-- Eyebrow + title -->
    <div class="space-y-1.5">
      {#if eyebrow}
        <p
          class="text-xs uppercase tracking-wider font-semibold text-primary/80 flex items-center gap-1.5"
        >
          <Shield class="size-3.5" />
          {eyebrow}
        </p>
      {/if}
      <h2 class="text-2xl md:text-3xl font-display font-bold tracking-tight">
        {resolvedTitle}
      </h2>
      <p class="text-sm text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1">
        <span class="font-medium text-foreground">{t('hero.tierLine', { tier: tierName })}</span>
        <span class="text-muted-foreground/60">·</span>
        <span>{t('hero.viaLine', { backend: resolvedBackendLabel })}</span>
      </p>
    </div>

    {#if !hideUrl}
      <!-- URL + QR side-by-side on desktop, stacked on mobile -->
      <div class="grid gap-6 md:grid-cols-[1fr_auto] md:items-start">
        <div class="space-y-3 min-w-0">
          <label
            for="primary-url"
            class="flex items-center gap-1.5 text-xs uppercase tracking-wider text-muted-foreground font-semibold"
          >
            <Link2 class="size-3.5" />
            {urlLabel}
          </label>
          <div class="relative rounded-lg border border-border bg-muted/40 p-3 group">
            <code
              id="primary-url"
              class="block select-all font-mono text-xs md:text-sm break-all pe-2 leading-relaxed text-foreground/90"
            >
              {subscriptionUrl}
            </code>
          </div>
          <div class="flex flex-wrap gap-2">
            <Button
              onclick={() => copy(subscriptionUrl, 'primary')}
              class="flex-1 sm:flex-initial transition-all min-h-11"
              size="lg"
            >
              {#if copied === 'primary'}
                <span in:fade={{ duration: 150 }} class="inline-flex items-center gap-2">
                  <Check class="size-4" />
                  {t('hero.copiedShort')}
                </span>
              {:else}
                <span in:fade={{ duration: 150 }} class="inline-flex items-center gap-2">
                  <Copy class="size-4" />
                  {t('hero.copyUrl')}
                </span>
              {/if}
            </Button>
            <Button variant="outline" size="lg" class="min-h-11" onclick={downloadConfig}>
              <Download class="size-4" />
              <span class="hidden sm:inline">{t('common.download')}</span>
            </Button>
            {#if showQr}
              <Button
                variant="outline"
                size="lg"
                onclick={() => (qrOpen = !qrOpen)}
                class="md:hidden min-h-11"
                aria-expanded={qrOpen}
              >
                <QrCodeIcon class="size-4" />
                {qrOpen ? t('hero.qrHide') : t('hero.qrShow')}
              </Button>
            {/if}
          </div>

          <!-- One-tap import: pick your app and the QR + button carry its
               deep-link import scheme. Scanning a plain https link just opens a
               browser, so this is how a scan/tap lands straight in the app. -->
          <div class="space-y-2 pt-1">
            <p class="text-xs uppercase tracking-wider text-muted-foreground font-semibold">
              {t('hero.importTitle')}
            </p>
            <div class="flex flex-wrap gap-1.5">
              <button
                type="button"
                onclick={() => (importApp = null)}
                aria-pressed={importApp === null}
                class="min-h-9 rounded-md px-2.5 py-1 text-xs font-medium transition-colors {importApp ===
                null
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted text-muted-foreground hover:text-foreground'}"
              >
                {t('hero.importPlain')}
              </button>
              {#each IMPORT_APPS as a (a.id)}
                <button
                  type="button"
                  onclick={() => (importApp = a)}
                  aria-pressed={importApp?.id === a.id}
                  class="min-h-9 rounded-md px-2.5 py-1 text-xs font-medium transition-colors {importApp?.id ===
                  a.id
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-muted text-muted-foreground hover:text-foreground'}"
                >
                  {a.name}
                </button>
              {/each}
            </div>
            {#if importApp}
              <a
                href={qrValue}
                class="inline-flex min-h-11 items-center justify-center gap-2 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
              >
                <Smartphone class="size-4" />
                {t('hero.importOpen', { app: importApp.name })}
              </a>
              <p class="text-xs text-muted-foreground">{t('hero.importOpenHint')}</p>
            {/if}
          </div>
        </div>

        {#if showQr}
          <!-- Desktop: always-visible QR. Mobile: collapsible. -->
          <div class="hidden md:block">
            <QrCode text={qrValue} size={144} />
            <p class="mt-2 text-xs text-muted-foreground text-center max-w-[144px]">
              {importApp ? t('hero.importScan', { app: importApp.name }) : t('hero.scanPhone')}
            </p>
          </div>
          {#if qrOpen}
            <div class="md:hidden flex flex-col items-center pt-2" in:fade={{ duration: 200 }}>
              <QrCode text={qrValue} size={192} />
              <p class="mt-2 text-xs text-muted-foreground">
                {importApp ? t('hero.importScan', { app: importApp.name }) : t('hero.scanOther')}
              </p>
            </div>
          {/if}
        {/if}
      </div>

      <!-- Fallback URL: secondary, equal billing as a peer alternative -->
      {#if fallbackUrl && fallbackUrl !== subscriptionUrl}
        <div class="space-y-2 pt-2 border-t border-border/60">
          <div
            class="flex items-center justify-between gap-2 text-xs uppercase tracking-wider text-muted-foreground font-semibold"
          >
            <span>{t('hero.fallbackLabel')}</span>
            <span class="text-muted-foreground normal-case font-normal text-[11px] tracking-normal">
              {t('hero.fallbackHint')}
            </span>
          </div>
          <div class="flex gap-2">
            <code
              class="flex-1 select-all px-3 py-2 rounded-md bg-muted text-xs font-mono break-all min-w-0 text-muted-foreground"
            >
              {fallbackUrl}
            </code>
            <Button
              variant="outline"
              size="sm"
              class="min-h-11"
              onclick={() => copy(fallbackUrl, 'fallback')}
            >
              {#if copied === 'fallback'}
                <Check class="size-3.5" />
              {:else}
                <Copy class="size-3.5" />
              {/if}
            </Button>
            {#if showQr}
              <Button
                variant="outline"
                size="sm"
                class="min-h-11"
                onclick={() => (qrFallbackOpen = !qrFallbackOpen)}
                aria-expanded={qrFallbackOpen}
                aria-label={t('hero.fallbackQrAria')}
              >
                <QrCodeIcon class="size-3.5" />
              </Button>
            {/if}
          </div>
          {#if showQr && qrFallbackOpen}
            <div class="flex flex-col items-center pt-2" in:fade={{ duration: 200 }}>
              <QrCode text={fallbackUrl} size={176} />
              <p class="mt-2 text-xs text-muted-foreground">{t('hero.scanFallback')}</p>
            </div>
          {/if}
        </div>
      {/if}
    {:else}
      <p class="text-sm text-muted-foreground">{t('hero.configBelowNote')}</p>
    {/if}

    <!-- Live-status callout: explains a stopped connection (over quota / disabled /
         expired). Silent when the key is active or the backend was unreachable. -->
    {#if keyIssue}
      <div
        class="rounded-lg border px-3 py-2 text-sm {keyIssue === 'limited'
          ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300'
          : 'border-destructive/40 bg-destructive/10 text-destructive'}"
      >
        {keyIssue === 'limited'
          ? t('hero.keyLimited')
          : keyIssue === 'expired'
            ? t('hero.keyExpired')
            : t('hero.keyDisabled')}
      </div>
    {/if}

    <!-- Metadata strip: traffic + expiry -->
    <div class="grid gap-4 sm:grid-cols-2 pt-2 border-t border-border/60">
      <!-- Traffic -->
      <div>
        <div class="flex items-center justify-between mb-1.5">
          <span
            class="flex items-center gap-1.5 text-xs uppercase tracking-wider text-muted-foreground font-semibold"
          >
            <Gauge class="size-3.5" />
            {t('hero.traffic')}
          </span>
          {#if trafficLimitBytes !== null}
            <span class="text-sm tabular-nums">
              {formatBytes(trafficUsedBytes)} / {formatBytes(trafficLimitBytes)}
            </span>
          {:else}
            <span
              class="rounded-full bg-primary/10 text-primary text-[11px] font-medium px-2 py-0.5"
            >
              {t('hero.unlimited')}
            </span>
          {/if}
        </div>
        {#if trafficLimitBytes !== null}
          <div class="h-1.5 rounded-full bg-muted overflow-hidden">
            <div
              class="h-full {usageColor} transition-all duration-500"
              style="width: {usagePct}%"
            ></div>
          </div>
          {#if usagePct >= 70}
            <p class="text-[11px] text-muted-foreground mt-1.5 tabular-nums">
              {usagePct >= 90
                ? t('hero.nearlyOut', { amount: formatBytes(trafficLimitBytes - trafficUsedBytes) })
                : t('hero.leftThisPeriod', {
                    amount: formatBytes(trafficLimitBytes - trafficUsedBytes),
                  })}
            </p>
          {/if}
          {#if nextResetDays !== null && nextResetDays >= 0}
            <p class="text-[11px] text-muted-foreground mt-1 tabular-nums">
              {t('hero.resetsInDays', { count: nextResetDays })}
            </p>
          {/if}
        {:else}
          <p class="text-[11px] text-muted-foreground tabular-nums">
            {t('hero.usedSoFar', { amount: formatBytes(trafficUsedBytes) })}
          </p>
        {/if}
      </div>

      <!-- Expiry -->
      <div>
        <div class="flex items-center justify-between mb-1.5">
          <span
            class="flex items-center gap-1.5 text-xs uppercase tracking-wider text-muted-foreground font-semibold"
          >
            <Calendar class="size-3.5" />
            {t('hero.expires')}
          </span>
          {#if expiryDate}
            <span class="text-sm tabular-nums {expiryUrgency}">
              {formatDate(expiryDate)}
            </span>
          {:else}
            <span class="text-sm text-muted-foreground">{t('hero.noExpiry')}</span>
          {/if}
        </div>
        {#if daysLeft !== null}
          <p class="text-[11px] tabular-nums {expiryUrgency}">
            {daysLeft < 0
              ? t('hero.expiredDaysAgo', { count: -daysLeft })
              : daysLeft === 0
                ? t('hero.expiresToday')
                : t('hero.daysRemaining', { count: daysLeft })}
          </p>
        {/if}
      </div>
    </div>
  </div>
</section>
