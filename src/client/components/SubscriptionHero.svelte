<script lang="ts">
  import { fade } from 'svelte/transition';
  import { Button } from '@client/components/ui/button';
  import QrCode from './QrCode.svelte';
  import Sparkline from './Sparkline.svelte';
  import StatBlock from './StatBlock.svelte';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import Download from '@lucide/svelte/icons/download';
  import Calendar from '@lucide/svelte/icons/calendar';
  import Activity from '@lucide/svelte/icons/activity';
  import Gauge from '@lucide/svelte/icons/gauge';
  import QrCodeIcon from '@lucide/svelte/icons/qr-code';
  import Link2 from '@lucide/svelte/icons/link-2';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import MapPin from '@lucide/svelte/icons/map-pin';
  import { formatBytes, daysUntil, copyText } from '../lib/utils';
  import { t } from '../lib/i18n/index.svelte';
  import { formatDate } from '../lib/i18n/format';
  import Link from './Link.svelte';
  import { toast } from 'svelte-sonner';
  import type { Snippet } from 'svelte';

  /**
   * The key pass: the product's signature object - a boarding-pass-style
   * card that hands someone their key. Big URL, one-click copy as the primary
   * action, QR on a perforated "stub" (dashed divider) for cross-device
   * handoff, expiry/traffic as calm stat blocks. Used on /get-account (step 3)
   * and /account (connection tab), identically headed "Your key" on both.
   *
   * Design decisions:
   * - One elevation level: border, no shadow (shadows are for overlays).
   * - The header is the title + a plain-text status line - no chips/badges;
   *   the live dot carries "is it up".
   * - Primary action is Copy (full-width on mobile, inline on desktop).
   * - QR is on the stub side of a dashed "perforation" at desktop, behind a
   *   toggle on mobile.
   * - Animated copy-success uses Check icon swap with a 1.5s rollback.
   * - Traffic + expiry are StatBlocks with tabular-nums (no jiggle).
   */
  interface Props {
    title?: string;
    /** Display name for the backend (from config.backends.labels). Falls back
     *  to the built-in names so existing callers keep working. */
    backendLabel?: string;
    subscriptionUrl: string;
    fallbackUrl?: string;
    expiresAt: string | null;
    /** Free-tier key: the expiry stat becomes activity-framed ("Active while
     *  you use it") — free keys never expire on a calendar; only accounts idle
     *  for `idleDays` are paused. Ignores `expiresAt` entirely (keys issued
     *  before the no-expiry cutover may still carry a stale panel date). */
    freeTier?: boolean;
    /** The idle window (publicConfig.freeTierDays) for the free-key subline. */
    idleDays?: number;
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
    /** Aggregate usage trend (bytes per bucket) + period total, rendered under the
     *  traffic stats. Optional: omitted at sign-up (no key yet) and for backends
     *  without usage history (Outline degrades to null → no trend). */
    usagePoints?: number[];
    usageTotal?: number;
    /**
     * Live node status (polled): true/false when observed, null = unknown,
     * undefined = don't render the badge at all. Lets the member tell "the node
     * is up but my network filters it" from an actual outage.
     */
    nodeOnline?: boolean | null;
    /** Member-facing location of the node serving this key ("Kansas City, MO"). */
    nodeLocationLabel?: string | null;
    /** The location's code ("MCI") — anchors the "Network status" deep link. */
    nodeLocationCode?: string | null;
    /** The node's own display name (e.g. "MCI-2"), when the backend has one. */
    nodeLabel?: string | null;
    /** The location's coarse public load band (quiet/busy/crowded). */
    nodeLoad?: 'quiet' | 'busy' | 'crowded' | 'unknown' | null;
    /** Optional key-management actions (regenerate / switch backend), rendered
     *  in a hairline-separated footer of the pass - the pass owns its actions. */
    actions?: Snippet;
  }
  let {
    title,
    backendLabel,
    subscriptionUrl,
    fallbackUrl,
    expiresAt,
    freeTier = false,
    idleDays = 90,
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
    usagePoints,
    usageTotal,
    nodeOnline,
    nodeLocationLabel,
    nodeLocationCode,
    nodeLabel,
    nodeLoad,
    actions,
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
  // QR for the danger-gated URL reveal (rawConfig mode) — same exposure class
  // as the visible link + copy button beside it; the amber warning covers it.
  let qrHiddenUrlOpen = $state(false);
  // hideUrl escape hatch: the member can still reveal the (CDN-fetched) link
  // behind an explicit click + warning, for apps that can't import a raw config.
  let showHiddenUrl = $state(false);

  async function copy(value: string, key: 'primary' | 'fallback') {
    if (await copyText(value)) {
      copied = key;
      toast.success(t('common.copied'), { duration: 1500 });
      setTimeout(() => {
        if (copied === key) copied = null;
      }, 1500);
    } else {
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

<section class="rounded-xl border border-border bg-card text-card-foreground overflow-hidden">
  {#if banner}
    <div
      class="bg-amber-500/10 border-b border-amber-500/30 px-5 py-2.5 text-sm text-amber-700 dark:text-amber-300"
    >
      {banner}
    </div>
  {/if}

  <div class="p-6 md:p-8 space-y-6">
    <!-- Pass header: title + plain-text status line. -->
    <div class="space-y-1.5">
      <h2 class="text-xl md:text-2xl font-display font-bold tracking-tight">
        {resolvedTitle}
      </h2>
      <p class="text-sm text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1">
        <span class="font-medium text-foreground">{t('hero.tierLine', { tier: tierName })}</span>
        <span class="text-muted-foreground/60">·</span>
        <span>{t('hero.viaLine', { backend: resolvedBackendLabel })}</span>
      </p>
      <!-- Node status, ONE compact line: the live dot (tooltip carries the node
           label + load band + state) + location + the status deep link. Offline
           is the only state spelled out (it's the actionable one). -->
      {#if nodeLocationLabel || nodeOnline !== undefined || nodeLocationCode}
        {@const nodeStateText =
          nodeOnline === true
            ? t('hero.nodeOnline')
            : nodeOnline === false
              ? t('hero.nodeOffline')
              : t('hero.nodeUnknown')}
        {@const loadText =
          nodeLoad === 'quiet'
            ? t('status.loadQuiet')
            : nodeLoad === 'busy'
              ? t('status.loadBusy')
              : nodeLoad === 'crowded'
                ? t('status.loadCrowded')
                : null}
        {@const dotLabel = [nodeLabel, nodeStateText, loadText].filter(Boolean).join(' · ')}
        <p class="text-sm text-muted-foreground flex flex-wrap items-center gap-x-2 gap-y-1">
          {#if nodeOnline !== undefined}
            <span
              class="inline-flex size-2 rounded-full shrink-0 {nodeOnline === true
                ? 'bg-emerald-500'
                : nodeOnline === false
                  ? 'bg-destructive'
                  : 'bg-muted-foreground/50'}"
              role="status"
              title={dotLabel}
              aria-label={dotLabel}
            ></span>
          {/if}
          {#if nodeOnline === false}
            <span class="text-destructive">{t('hero.nodeOffline')}</span>
            <span class="text-muted-foreground/60">·</span>
          {/if}
          {#if nodeLocationLabel}
            <span class="inline-flex items-center gap-1">
              <MapPin class="size-3.5" aria-hidden="true" />
              {nodeLocationLabel}
            </span>
          {/if}
          {#if nodeLocationCode}
            <span class="text-muted-foreground/60">·</span>
            <Link
              href="/status#loc-{nodeLocationCode}"
              class="inline-flex items-center gap-1 underline underline-offset-2 hover:text-foreground"
            >
              {t('hero.nodeStatusLink')} →
            </Link>
          {/if}
        </p>
      {/if}
    </div>

    {#if !hideUrl}
      <!-- Main zone: URL + actions on the left, QR on the perforated stub. -->
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
        </div>

        {#if showQr}
          <!-- The stub: QR on the far side of the dashed "perforation". -->
          <div class="hidden md:block border-s border-dashed border-border ps-6 ms-2">
            <QrCode text={subscriptionUrl} size={144} />
            <p class="mt-2 text-xs text-muted-foreground text-center max-w-[144px]">
              {t('hero.scanPhone')}
            </p>
          </div>
          {#if qrOpen}
            <div class="md:hidden flex flex-col items-center pt-2" in:fade={{ duration: 200 }}>
              <QrCode text={subscriptionUrl} size={192} />
              <p class="mt-2 text-xs text-muted-foreground">{t('hero.scanOther')}</p>
            </div>
          {/if}
        {/if}
      </div>

      <!-- Fallback URL: secondary, hairline-separated inside the pass. -->
      {#if fallbackUrl && fallbackUrl !== subscriptionUrl}
        <div class="space-y-2 pt-4 border-t border-border/60">
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
      <div class="space-y-3">
        <p class="text-sm text-muted-foreground">{t('hero.configBelowNote')}</p>
        {#if !showHiddenUrl}
          <button
            type="button"
            class="text-xs text-muted-foreground underline hover:text-foreground"
            onclick={() => (showHiddenUrl = true)}
          >
            {t('hero.showUrlAnyway')}
          </button>
        {:else}
          <!-- The disclaimer is not dismissible-separately-from-the-URL on
               purpose: as long as the link is visible, so is the warning. -->
          <div
            class="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300"
            role="note"
          >
            <TriangleAlert class="size-4 shrink-0 mt-0.5" aria-hidden="true" />
            <span>{t('hero.urlDangerBody')}</span>
          </div>
          <div class="flex gap-2">
            <code
              class="flex-1 select-all px-3 py-2 rounded-md bg-muted text-xs font-mono break-all min-w-0 text-muted-foreground"
            >
              {subscriptionUrl}
            </code>
            <Button
              variant="outline"
              size="sm"
              class="min-h-11"
              onclick={() => copy(subscriptionUrl, 'primary')}
              aria-label={t('hero.copyUrl')}
            >
              {#if copied === 'primary'}
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
                onclick={() => (qrHiddenUrlOpen = !qrHiddenUrlOpen)}
                aria-expanded={qrHiddenUrlOpen}
                aria-label={qrHiddenUrlOpen ? t('hero.qrHide') : t('hero.qrShow')}
              >
                <QrCodeIcon class="size-3.5" />
              </Button>
            {/if}
          </div>
          {#if showQr && qrHiddenUrlOpen}
            <div class="flex flex-col items-center pt-2" in:fade={{ duration: 200 }}>
              <QrCode text={subscriptionUrl} size={176} />
              <p class="mt-2 text-xs text-muted-foreground">{t('hero.scanOther')}</p>
            </div>
          {/if}
        {/if}
      </div>
    {/if}

    <!-- Node-offline callout: the outage is on our side, not the member's network.
         (The green/online state needs no callout - the badge + tooltip carry it.) -->
    {#if nodeOnline === false}
      <div
        class="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
      >
        {t('hero.nodeOfflineBody')}
      </div>
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

    <!-- Meta zone: traffic + expiry as stat blocks under a hairline. -->
    <div class="grid gap-4 sm:grid-cols-2 pt-4 border-t border-border/60">
      <StatBlock icon={Gauge} label={t('hero.traffic')}>
        {#if trafficLimitBytes !== null}
          <p class="text-sm tabular-nums">
            {formatBytes(trafficUsedBytes)} / {formatBytes(trafficLimitBytes)}
          </p>
          <div class="h-1.5 rounded-full bg-muted overflow-hidden">
            <div
              class="h-full {usageColor} transition-all duration-500"
              style="width: {usagePct}%"
            ></div>
          </div>
          {#if usagePct >= 70}
            <p class="text-[11px] text-muted-foreground tabular-nums">
              {usagePct >= 90
                ? t('hero.nearlyOut', {
                    amount: formatBytes(Math.max(0, trafficLimitBytes - trafficUsedBytes)),
                  })
                : t('hero.leftThisPeriod', {
                    amount: formatBytes(Math.max(0, trafficLimitBytes - trafficUsedBytes)),
                  })}
            </p>
          {/if}
          {#if nextResetDays !== null && nextResetDays >= 0}
            <p class="text-[11px] text-muted-foreground tabular-nums">
              {t('hero.resetsInDays', { count: nextResetDays })}
            </p>
          {/if}
        {:else}
          <p>
            <span
              class="rounded-full bg-primary/10 text-primary text-[11px] font-medium px-2 py-0.5"
            >
              {t('hero.unlimited')}
            </span>
          </p>
          <p class="text-[11px] text-muted-foreground tabular-nums">
            {t('hero.usedSoFar', { amount: formatBytes(trafficUsedBytes) })}
          </p>
        {/if}

        <!-- Usage trend, shown by default. A quiet/new key draws a flat baseline
             (not hidden). Absent only when there's no usage data at all. -->
        {#if usagePoints && usagePoints.length > 0}
          <div class="pt-2 space-y-1">
            <div class="text-primary">
              <Sparkline points={usagePoints} class="w-full h-10" />
            </div>
            {#if usageTotal !== undefined}
              <p class="text-[11px] text-muted-foreground tabular-nums">
                {t('usage.total', { amount: formatBytes(usageTotal) })}
              </p>
            {/if}
          </div>
        {/if}
      </StatBlock>

      {#if freeTier}
        <!-- Free keys have no calendar expiry (the panel carries the no-expiry
             sentinel; the usage-based idle sweep governs) — frame the stat
             around activity instead of a date. -->
        <StatBlock icon={Activity} label={t('hero.validityLabel')}>
          <p class="text-sm">{t('hero.staysActive')}</p>
          <p class="text-[11px] text-muted-foreground">
            {t('hero.idleNote', { days: idleDays })}
          </p>
        </StatBlock>
      {:else}
        <StatBlock icon={Calendar} label={t('hero.expires')}>
          {#if expiryDate}
            <p class="text-sm tabular-nums {expiryUrgency}">
              {formatDate(expiryDate)}
            </p>
          {:else}
            <p class="text-sm text-muted-foreground">{t('hero.noExpiry')}</p>
          {/if}
          {#if daysLeft !== null}
            <p class="text-[11px] tabular-nums {expiryUrgency}">
              {daysLeft < 0
                ? t('hero.expiredDaysAgo', { count: -daysLeft })
                : daysLeft === 0
                  ? t('hero.expiresToday')
                  : t('hero.daysRemaining', { count: daysLeft })}
            </p>
          {/if}
        </StatBlock>
      {/if}
    </div>

    <!-- Pass footer: the key-management actions live ON the pass. -->
    {#if actions}
      <div class="pt-4 border-t border-border/60">
        {@render actions()}
      </div>
    {/if}
  </div>
</section>
