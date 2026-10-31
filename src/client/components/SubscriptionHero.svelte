<script lang="ts">
  import { fade } from 'svelte/transition';
  import { Button } from '@client/components/ui/button';
  import QrCode from './QrCode.svelte';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import Download from '@lucide/svelte/icons/download';
  import QrCodeIcon from '@lucide/svelte/icons/qr-code';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import { copyText } from '../lib/utils';
  import { t } from '../lib/i18n/index.svelte';
  import Link from './Link.svelte';
  import { toast } from 'svelte-sonner';
  import type { Snippet } from 'svelte';

  /**
   * The key pass: the product's signature object - a boarding-pass-style
   * card that hands someone their key. Big URL, one-click copy as the primary
   * action, QR on a perforated "stub" (dashed divider) for cross-device
   * handoff. Used on /get-account (step 3) and /account (connection tab),
   * identically headed "Your key" on both.
   *
   * Design decisions:
   * - One elevation level: border, no shadow (shadows are for overlays).
   * - The header is the title + a plain-text status line - no chips/badges;
   *   the live dot carries "is it up".
   * - Primary action is Copy (full-width on mobile, inline on desktop).
   * - QR is on the stub side of a dashed "perforation" at desktop, behind a
   *   toggle on mobile.
   * - Animated copy-success uses Check icon swap with a 1.5s rollback.
   * - The pass carries ONLY the key + its actions (2026-08 unclutter pass):
   *   traffic/expiry stats live in the sibling UsagePanel, and the fallback
   *   link sits behind a disclosure so the card reads as one object.
   */
  interface Props {
    title?: string;
    /** Display name for the backend (from config.backends.labels). Falls back
     *  to the built-in names so existing callers keep working. */
    backendLabel?: string;
    subscriptionUrl: string;
    fallbackUrl?: string;
    tierName: string;
    /** Soft amber banner shown above the card (e.g. "key already issued today"). */
    banner?: string;
    /** Whether to render the QR. Default true. Pass false for compact contexts. */
    showQr?: boolean;
    /**
     * Privacy mode: omit the big subscription URL + QR + copy block entirely and
     * show only the header + a pointer to the raw config below. The subscription
     * link is what a client fetches through a CDN, so "maximize privacy"
     * deliberately doesn't surface it as the headline.
     */
    hideUrl?: boolean;
    /**
     * Which backend issued the key. Drives label wording (Remnawave returns a
     * multi-protocol subscription URL; Outline returns a single `ss://` access
     * key) and the download filename. Defaults to `remnawave` so existing
     * callers keep their behavior.
     */
    backend?: string;
    /** Delivery is a single bare access key (no subscription document). From
     *  the backend's public capabilities; defaults to the historical
     *  outline-only heuristic for older callers. */
    accessKeyOnly?: boolean;
    /** Live key state from the backend (undefined/'unknown' when unreachable).
     *  `limited`/`disabled`/`expired` surface a "why your VPN stopped" callout. */
    status?: 'active' | 'disabled' | 'limited' | 'expired' | 'unknown';
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
    /** Origin edges: refresh nudge + connection labels (labels only). */
    nodeRelay?: {
      refreshSuggested: boolean;
      connections: Array<{ label: string; role: string; family: string }>;
    } | null;
    /** Optional key-management actions (switch server / regenerate / switch
     *  backend), rendered in a hairline-separated footer of the pass - the
     *  pass owns its actions, and each action's modal owns its explanation. */
    actions?: Snippet;
  }
  let {
    title,
    backendLabel,
    subscriptionUrl,
    fallbackUrl,
    tierName,
    banner,
    showQr = true,
    hideUrl = false,
    backend = 'remnawave',
    accessKeyOnly = undefined,
    status,
    nodeOnline,
    nodeLocationLabel,
    nodeLocationCode,
    nodeLabel,
    nodeLoad,
    nodeRelay = null,
    actions,
  }: Props = $props();

  // Outline keys are bare `ss://` URLs that VPN clients import as a single
  // "access key", not as a multi-protocol subscription. Use the right noun in
  // the UI so the user knows what they're looking at. All labels resolve in
  // $derived so a locale switch re-renders them (t() reads $state).
  let resolvedTitle = $derived(title ?? t('hero.titleDefault'));
  // The labels of this key's main and backup connections, when it has a backup.
  let relayBackup = $derived.by(() => {
    const primary = nodeRelay?.connections.find((c) => c.role === 'primary')?.label;
    const backup = nodeRelay?.connections.find((c) => c.role === 'backup')?.label;
    return primary && backup ? { primary, backup } : null;
  });
  let isAccessKey = $derived(accessKeyOnly ?? backend === 'outline');
  let urlLabel = $derived(
    isAccessKey ? t('hero.urlLabelAccessKey') : t('hero.urlLabelSubscription'),
  );
  let resolvedBackendLabel = $derived(backendLabel ?? (isAccessKey ? 'Outline' : 'Xray'));
  let downloadFilename = $derived(
    isAccessKey ? 'freesocks-outline.txt' : 'freesocks-subscription.txt',
  );

  let copied = $state<'primary' | 'fallback' | null>(null);
  let qrOpen = $state(false);
  let qrFallbackOpen = $state(false);
  // Fallback link disclosure: collapsed by default so the pass reads as one
  // object (most members never need it; the hint on the toggle says when to).
  let fallbackOpen = $state(false);
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
</script>

<section class="overflow-hidden rounded-lg border border-border/70 bg-card text-card-foreground">
  {#if banner}
    <div
      class="border-b border-amber-500/30 bg-amber-500/10 px-[clamp(20px,2.4vw,28px)] py-2.5 text-[15px] text-amber-700 dark:text-amber-300"
    >
      {banner}
    </div>
  {/if}

  <div class="space-y-6 p-[clamp(20px,2.4vw,28px)]">
    <!-- Pass header: title + plain-text status lines. -->
    <div class="space-y-1.5">
      <h2 class="text-2xl font-bold leading-tight tracking-[-0.01em] rtl:tracking-normal">
        {resolvedTitle}
      </h2>
      <p class="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[15px] text-muted-foreground">
        <span class="text-foreground">{t('hero.tierLine', { tier: tierName })}</span>
        <span aria-hidden="true">·</span>
        <span>{t('hero.viaLine', { backend: resolvedBackendLabel })}</span>
      </p>
      <!-- Node status, ONE compact line: a square status mark and the state in
           words (the tooltip adds the node label), the location and load band,
           and the status deep link. -->
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
        <p class="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[15px] text-muted-foreground">
          {#if nodeOnline !== undefined}
            <span
              class="inline-flex items-center gap-2 {nodeOnline === true
                ? 'text-foreground'
                : nodeOnline === false
                  ? 'text-destructive'
                  : ''}"
              role="status"
              title={dotLabel}
            >
              <span
                class="size-[9px] shrink-0 {nodeOnline === true
                  ? 'bg-primary'
                  : nodeOnline === false
                    ? 'bg-destructive'
                    : 'bg-muted-foreground/50'}"
                aria-hidden="true"
              ></span>
              {nodeStateText}
            </span>
          {/if}
          {#if nodeLocationLabel}
            {#if nodeOnline !== undefined}<span aria-hidden="true">·</span>{/if}
            <span>{nodeLocationLabel}{loadText ? ` · ${loadText}` : ''}</span>
          {/if}
          {#if nodeLocationCode}
            <span aria-hidden="true">·</span>
            <Link href="/status#loc-{nodeLocationCode}" class="link-brand text-foreground">
              {t('hero.nodeStatusLink')}
            </Link>
          {/if}
        </p>
      {/if}
      {#if nodeRelay?.refreshSuggested}
        <p
          class="mt-1 rounded-sm border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-[15px] text-amber-800 dark:text-amber-200"
          role="status"
        >
          {t('hero.relayRefreshSuggested')}
        </p>
      {/if}
      {#if nodeRelay && nodeRelay.connections.length > 0}
        <p class="text-sm text-muted-foreground">
          {t('hero.relayConnections')}
          <span class="text-foreground"
            >{nodeRelay.connections.map((c) => c.label).join(' · ')}</span
          >
        </p>
        <!-- An app that imports a plain link list (Anywhere, v2rayNG...) shows the
             main and backup entries side by side and never switches on its own. -->
        {#if relayBackup}
          <p class="text-sm text-muted-foreground">
            {t('hero.relayBackupHint', relayBackup)}
          </p>
        {/if}
      {/if}
    </div>

    {#if !hideUrl}
      <!-- Main zone: URL + actions on the left, QR on the perforated stub. -->
      <div class="grid gap-6 md:grid-cols-[1fr_auto] md:items-start">
        <div class="space-y-3 min-w-0">
          <label for="primary-url" class="block text-sm text-muted-foreground">
            {urlLabel}
          </label>
          <div class="rounded-sm border border-border bg-well px-4 py-3.5">
            <code
              id="primary-url"
              dir="ltr"
              class="block select-all break-all font-mono text-[15px] leading-relaxed text-foreground"
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
          <div class="ms-2 hidden border-s border-border/70 ps-6 md:block">
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

      <!-- Fallback URL: behind a disclosure - most members never need it, and
           always-open it made the pass read as two competing links. -->
      {#if fallbackUrl && fallbackUrl !== subscriptionUrl}
        <div class="space-y-2 border-t border-border/70 pt-4">
          <button
            type="button"
            onclick={() => (fallbackOpen = !fallbackOpen)}
            aria-expanded={fallbackOpen}
            class="flex w-full min-h-11 items-center justify-between gap-2 rounded-sm text-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <span class="text-[15px]">
              <strong class="font-bold text-foreground">{t('hero.fallbackLabel')}</strong>
              <span class="text-muted-foreground">{t('hero.fallbackHint')}</span>
            </span>
            <span class="flex items-center text-muted-foreground">
              <ChevronDown
                class="size-3.5 shrink-0 transition-transform {fallbackOpen ? 'rotate-180' : ''}"
                aria-hidden="true"
              />
            </span>
          </button>
          {#if fallbackOpen}
            <div class="flex gap-2" in:fade={{ duration: 150 }}>
              <code
                dir="ltr"
                class="min-w-0 flex-1 select-all break-all rounded-sm border border-border bg-well px-3 py-2 font-mono text-sm text-foreground"
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
            class="flex items-start gap-2 rounded-sm border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-300"
            role="note"
          >
            <TriangleAlert class="size-4 shrink-0 mt-0.5" aria-hidden="true" />
            <span>{t('hero.urlDangerBody')}</span>
          </div>
          <div class="flex gap-2">
            <code
              dir="ltr"
              class="min-w-0 flex-1 select-all break-all rounded-sm border border-border bg-well px-3 py-2 font-mono text-sm text-foreground"
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
        class="rounded-sm border border-destructive/40 bg-destructive/10 px-3 py-2 text-[15px] text-destructive"
      >
        {t('hero.nodeOfflineBody')}
      </div>
    {/if}

    <!-- Live-status callout: explains a stopped connection (over quota / disabled /
         expired). Silent when the key is active or the backend was unreachable. -->
    {#if keyIssue}
      <div
        class="rounded-sm border px-3 py-2 text-[15px] {keyIssue === 'limited'
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

    <!-- Traffic/expiry stats moved to the sibling UsagePanel (2026-08 unclutter
         pass) - the pass carries only the key and its actions. -->

    <!-- Pass footer: the key-management actions live ON the pass. -->
    {#if actions}
      <div class="border-t border-border/70 pt-5">
        {@render actions()}
      </div>
    {/if}
  </div>
</section>
