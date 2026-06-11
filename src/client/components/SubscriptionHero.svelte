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
  import { formatBytes } from '../lib/utils';
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
     * Which backend issued the key. Drives label wording (Remnawave returns a
     * multi-protocol subscription URL; Outline returns a single `ss://` access
     * key) and the download filename. Defaults to `remnawave` so existing
     * callers keep their behavior.
     */
    backend?: 'remnawave' | 'outline';
  }
  let {
    title = 'Your subscription',
    eyebrow,
    subscriptionUrl,
    fallbackUrl,
    expiresAt,
    trafficLimitBytes,
    trafficUsedBytes,
    tierName,
    banner,
    showQr = true,
    backend = 'remnawave',
  }: Props = $props();

  // Outline keys are bare `ss://` URLs that VPN clients import as a single
  // "access key", not as a multi-protocol subscription. Use the right noun in
  // the UI so the user knows what they're looking at.
  let urlLabel = $derived(backend === 'outline' ? 'Access key' : 'Subscription URL');
  let downloadFilename = $derived(
    backend === 'outline' ? 'freesocks-outline.txt' : 'freesocks-subscription.txt',
  );

  let copied = $state<'primary' | 'fallback' | null>(null);
  let qrOpen = $state(false);
  let qrFallbackOpen = $state(false);

  async function copy(value: string, key: 'primary' | 'fallback') {
    try {
      await navigator.clipboard.writeText(value);
      copied = key;
      toast.success('Copied to clipboard', { duration: 1500 });
      setTimeout(() => {
        if (copied === key) copied = null;
      }, 1500);
    } catch {
      toast.error('Copy failed. Select the URL and copy it manually.');
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
    toast.success(`Downloaded ${downloadFilename}`);
  }

  // Traffic percentage, only meaningful when there's a limit.
  let usagePct = $derived(
    trafficLimitBytes ? Math.min(100, (trafficUsedBytes / trafficLimitBytes) * 100) : 0,
  );
  let usageColor = $derived(
    usagePct >= 90 ? 'bg-destructive' : usagePct >= 70 ? 'bg-amber-500' : 'bg-primary',
  );

  // Expiry: convert + classify (so we can hint when it's close).
  let expiryDate = $derived(expiresAt ? new Date(expiresAt) : null);
  let daysLeft = $derived(
    expiryDate ? Math.ceil((expiryDate.getTime() - Date.now()) / 86_400_000) : null,
  );
  let expiryUrgency = $derived(
    daysLeft !== null && daysLeft <= 7
      ? 'text-amber-600 dark:text-amber-400'
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
        {title}
      </h2>
      <p class="text-sm text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1">
        <span class="inline-flex items-center gap-1">
          Tier <strong class="text-foreground">{tierName}</strong>
        </span>
        <span class="text-muted-foreground/60">·</span>
        <span class="inline-flex items-center gap-1">
          via{' '}
          <strong class="text-foreground">
            {backend === 'outline' ? 'Outline' : 'Xray'}
          </strong>
        </span>
      </p>
    </div>

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
            class="block font-mono text-xs md:text-sm break-all pe-2 leading-relaxed text-foreground/90"
          >
            {subscriptionUrl}
          </code>
        </div>
        <div class="flex flex-wrap gap-2">
          <Button
            onclick={() => copy(subscriptionUrl, 'primary')}
            class="flex-1 sm:flex-initial transition-all"
            size="lg"
          >
            {#if copied === 'primary'}
              <span in:fade={{ duration: 150 }} class="inline-flex items-center gap-2">
                <Check class="size-4" />
                Copied
              </span>
            {:else}
              <span in:fade={{ duration: 150 }} class="inline-flex items-center gap-2">
                <Copy class="size-4" />
                Copy URL
              </span>
            {/if}
          </Button>
          <Button variant="outline" size="lg" onclick={downloadConfig}>
            <Download class="size-4" />
            <span class="hidden sm:inline">Download</span>
          </Button>
          {#if showQr}
            <Button
              variant="outline"
              size="lg"
              onclick={() => (qrOpen = !qrOpen)}
              class="md:hidden"
              aria-expanded={qrOpen}
            >
              <QrCodeIcon class="size-4" />
              {qrOpen ? 'Hide' : 'QR'}
            </Button>
          {/if}
        </div>
      </div>

      {#if showQr}
        <!-- Desktop: always-visible QR. Mobile: collapsible. -->
        <div class="hidden md:block">
          <QrCode text={subscriptionUrl} size={144} />
          <p class="mt-2 text-xs text-muted-foreground text-center max-w-[144px]">
            Scan with your phone
          </p>
        </div>
        {#if qrOpen}
          <div class="md:hidden flex flex-col items-center pt-2" in:fade={{ duration: 200 }}>
            <QrCode text={subscriptionUrl} size={192} />
            <p class="mt-2 text-xs text-muted-foreground">Scan with another device</p>
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
          <span>Fallback URL</span>
          <span class="text-muted-foreground normal-case font-normal text-[11px] tracking-normal">
            Use this if the main URL gets blocked
          </span>
        </div>
        <div class="flex gap-2">
          <code
            class="flex-1 px-3 py-2 rounded-md bg-muted text-xs font-mono break-all min-w-0 text-muted-foreground"
          >
            {fallbackUrl}
          </code>
          <Button variant="outline" size="sm" onclick={() => copy(fallbackUrl, 'fallback')}>
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
              onclick={() => (qrFallbackOpen = !qrFallbackOpen)}
              aria-expanded={qrFallbackOpen}
              aria-label="Show fallback URL QR code"
            >
              <QrCodeIcon class="size-3.5" />
            </Button>
          {/if}
        </div>
        {#if showQr && qrFallbackOpen}
          <div class="flex flex-col items-center pt-2" in:fade={{ duration: 200 }}>
            <QrCode text={fallbackUrl} size={176} />
            <p class="mt-2 text-xs text-muted-foreground">Scan the fallback on another device</p>
          </div>
        {/if}
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
            Traffic
          </span>
          {#if trafficLimitBytes !== null}
            <span class="text-sm tabular-nums">
              {formatBytes(trafficUsedBytes)} / {formatBytes(trafficLimitBytes)}
            </span>
          {:else}
            <span
              class="rounded-full bg-primary/10 text-primary text-[11px] font-medium px-2 py-0.5"
            >
              Unlimited
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
                ? `Nearly out, only ${formatBytes(trafficLimitBytes - trafficUsedBytes)} left this period.`
                : `${formatBytes(trafficLimitBytes - trafficUsedBytes)} left this period.`}
            </p>
          {/if}
        {:else}
          <p class="text-[11px] text-muted-foreground tabular-nums">
            {formatBytes(trafficUsedBytes)} used so far
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
            Expires
          </span>
          {#if expiryDate}
            <span class="text-sm tabular-nums {expiryUrgency}">
              {expiryDate.toLocaleDateString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
              })}
            </span>
          {:else}
            <span class="text-sm text-muted-foreground">No expiry</span>
          {/if}
        </div>
        {#if daysLeft !== null}
          <p class="text-[11px] tabular-nums {expiryUrgency}">
            {daysLeft < 0
              ? `Expired ${-daysLeft} day${-daysLeft === 1 ? '' : 's'} ago`
              : daysLeft === 0
                ? 'Expires today'
                : `${daysLeft} day${daysLeft === 1 ? '' : 's'} remaining`}
          </p>
        {/if}
      </div>
    </div>
  </div>
</section>
