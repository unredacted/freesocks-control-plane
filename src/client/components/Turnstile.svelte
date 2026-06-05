<script lang="ts" module>
  declare global {
    interface Window {
      turnstile?: {
        render(
          container: HTMLElement,
          opts: {
            sitekey: string;
            callback: (token: string) => void;
            theme?: 'auto' | 'light' | 'dark';
          },
        ): string;
        reset(widgetId?: string): void;
      };
      onTurnstileLoad?: () => void;
    }
  }
</script>

<script lang="ts">
  /**
   * Loads `https://challenges.cloudflare.com/turnstile/v0/api.js` and renders
   * the widget. If the script fails to load (CSP block, restrictive network,
   * browser extension blocking, etc.), surfaces an explicit error state with
   * a retry — not a silent dead-end.
   *
   * IMPORTANT — policy exception. The codebase otherwise bans third-party
   * scripts and resources (see CLAUDE.md's "No third-party resources"
   * section). Turnstile is the singular allowed exception because:
   *
   *   1. It is fundamentally a service, not a library. The api.js file
   *      embeds a cross-origin iframe that performs the bot check by
   *      communicating with Cloudflare's verification backend over the
   *      embedding origin. Self-hosting the JS file does not bypass that;
   *      it just breaks the widget entirely.
   *   2. It is load-bearing for anti-abuse. The free-tier rate-limiter (KV
   *      + D1 backstop) is the second line of defense; Turnstile is the
   *      first. Removing it lets attackers mint free-tier keys at machine
   *      speed.
   *   3. It is same-trust-boundary. The control plane already runs on
   *      Cloudflare Workers and uses Cloudflare D1, KV, and Email Sending.
   *      Adding `challenges.cloudflare.com` to the trust set does not
   *      meaningfully expand the surface area.
   *
   * If a self-hostable alternative becomes available (a different captcha
   * provider with a bundleable widget, or an alternative anti-abuse design
   * — proof-of-work, identity proofs, etc.) this exception should be
   * revisited.
   */
  interface Props {
    siteKey: string;
    onVerify: (token: string) => void;
    theme?: 'auto' | 'light' | 'dark';
  }

  let { siteKey, onVerify, theme = 'auto' }: Props = $props();

  let container = $state<HTMLDivElement | null>(null);
  let widgetId = $state<string | null>(null);
  let loadFailed = $state(false);
  let retryNonce = $state(0);

  $effect(() => {
    // Read all reactive deps so this re-runs on retry / siteKey / theme change.
    void siteKey;
    void theme;
    void retryNonce;

    loadFailed = false;
    let abandoned = false;

    const renderWidget = () => {
      if (abandoned || !container || !window.turnstile) return;
      try {
        widgetId = window.turnstile.render(container, {
          sitekey: siteKey,
          callback: onVerify,
          theme,
        });
      } catch (err) {
        // Widget render itself failed (rare; mostly bad sitekey).
        console.error('Turnstile render failed', err);
        loadFailed = true;
      }
    };

    if (window.turnstile) {
      renderWidget();
      return () => {
        abandoned = true;
        if (widgetId && window.turnstile) window.turnstile.reset(widgetId);
      };
    }

    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad';
    script.async = true;
    script.defer = true;
    window.onTurnstileLoad = renderWidget;

    // Fallback: if neither onload fires nor onerror within 10s, surface error.
    const watchdog = setTimeout(() => {
      if (!window.turnstile) loadFailed = true;
    }, 10000);

    script.onerror = () => {
      console.error('Turnstile script failed to load');
      loadFailed = true;
    };

    document.head.appendChild(script);

    return () => {
      abandoned = true;
      clearTimeout(watchdog);
      if (widgetId && window.turnstile) window.turnstile.reset(widgetId);
    };
  });

  function retry() {
    loadFailed = false;
    retryNonce += 1;
  }
</script>

{#if loadFailed}
  <div class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-3 text-sm">
    <p class="font-semibold mb-1">Couldn't load the human-check widget.</p>
    <p class="text-muted-foreground">
      This usually means a network filter, browser extension, or restrictive corporate firewall is
      blocking <code class="font-mono">challenges.cloudflare.com</code>.
    </p>
    <ul class="list-disc pl-5 mt-2 text-xs text-muted-foreground space-y-1">
      <li>Try disabling browser extensions (uBlock, Privacy Badger)</li>
      <li>Try a different network</li>
      <li>Try a different browser or private/incognito window</li>
    </ul>
    <button type="button" class="mt-3 underline text-primary hover:no-underline" onclick={retry}>
      Retry
    </button>
  </div>
{:else}
  <div bind:this={container} class="cf-turnstile"></div>
{/if}
