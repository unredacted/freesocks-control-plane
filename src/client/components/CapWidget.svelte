<script lang="ts">
  /**
   * Self-hosted Cap captcha widget (W1) — the replacement for the Cloudflare
   * Turnstile component. `@cap.js/widget` is BUNDLED from npm (not a remote
   * script), and challenge traffic goes to our SAME-ORIGIN `/cap` path (Caddy
   * proxies it to the Cap service), so the app now loads ZERO third-party
   * scripts and works behind the GFW where challenges.cloudflare.com is blocked.
   *
   * Cap is proof-of-work: the browser solves a computational puzzle. That prices
   * abuse in CPU rather than detecting bots, so the per-IP rate limits (A1 + W2)
   * are the primary anti-abuse control; this raises the bar on top.
   *
   * Importing the package registers the <cap-widget> custom element. It emits
   * `solve` (detail.token), `error`, and `reset`. We surface a load/solve
   * failure as an explicit, actionable state (matching the old Turnstile UX)
   * rather than a silent dead-end.
   */
  import '@cap.js/widget';

  interface Props {
    apiEndpoint: string;
    siteKey: string;
    onVerify: (token: string) => void;
    /** Optional i18n strings; default to English. */
    i18n?: {
      initialState?: string;
      verifyingLabel?: string;
      solvedLabel?: string;
      errorLabel?: string;
    };
  }

  let { apiEndpoint, siteKey, onVerify, i18n }: Props = $props();

  let el = $state<HTMLElement | null>(null);
  let failed = $state(false);
  let retryNonce = $state(0);

  // data-cap-api-endpoint must be "<endpoint>/<siteKey>/" (trailing slash).
  const endpoint = $derived(`${apiEndpoint.replace(/\/$/, '')}/${siteKey}/`);

  $effect(() => {
    void retryNonce; // re-bind listeners on retry
    const node = el;
    if (!node) return;

    const onSolve = (e: Event) => {
      const token = (e as CustomEvent<{ token: string }>).detail?.token;
      if (token) onVerify(token);
    };
    const onError = (e: Event) => {
      console.error('Cap widget error', (e as CustomEvent).detail);
      failed = true;
      onVerify(''); // invalidate any stale token
    };
    const onReset = () => onVerify(''); // token expired / returned to initial state

    node.addEventListener('solve', onSolve);
    node.addEventListener('error', onError);
    node.addEventListener('reset', onReset);
    return () => {
      node.removeEventListener('solve', onSolve);
      node.removeEventListener('error', onError);
      node.removeEventListener('reset', onReset);
    };
  });

  function retry() {
    failed = false;
    onVerify('');
    retryNonce += 1;
  }
</script>

{#if failed}
  <div class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-3 text-sm">
    <p class="mb-1 font-semibold">Couldn't complete the human check.</p>
    <p class="text-muted-foreground">
      The check runs entirely in your browser. If it failed, your browser may be blocking the
      worker it needs, or the network dropped the request.
    </p>
    <ul class="mt-2 list-disc space-y-1 pl-5 text-xs text-muted-foreground">
      <li>Try disabling browser extensions</li>
      <li>Try a different network or a private/incognito window</li>
      <li>Make sure JavaScript and WebAssembly are enabled</li>
    </ul>
    <button type="button" class="mt-3 text-primary underline hover:no-underline" onclick={retry}>
      Retry
    </button>
  </div>
{:else}
  {#key retryNonce}
    <cap-widget
      bind:this={el}
      data-cap-api-endpoint={endpoint}
      data-cap-i18n-initial-state={i18n?.initialState}
      data-cap-i18n-verifying-label={i18n?.verifyingLabel}
      data-cap-i18n-solved-label={i18n?.solvedLabel}
      data-cap-i18n-error-label={i18n?.errorLabel}
    ></cap-widget>
  {/key}
{/if}
