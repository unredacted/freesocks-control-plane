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
   *
   * The PoW WASM + pako are served SAME-ORIGIN (cap-wasm-config, imported first)
   * so nothing is fetched from cdn.jsdelivr.net — preserving the zero-third-party
   * guarantee and working where that CDN is blocked.
   *
   * The widget package (+ its WASM plumbing) is LAZY-imported on mount: Login and
   * GetAccount sit on the statically-routed member entry chunk, so a static
   * import here would make every first-time visitor on the Home page download
   * the captcha machinery they may never use — real bytes on a censored, slow
   * link. cap-wasm-config must still load BEFORE the widget registers.
   */
  import { t } from '../lib/i18n/index.svelte';

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
  let widgetReady = $state(false);

  $effect(() => {
    void retryNonce; // a retry after a chunk-load failure re-attempts the import
    if (widgetReady) return;
    let cancelled = false;
    (async () => {
      try {
        await import('../lib/cap-wasm-config');
        await import('@cap.js/widget');
        if (!cancelled) widgetReady = true;
      } catch (err) {
        // Flaky network dropped the lazy chunk — same recovery UI as a solve error.
        console.error('Cap widget failed to load', err);
        if (!cancelled) failed = true;
      }
    })();
    return () => {
      cancelled = true;
    };
  });

  // data-cap-api-endpoint must be "<endpoint>/<siteKey>/" (trailing slash).
  const endpoint = $derived(`${apiEndpoint.replace(/\/$/, '')}/${siteKey}/`);

  // Widget labels default to the app catalog (reactive: t() reads the locale
  // $state) so every call site is translated without passing the prop.
  const labels = $derived({
    initialState: i18n?.initialState ?? t('captcha.initial'),
    verifyingLabel: i18n?.verifyingLabel ?? t('captcha.verifying'),
    solvedLabel: i18n?.solvedLabel ?? t('captcha.solved'),
    errorLabel: i18n?.errorLabel ?? t('captcha.error'),
  });

  $effect(() => {
    void retryNonce; // re-bind listeners on retry
    const node = el;
    if (!node) return;

    // The custom element dispatches `reset` from its disconnectedCallback, which
    // Svelte runs DURING its DOM teardown flush (when `failed` flips, the {#key}
    // remounts, or the page navigates away). Calling onVerify() straight from
    // there mutates the PARENT's `token` $state mid-flush -> Svelte throws
    // state_unsafe_mutation. So notify the parent on a microtask (outside the
    // flush), and drop it if THIS effect run has already been torn down (`alive`
    // is per-run, so a stale reset from an old widget can't clear a new token).
    let alive = true;
    const notify = (token: string) => {
      queueMicrotask(() => {
        if (alive) onVerify(token);
      });
    };

    const onSolve = (e: Event) => {
      const token = (e as CustomEvent<{ token: string }>).detail?.token;
      if (token) notify(token);
    };
    const onError = (e: Event) => {
      console.error('Cap widget error', (e as CustomEvent).detail);
      failed = true;
      notify(''); // invalidate any stale token
    };
    const onReset = () => notify(''); // token expired / returned to initial state

    node.addEventListener('solve', onSolve);
    node.addEventListener('error', onError);
    node.addEventListener('reset', onReset);
    return () => {
      alive = false;
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
    <p class="mb-1 font-semibold">{t('captcha.failedTitle')}</p>
    <p class="text-muted-foreground">
      {t('captcha.failedBody')}
    </p>
    <ul class="mt-2 list-disc space-y-1 ps-5 text-xs text-muted-foreground">
      <li>{t('captcha.failedTip1')}</li>
      <li>{t('captcha.failedTip2')}</li>
      <li>{t('captcha.failedTip3')}</li>
    </ul>
    <button type="button" class="mt-3 text-primary underline hover:no-underline" onclick={retry}>
      {t('common.retry')}
    </button>
  </div>
{:else if !widgetReady}
  <div
    class="flex min-h-11 items-center rounded-md border border-border px-3 text-sm text-muted-foreground"
    role="status"
  >
    {t('common.loading')}
  </div>
{:else}
  {#key retryNonce}
    <cap-widget
      bind:this={el}
      data-cap-api-endpoint={endpoint}
      data-cap-i18n-initial-state={labels.initialState}
      data-cap-i18n-verifying-label={labels.verifyingLabel}
      data-cap-i18n-solved-label={labels.solvedLabel}
      data-cap-i18n-error-label={labels.errorLabel}
    ></cap-widget>
  {/key}
{/if}
