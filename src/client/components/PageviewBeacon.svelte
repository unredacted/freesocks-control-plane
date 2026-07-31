<script lang="ts">
  /**
   * Anonymous pageview beacon: fires trackPageview on every route change (and
   * on first paint, once /api/v1/config resolves) when the operator enabled
   * the Umami relay. Renders nothing.
   *
   * Lives in its OWN component inside <QueryClientProvider> for the same
   * reason as PopWarm: configQuery() reads the query client from Svelte
   * context at init, which App.svelte's own script runs too early for.
   * Mounted OUTSIDE the {#key router.pathname} block so the $effect re-runs on
   * navigation instead of the component remounting. The effect also re-runs on
   * config refetches — trackPageview's same-path dedupe absorbs those.
   * /admin is excluded inside trackPageview (shouldTrack).
   */
  import { configQuery } from '../lib/queries';
  import { router } from '../stores/router.svelte';
  import { trackPageview } from '../lib/analytics';

  const config = configQuery();
  $effect(() => {
    const path = router.pathname;
    if (config.data?.analytics.enabled !== true) return;
    trackPageview(path);
  });
</script>
