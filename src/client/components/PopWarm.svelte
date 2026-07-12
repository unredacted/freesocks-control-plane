<script lang="ts">
  /**
   * Boot-warm the proof-of-possession signing worker for an authenticated
   * session (loads the persisted key + fetches the server-time offset off the
   * first request's critical path; matters when POP_REQUIRED is on). Never for
   * an anonymous visitor.
   *
   * This lives in its OWN component, rendered INSIDE <QueryClientProvider>,
   * because meQuery() -> createQuery() reads the query client from Svelte
   * context at init. App.svelte hosts the provider, so its script runs BEFORE
   * its own provider child mounts - calling meQuery() there threw
   * "No QueryClient was found in Svelte context" and crashed the whole SPA.
   * Renders nothing.
   */
  import { meQuery } from '../lib/queries';
  import { prewarm } from '../lib/pop';

  const me = meQuery();
  let warmed = false;
  $effect(() => {
    if (!warmed && me.data?.authenticated) {
      warmed = true;
      void prewarm('member');
    }
  });
</script>
