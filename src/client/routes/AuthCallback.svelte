<script lang="ts">
  // Server handles the actual /api/auth/callback redirect; this client route
  // exists only as a landing page in case the OIDC redirect URI is set to a
  // frontend path during certain development setups. The server-side route
  // does the work and 302s us forward.
  import Link from '../components/Link.svelte';
  import { Button } from '@client/components/ui/button';
  import { router } from '../stores/router.svelte';

  // If Authentik returned an error in the query string, surface it so the
  // user isn't stuck on a blank "signing you in" forever.
  let oidcError = $derived(router.searchParams.get('error'));
  let oidcErrorDescription = $derived(router.searchParams.get('error_description'));
  $effect(() => {
    if (oidcError) return; // don't redirect if there's an OIDC error to display
    // The server normally 302s before this SPA route even renders. If we do
    // land here (e.g. a dev redirect_uri pointing at the frontend), forward to
    // /account — the session cookie set by the callback takes effect there.
    router.navigate('/account', { replace: true });
  });
</script>

{#if oidcError}
  <div class="max-w-lg mx-auto py-16 text-center space-y-4">
    <h1 class="text-2xl font-bold">Sign-in failed</h1>
    <p class="text-muted-foreground">{oidcErrorDescription ?? oidcError}</p>
    <p class="text-xs text-muted-foreground">Code: {oidcError}</p>
    <div class="flex gap-2 justify-center pt-2">
      <a href="/api/auth/login?returnTo=/account">
        <Button>Try again</Button>
      </a>
      <Link href="/">
        <Button variant="ghost">Back home</Button>
      </Link>
    </div>
  </div>
{:else}
  <div class="text-center py-16 text-muted-foreground">Signing you in...</div>
{/if}
