<script lang="ts">
  import { startAuthentication } from '@simplewebauthn/browser';
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { router } from '../../stores/router.svelte';
  import { ensureSessionKey, setSessionToken } from '../../lib/pop';
  import { POP_ALG_FIELD, POP_PUBKEY_FIELD } from '../../../shared/crypto/pop';

  let busy = $state(false);
  let error = $state<string | null>(null);
  // Usernameless (discoverable-credential) sign-in is the default. The username
  // field is a fallback only: some authenticators register a passkey WITHOUT
  // making it discoverable, so the browser won't surface it without an
  // allowCredentials hint - a username lets the server supply that hint.
  let useUsername = $state(false);
  let username = $state('');

  async function signIn(withUsername: boolean) {
    busy = true;
    error = null;
    try {
      // Omit the username for the discoverable flow; send it only for the
      // fallback. The server returns no allowCredentials when usernameless, so
      // the authenticator offers every resident passkey for this site.
      const optsRes = await fetch('/api/admin/auth/authenticate/options', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(withUsername && username.trim() ? { username: username.trim() } : {}),
      });
      if (!optsRes.ok) {
        const body = (await optsRes.json().catch(() => ({}))) as { error?: { message?: string } };
        throw new Error(body.error?.message ?? `Failed to start sign-in (${optsRes.status})`);
      }
      const optsBody = (await optsRes.json()) as {
        options: Parameters<typeof startAuthentication>[0]['optionsJSON'];
        challengeId: string;
      };

      let assertion: Awaited<ReturnType<typeof startAuthentication>>;
      try {
        assertion = await startAuthentication({ optionsJSON: optsBody.options });
      } catch (err) {
        const name = err instanceof Error ? err.name : '';
        if (name === 'NotAllowedError' || name === 'AbortError') {
          // Cancelled, timed out, or no usable passkey was offered. From the
          // usernameless path, surface the username fallback as the next step
          // (covers an older passkey that isn't discoverable).
          if (!withUsername) {
            useUsername = true;
            throw new Error(
              "No passkey selected. If yours isn't offered automatically, enter your username and try again.",
            );
          }
          throw new Error('Passkey prompt was cancelled. Try again.');
        }
        throw new Error(
          `Passkey ceremony failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }

      // PoP (Phase 2): mint/ensure the admin signing key and bind it to this
      // session by posting its public point + algorithm with the assertion. Admin
      // then inherits PoP via the shared apiClient seam on every later request.
      const popKey = await ensureSessionKey('admin');
      const verifyRes = await fetch('/api/admin/auth/authenticate/verify', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          challengeId: optsBody.challengeId,
          response: assertion,
          ...(popKey ? { [POP_PUBKEY_FIELD]: popKey.pub, [POP_ALG_FIELD]: popKey.alg } : {}),
        }),
      });
      if (!verifyRes.ok) {
        const body = (await verifyRes.json().catch(() => ({}))) as { error?: { message?: string } };
        throw new Error(body.error?.message ?? 'Sign-in failed');
      }
      // PoP sid-binding: persist the public per-session token from the response
      // so every later admin request signs it (admin login bypasses apiClient).
      const okBody = (await verifyRes.json().catch(() => ({}))) as { popSessionToken?: string };
      setSessionToken('admin', okBody.popSessionToken);
      router.navigate('/admin/tiers');
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="max-w-md mx-auto py-12">
  <Card>
    <CardHeader>
      <CardTitle>Admin sign-in</CardTitle>
      <CardDescription>Sign in with your passkey - no username needed.</CardDescription>
    </CardHeader>
    <CardContent class="space-y-4">
      {#if error}
        <p class="text-sm text-destructive">{error}</p>
      {/if}

      {#if useUsername}
        <div>
          <label class="text-sm mb-1 block" for="admin-username">Username</label>
          <Input
            id="admin-username"
            bind:value={username}
            autocomplete="username webauthn"
            onkeydown={(e: KeyboardEvent) => {
              if (e.key === 'Enter' && username.trim() && !busy) void signIn(true);
            }}
          />
        </div>
        <Button onclick={() => signIn(true)} disabled={busy || !username.trim()} class="w-full">
          {busy ? 'Authenticating…' : 'Sign in'}
        </Button>
        <button
          type="button"
          class="text-xs text-muted-foreground underline hover:text-foreground"
          onclick={() => {
            useUsername = false;
            error = null;
          }}
        >
          Back to passkey sign-in
        </button>
      {:else}
        <Button onclick={() => signIn(false)} disabled={busy} class="w-full">
          {busy ? 'Authenticating…' : 'Sign in with a passkey'}
        </Button>
        <button
          type="button"
          class="text-xs text-muted-foreground underline hover:text-foreground"
          onclick={() => {
            useUsername = true;
            error = null;
          }}
        >
          Use a username instead
        </button>
      {/if}
    </CardContent>
  </Card>
</div>
