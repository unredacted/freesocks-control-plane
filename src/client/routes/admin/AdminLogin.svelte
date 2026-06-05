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

  let username = $state('');
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function submit() {
    busy = true;
    error = null;
    try {
      const optsRes = await fetch('/api/admin/auth/authenticate/options', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      if (!optsRes.ok) {
        // Surface the server's actual error message so the user can tell the
        // difference between "username not found" and "service unavailable".
        const body = (await optsRes.json().catch(() => ({}))) as { error?: { message?: string } };
        const msg = body.error?.message;
        // Specific UX: a 403 here usually means the username doesn't exist
        // ("No such admin"). Make that human-friendly.
        if (optsRes.status === 403) {
          throw new Error(msg ?? 'No admin found with that username.');
        }
        throw new Error(msg ?? `Failed to start authentication (${optsRes.status})`);
      }
      const optsBody = (await optsRes.json()) as {
        options: Parameters<typeof startAuthentication>[0]['optionsJSON'];
        challengeId: string;
      };
      let assertion: Awaited<ReturnType<typeof startAuthentication>>;
      try {
        assertion = await startAuthentication({ optionsJSON: optsBody.options });
      } catch (err) {
        // Distinguish user-cancelled (NotAllowedError) from device errors so
        // the message is actionable rather than scary.
        const name = err instanceof Error ? err.name : '';
        if (name === 'NotAllowedError' || name === 'AbortError') {
          throw new Error('Passkey prompt was cancelled. Try again.');
        }
        throw new Error(
          `Passkey ceremony failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      const verifyRes = await fetch('/api/admin/auth/authenticate/verify', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: optsBody.challengeId, response: assertion }),
      });
      if (!verifyRes.ok) {
        const body = (await verifyRes.json().catch(() => ({}))) as { error?: { message?: string } };
        throw new Error(body.error?.message ?? 'Authentication failed');
      }
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
      <CardDescription>Use your registered passkey.</CardDescription>
    </CardHeader>
    <CardContent class="space-y-4">
      <div>
        <label class="text-sm mb-1 block" for="admin-username">Username</label>
        <Input id="admin-username" bind:value={username} />
      </div>
      {#if error}
        <p class="text-sm text-destructive">{error}</p>
      {/if}
      <Button onclick={submit} disabled={busy || !username} class="w-full">
        {busy ? 'Authenticating...' : 'Sign in with passkey'}
      </Button>
    </CardContent>
  </Card>
</div>
