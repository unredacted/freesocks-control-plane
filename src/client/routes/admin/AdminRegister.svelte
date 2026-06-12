<script lang="ts">
  import { startRegistration } from '@simplewebauthn/browser';
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

  /**
   * Invite landing page (multi-admin onboarding). Opened from the one-time link
   * an existing admin shares (/admin/register?invite=<token>). The invite token
   * is the authorization — the visitor has no session yet. On success the new
   * admin registers a discoverable passkey and can then sign in usernameless.
   */
  let inviteToken = $derived(router.searchParams.get('invite') ?? '');
  let deviceLabel = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let done = $state(false);
  let registeredUsername = $state('');

  async function register() {
    busy = true;
    error = null;
    try {
      const optsRes = await fetch('/api/admin/auth/register/options', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ invite: inviteToken }),
      });
      if (!optsRes.ok) {
        const body = (await optsRes.json().catch(() => ({}))) as { error?: { message?: string } };
        throw new Error(body.error?.message ?? `Could not start registration (${optsRes.status})`);
      }
      const { options } = (await optsRes.json()) as {
        options: Parameters<typeof startRegistration>[0]['optionsJSON'];
      };

      let reg: Awaited<ReturnType<typeof startRegistration>>;
      try {
        reg = await startRegistration({ optionsJSON: options });
      } catch (err) {
        const name = err instanceof Error ? err.name : '';
        if (name === 'NotAllowedError' || name === 'AbortError') {
          throw new Error('Passkey prompt was cancelled. Try again.');
        }
        throw new Error(
          `Passkey setup failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }

      const verifyRes = await fetch('/api/admin/auth/register/verify', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          invite: inviteToken,
          response: reg,
          deviceLabel: deviceLabel.trim() || 'unnamed',
        }),
      });
      if (!verifyRes.ok) {
        const body = (await verifyRes.json().catch(() => ({}))) as { error?: { message?: string } };
        throw new Error(body.error?.message ?? `Registration failed (${verifyRes.status})`);
      }
      const out = (await verifyRes.json()) as { username?: string };
      registeredUsername = out.username ?? '';
      done = true;
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="max-w-md mx-auto py-12">
  <Card>
    {#if done}
      <CardHeader>
        <CardTitle>You're set up</CardTitle>
        <CardDescription>
          Your passkey is registered{registeredUsername ? ` as ${registeredUsername}` : ''}. Sign in
          with it — no username needed.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Button onclick={() => router.navigate('/admin')} class="w-full">Go to sign-in</Button>
      </CardContent>
    {:else if !inviteToken}
      <CardHeader>
        <CardTitle>Invalid invite link</CardTitle>
        <CardDescription>
          This link is missing its invite token. Ask the admin who invited you to send a fresh link.
        </CardDescription>
      </CardHeader>
    {:else}
      <CardHeader>
        <CardTitle>Register your admin passkey</CardTitle>
        <CardDescription>
          You've been invited as an admin. Register a passkey on this device to finish — you'll use
          it (Face ID, Touch ID, a security key, or your password manager) to sign in.
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-4">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="reg-device">
            Device label (optional)
          </label>
          <Input
            id="reg-device"
            bind:value={deviceLabel}
            placeholder="e.g. Work laptop"
            autocomplete="off"
          />
        </div>
        {#if error}
          <p class="text-sm text-destructive">{error}</p>
        {/if}
        <Button onclick={register} disabled={busy} class="w-full">
          {busy ? 'Working…' : 'Register passkey'}
        </Button>
      </CardContent>
    {/if}
  </Card>
</div>
