<script lang="ts">
  import { onMount } from 'svelte';
  import { z } from 'zod';
  import { apiClient } from '../../lib/api';
  import { readAdminInvite } from '../../lib/adminInvite';
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
   * an existing admin shares (/admin/register#invite=<token>). The invite token
   * is the authorization - the visitor has no session yet. On success the new
   * admin registers a discoverable passkey and can then sign in usernameless.
   */
  let inviteToken = $state('');
  onMount(() => {
    const { token, cleanPath } = readAdminInvite(window.location.href);
    router.navigate(cleanPath, { replace: true, scroll: false });
    inviteToken = token;
    // A second invite opened in the same tab needs a fresh registration ceremony.
    const newLink = () => {
      if (new URLSearchParams(window.location.hash.slice(1)).has('invite'))
        window.location.reload();
    };
    window.addEventListener('hashchange', newLink);
    return () => window.removeEventListener('hashchange', newLink);
  });
  let deviceLabel = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let done = $state(false);
  let registeredUsername = $state('');

  async function register() {
    if (busy || !inviteToken) return;
    busy = true;
    error = null;
    try {
      const { options } = await apiClient.post(
        '/api/admin/auth/register/options',
        { invite: inviteToken },
        z.object({
          options: z.custom<Parameters<typeof startRegistration>[0]['optionsJSON']>(
            (value) => typeof value === 'object' && value !== null && 'challenge' in value,
          ),
        }),
      );

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

      const out = await apiClient.post(
        '/api/admin/auth/register/verify',
        { invite: inviteToken, response: reg, deviceLabel: deviceLabel.trim() || 'unnamed' },
        z.object({ ok: z.literal(true), username: z.string() }),
      );
      inviteToken = '';
      registeredUsername = out.username;
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
          with it - no username needed.
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
          You've been invited as an admin. Register a passkey on this device to finish - you'll use
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
