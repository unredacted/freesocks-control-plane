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

  interface Props {
    /** Called after bootstrap completes so the parent can re-fetch status. */
    onComplete: () => void;
  }
  let { onComplete }: Props = $props();

  /**
   * One-time bootstrap form for the very first admin. Server-side this is
   * only accepted while no admin has a registered passkey, so the form is
   * harmless to expose publicly — without ADMIN_BOOTSTRAP_SECRET it does
   * nothing.
   */
  let bootstrap = $state('');
  let username = $state('');
  let displayName = $state('');
  let deviceLabel = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let done = $state(false);

  async function submit() {
    busy = true;
    error = null;
    try {
      const headers = {
        'content-type': 'application/json',
        'x-admin-bootstrap-token': bootstrap,
      };
      const optsRes = await fetch('/api/admin/auth/register-bootstrap/options', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({ username, displayName: displayName || username }),
      });
      if (!optsRes.ok) {
        const body = (await optsRes.json().catch(() => ({}))) as { error?: { message?: string } };
        throw new Error(body.error?.message ?? `Options failed (${optsRes.status})`);
      }
      const { options, adminId } = (await optsRes.json()) as {
        options: Parameters<typeof startRegistration>[0]['optionsJSON'];
        adminId: number;
      };

      const reg = await startRegistration({ optionsJSON: options });

      const verifyRes = await fetch('/api/admin/auth/register-bootstrap/verify', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({ adminId, response: reg, deviceLabel: deviceLabel || 'unnamed' }),
      });
      if (!verifyRes.ok) {
        const body = (await verifyRes.json().catch(() => ({}))) as { error?: { message?: string } };
        throw new Error(body.error?.message ?? `Verification failed (${verifyRes.status})`);
      }
      done = true;
      onComplete();
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

{#if done}
  <div class="max-w-md mx-auto py-12">
    <Card>
      <CardHeader>
        <CardTitle>You're set up</CardTitle>
        <CardDescription>
          Admin <strong>{username}</strong> is registered. Rotate
          <code>ADMIN_BOOTSTRAP_SECRET</code> now (the value is no longer useful).
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Button onclick={() => router.navigate('/admin')} class="w-full">
          Continue to sign-in
        </Button>
      </CardContent>
    </Card>
  </div>
{:else}
  <div class="max-w-md mx-auto py-12">
    <Card>
      <CardHeader>
        <CardTitle>Set up the first admin</CardTitle>
        <CardDescription>
          One-time setup. Once you complete this, the bootstrap path is closed and any further
          admins must be added through the CMS.
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-4">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="boot-secret">
            ADMIN_BOOTSTRAP_SECRET
          </label>
          <Input
            id="boot-secret"
            type="password"
            bind:value={bootstrap}
            placeholder="paste from `npx convex env set ADMIN_BOOTSTRAP_SECRET`"
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="boot-username">
            Username
          </label>
          <Input id="boot-username" bind:value={username} placeholder="admin" autocomplete="off" />
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="boot-display">
            Display name
          </label>
          <Input
            id="boot-display"
            bind:value={displayName}
            placeholder="defaults to username"
            autocomplete="off"
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="boot-device">
            Device label (this passkey)
          </label>
          <Input
            id="boot-device"
            bind:value={deviceLabel}
            placeholder="Browser passkey"
            autocomplete="off"
          />
        </div>
        {#if error}
          <p class="text-sm text-destructive">{error}</p>
        {/if}
        <Button onclick={submit} disabled={busy || !bootstrap || !username} class="w-full">
          {busy ? 'Working...' : 'Register passkey'}
        </Button>
      </CardContent>
    </Card>
  </div>
{/if}
