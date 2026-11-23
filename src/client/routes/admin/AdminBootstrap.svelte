<script lang="ts">
  import { startRegistration } from '@simplewebauthn/browser';
  import { z } from 'zod';
  import { apiClient } from '../../lib/api';
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
   * harmless to expose publicly: without ADMIN_BOOTSTRAP_SECRET it does
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
      const { options, adminId } = await apiClient.post(
        '/api/admin/auth/register-bootstrap/options',
        { bootstrapSecret: bootstrap, username, displayName: displayName || username },
        z.object({
          adminId: z.string(),
          options: z.custom<Parameters<typeof startRegistration>[0]['optionsJSON']>(
            (value) => typeof value === 'object' && value !== null && 'challenge' in value,
          ),
        }),
      );
      const reg = await startRegistration({ optionsJSON: options });
      await apiClient.post(
        '/api/admin/auth/register-bootstrap/verify',
        {
          bootstrapSecret: bootstrap,
          adminId,
          response: reg,
          deviceLabel: deviceLabel || 'unnamed',
        },
        z.object({ ok: z.literal(true) }),
      );
      bootstrap = '';
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
            placeholder="paste from `bunx convex env set ADMIN_BOOTSTRAP_SECRET`"
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
