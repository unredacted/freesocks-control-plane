<script lang="ts">
  import { z } from 'zod';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import KeyRound from '@lucide/svelte/icons/key-round';
  import Trash2 from '@lucide/svelte/icons/trash-2';
  import ShieldAlert from '@lucide/svelte/icons/shield-alert';
  import { apiClient } from '../lib/api';
  import { queryClient } from '../lib/query-client';
  import { passkeysQuery, queryKeys } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import { enrollPasskey, passkeysSupported, PasskeyCancelledError } from '../lib/memberPasskey';

  /**
   * Member passkey manager. In the account Security tab it lists + adds + removes
   * passkeys; on the sign-up step it's rendered with `showList={false}` as a
   * one-shot "add a passkey" prompt. Either way it leads with the sync/anonymity
   * warning - a passkey is opt-in and the account number stays the recovery secret.
   */
  let { showList = true, onEnrolled }: { showList?: boolean; onEnrolled?: () => void } = $props();

  const supported = passkeysSupported();
  let deviceLabel = $state('');

  // The list is only relevant in the manager (Security tab), and only when supported.
  const passkeys = passkeysQuery(() => showList && supported);

  const add = createMutation(() => ({
    mutationFn: () => enrollPasskey(deviceLabel),
    onSuccess: async () => {
      deviceLabel = '';
      await queryClient.invalidateQueries({ queryKey: queryKeys.passkeys });
      toast.success(t('passkey.added'));
      onEnrolled?.();
    },
    onError: (err) => {
      // A dismissed browser prompt isn't an error worth a toast.
      if (err instanceof PasskeyCancelledError) return;
      toast.error(t('passkey.addFailed'), {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  }));

  const RevokeResp = z.object({ ok: z.boolean(), revoked: z.boolean() });
  const revoke = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.post('/api/v1/account/passkey/revoke', { id }, RevokeResp),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.passkeys });
      toast.success(t('passkey.removed'));
    },
    onError: (err) =>
      toast.error(t('passkey.removeFailed'), {
        description: err instanceof Error ? err.message : String(err),
      }),
  }));

  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString() : '');
</script>

<div class="rounded-xl border border-border bg-card p-4 sm:p-5 space-y-4">
  <div class="flex items-start gap-3">
    <KeyRound class="size-5 text-primary mt-0.5 shrink-0" aria-hidden="true" />
    <div class="space-y-1">
      <p class="text-sm font-medium">{t('passkey.title')}</p>
      <p class="text-xs text-muted-foreground leading-snug">{t('passkey.desc')}</p>
    </div>
  </div>

  {#if !supported}
    <p class="text-xs text-muted-foreground">{t('passkey.unsupported')}</p>
  {:else}
    <!-- Privacy/anonymity warning: a synced passkey can link this anonymous
         account to an Apple/Google identity. Shown before any enroll action. -->
    <div
      class="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-muted-foreground"
      role="note"
    >
      <ShieldAlert class="size-4 shrink-0 text-amber-600 dark:text-amber-500" aria-hidden="true" />
      <span class="leading-snug">{t('passkey.warning')}</span>
    </div>

    {#if showList}
      {#if passkeys.data && passkeys.data.passkeys.length > 0}
        <ul class="divide-y divide-border/60 rounded-md border border-border">
          {#each passkeys.data.passkeys as pk (pk.id)}
            <li class="flex items-center justify-between gap-3 px-3 py-2">
              <div class="min-w-0">
                <p class="truncate text-sm font-medium">{pk.deviceLabel || t('passkey.title')}</p>
                <p class="text-xs text-muted-foreground">
                  {t('passkey.addedOn', { date: fmt(pk.createdAt) })}{pk.lastUsedAt
                    ? ` · ${t('passkey.lastUsed', { date: fmt(pk.lastUsedAt) })}`
                    : ''}
                </p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                class="shrink-0 text-destructive hover:text-destructive"
                disabled={revoke.isPending}
                onclick={() => revoke.mutate(pk.id)}
                aria-label={t('passkey.remove')}
              >
                <Trash2 class="size-4" />
                <span class="hidden sm:inline">{t('passkey.remove')}</span>
              </Button>
            </li>
          {/each}
        </ul>
      {:else if passkeys.isSuccess}
        <p class="text-xs text-muted-foreground">{t('passkey.none')}</p>
      {/if}
    {/if}

    <div class="flex flex-col gap-2 sm:flex-row sm:items-end">
      <div class="flex-1">
        <label for="passkey-device" class="mb-1 block text-xs text-muted-foreground">
          {t('passkey.deviceLabelLabel')}
        </label>
        <Input
          id="passkey-device"
          bind:value={deviceLabel}
          placeholder={t('passkey.deviceLabelPlaceholder')}
          autocomplete="off"
          maxlength={64}
        />
      </div>
      <Button class="min-h-11 shrink-0" disabled={add.isPending} onclick={() => add.mutate()}>
        <KeyRound class="size-4" />
        {add.isPending ? t('passkey.adding') : t('passkey.add')}
      </Button>
    </div>
  {/if}
</div>
