<script lang="ts">
  /**
   * Admin -> Billing: the Telegram gift shop. The bot sells gift codes only,
   * to nobody in particular (no account, no chat kept), for Telegram Stars only
   * (Telegram's rule for digital goods in a bot). The bot token is write-only here (blank keeps the
   * saved one); Register webhook makes the webhook secret. The card shows only
   * whether each is set, and how the webhook stands at Telegram.
   */
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Input } from '@client/components/ui/input';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminTelegramQuery, queryKeys } from '../../lib/queries';
  import { formatMoney } from '../../lib/i18n/format';
  import {
    AdminTelegramConfig,
    AdminTelegramWebhook,
    type AdminTelegramPatch,
  } from '../../../shared/contracts/admin';

  interface Props {
    /** The membership durations in the billing catalog (months). */
    durations: number[];
    /** The billing currency, which the Stars rate is set in. */
    currency: string;
  }
  let { durations, currency }: Props = $props();

  const qc = useQueryClient();
  const q = adminTelegramQuery();
  const view = $derived(q.data ?? null);
  const webhook = $derived(view?.webhook ?? null);

  let enabled = $state(false);
  let botUsername = $state('');
  // Write-only: never filled from the server, cleared after a save.
  let botToken = $state('');
  let starsEnabled = $state(false);
  let termsUrl = $state('');
  // What 1,000 Stars are worth, as typed in the billing currency ('13.00').
  let valuePer1000 = $state('');
  // Stars per code, by months, as typed ('' = not sold for Stars).
  let stars = $state<Record<number, string>>({});
  let init = $state(false);
  $effect(() => {
    if (view && !init) {
      enabled = view.enabled;
      botUsername = view.botUsername;
      starsEnabled = view.starsEnabled;
      termsUrl = view.termsUrl;
      valuePer1000 = (view.starsValuePer1000 / 100).toFixed(2);
      stars = Object.fromEntries(view.starsPrices.map((p) => [p.months, String(p.stars)]));
      init = true;
    }
  });

  const save = createMutation(() => ({
    mutationFn: (patch: AdminTelegramPatch) =>
      apiClient.patch('/api/v1/admin/telegram', patch, AdminTelegramConfig),
    onSuccess: () => {
      botToken = '';
      void qc.invalidateQueries({ queryKey: queryKeys.adminTelegram });
      toast.success('Telegram shop settings saved');
    },
    onError: (err) => {
      toast.error('Could not save the Telegram shop settings', {
        description: apiErrorMessage(err),
      });
    },
  }));

  const hook = createMutation(() => ({
    mutationFn: (action: 'register' | 'remove') =>
      apiClient.post('/api/v1/admin/telegram/webhook', { action }, AdminTelegramWebhook),
    onSuccess: (_r, action) => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminTelegram });
      toast.success(action === 'register' ? 'Webhook registered' : 'Webhook removed');
    },
    onError: (err) => {
      toast.error('Telegram refused the change', { description: apiErrorMessage(err) });
    },
  }));

  function submit() {
    const starsPrices = durations
      .map((months) => ({ months, stars: Number(stars[months] ?? '') }))
      .filter((p) => (stars[p.months] ?? '').trim() !== '' && Number.isFinite(p.stars));
    const rate = rateCents(valuePer1000);
    save.mutate({
      enabled,
      botUsername: botUsername.trim(),
      starsEnabled,
      starsPrices,
      termsUrl: termsUrl.trim(),
      ...(Number.isFinite(rate) ? { starsValuePer1000: rate } : {}),
      ...(botToken.trim() ? { botToken: botToken.trim() } : {}),
    });
  }

  // The typed rate in minor units; NaN while blank or not a number.
  const rateCents = (text: string): number => {
    const t = text.trim();
    return t ? Math.round(Number(t) * 100) : NaN;
  };
  // A code's value at the typed rate, shown under its Stars price.
  const valueOf = (starsText: string | undefined): string | null => {
    const n = Number((starsText ?? '').trim());
    const rate = rateCents(valuePer1000);
    if (!(starsText ?? '').trim() || !Number.isFinite(n) || n <= 0 || !Number.isFinite(rate)) {
      return null;
    }
    return formatMoney(Math.round((n * rate) / 1000), currency);
  };

  const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '');
  const mismatch = $derived(
    !!webhook?.tokenUsername &&
      !!view?.botUsername &&
      webhook.tokenUsername.toLowerCase() !== view.botUsername.toLowerCase(),
  );
</script>

<section class="mb-8 space-y-5 rounded-xl border border-border bg-card p-5">
  <div>
    <h2 class="text-base font-semibold">Telegram gift shop</h2>
    <p class="mt-1 text-sm text-muted-foreground">
      A Telegram bot that sells membership gift codes and nothing else. Buyers redeem a code in the
      app like any other. The bot never asks for an account number and keeps no chat: its orders
      have no account, and their codes are linked to nobody. Buyers pay in Telegram Stars only:
      Telegram's rules allow nothing else for digital goods in a bot. Off by default.
    </p>
  </div>

  {#if view}
    <ul class="space-y-1 text-xs">
      <li
        class={view.tokenSet ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'}
      >
        Bot token: {view.tokenSet ? 'saved' : 'not saved'}
      </li>
      <li
        class={view.secretSet ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'}
      >
        Webhook secret: {view.secretSet ? 'set' : 'made when you register the webhook'}
      </li>
      {#if webhook}
        <li
          class={webhook.pointsHere ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600'}
        >
          Webhook: {webhook.reachable
            ? webhook.pointsHere
              ? 'points at this deployment'
              : webhook.set
                ? 'points somewhere else'
                : 'not registered'
            : 'Telegram did not answer'}
          {#if webhook.pendingUpdates > 0}({webhook.pendingUpdates} updates waiting){/if}
        </li>
        {#if webhook.lastErrorAt}
          <li class="text-amber-600">
            Last delivery error {when(webhook.lastErrorAt)}: {webhook.lastErrorMessage ?? 'unknown'}
          </li>
        {/if}
        {#if mismatch}
          <li class="text-amber-600">
            The token belongs to @{webhook.tokenUsername}, not @{view.botUsername}.
          </li>
        {/if}
      {/if}
    </ul>
  {/if}

  <div class="grid gap-4 sm:grid-cols-2">
    <label class="block space-y-1">
      <span class="text-xs text-muted-foreground">Bot username (from BotFather)</span>
      <Input placeholder="FreeSocksShopBot" bind:value={botUsername} autocomplete="off" />
    </label>
    <label class="block space-y-1">
      <span class="text-xs text-muted-foreground">
        Bot token (from BotFather){view?.tokenSet ? ', leave blank to keep the saved one' : ''}
      </span>
      <Input
        type="password"
        placeholder={view?.tokenSet ? 'Saved' : '123456789:AA...'}
        bind:value={botToken}
        autocomplete="off"
      />
    </label>
  </div>

  <div class="space-y-2 text-sm">
    <label class="flex items-center gap-3">
      <Checkbox checked={enabled} onCheckedChange={(v) => (enabled = v === true)} />
      <span>Shop open</span>
    </label>
    <label class="flex items-center gap-3">
      <Checkbox checked={starsEnabled} onCheckedChange={(v) => (starsEnabled = v === true)} />
      <span>Sell for Telegram Stars</span>
    </label>
  </div>

  <label class="block space-y-1">
    <span class="text-xs text-muted-foreground">
      Full terms of sale (optional https link). The bot always shows its own short terms, and buyers
      accept them before paying; this adds a link to yours.
    </span>
    <Input placeholder="https://" bind:value={termsUrl} autocomplete="off" />
  </label>

  <div>
    <p class="mb-2 text-xs text-muted-foreground">
      Stars per code. Leave a duration blank to not sell it for Stars.
    </p>
    <div class="grid gap-3 sm:grid-cols-4">
      {#each durations as months (months)}
        <label class="block space-y-1">
          <span class="text-xs text-muted-foreground">{months} mo</span>
          <Input
            inputmode="numeric"
            placeholder="Stars"
            value={stars[months] ?? ''}
            oninput={(e) =>
              (stars = { ...stars, [months]: (e.currentTarget as HTMLInputElement).value })}
          />
          {#if valueOf(stars[months])}
            <span class="block text-[11px] text-muted-foreground tabular-nums">
              ≈ {valueOf(stars[months])} to you
            </span>
          {/if}
        </label>
      {/each}
    </div>
  </div>

  <label class="block max-w-xs space-y-1">
    <span class="text-xs text-muted-foreground">
      What 1,000 Stars are worth to you, in {currency}. Each Stars order records its {currency} value
      at this rate when it is paid, for the revenue chart and the orders list. Telegram's payout rate
      is 13.00 USD per 1,000 Stars.
    </span>
    <Input inputmode="decimal" placeholder="13.00" bind:value={valuePer1000} autocomplete="off" />
  </label>

  <div class="flex flex-wrap justify-end gap-2">
    <Button
      variant="outline"
      onclick={() => hook.mutate('remove')}
      disabled={hook.isPending || !view?.tokenSet}
    >
      Remove webhook
    </Button>
    <Button
      variant="outline"
      onclick={() => hook.mutate('register')}
      disabled={hook.isPending || !view?.tokenSet || !view?.webhookUrl}
    >
      {hook.isPending ? 'Working…' : 'Register webhook'}
    </Button>
    <Button onclick={submit} disabled={save.isPending || !init}>
      {save.isPending ? 'Saving…' : 'Save Telegram shop'}
    </Button>
  </div>
</section>
