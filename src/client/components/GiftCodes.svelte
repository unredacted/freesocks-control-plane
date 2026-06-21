<script lang="ts">
  /**
   * Buy membership codes to SHARE (gift), distinct from the self-`UpgradeMembership`
   * flow: the purchase mints `quantity` shareable codes bound to the buyer instead
   * of extending the buyer's own membership. Method + duration pickers mirror
   * UpgradeMembership; a quantity stepper scales the price. "Buy codes" creates a
   * processor-hosted invoice and full-page redirects (the strict CSP forbids an
   * embedded SDK). The freshly-minted codes are revealed ONCE on return (handled
   * by Account's order poll); this panel also lists the codes you've bought + their
   * redeemed status.
   */
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { configQuery, accountCodesQuery } from '../lib/queries';
  import { apiClient } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney, formatDate } from '../lib/i18n/format';
  import { perMonthCents, savingsPct } from '../lib/billing';
  import { CheckoutResponse, type BillingProcessor } from '../../shared/contracts/billing';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Gift from '@lucide/svelte/icons/gift';

  const config = configQuery();
  let billing = $derived(config.data?.billing);
  let durations = $derived(billing?.durations ?? []);
  let currency = $derived(billing?.currency ?? 'USD');
  let cryptoMin = $derived(billing?.cryptoMinMonths ?? 3);

  const RAIL_ORDER: BillingProcessor[] = ['nowpayments', 'stripe', 'paypal'];
  let rails = $derived(RAIL_ORDER.filter((r) => billing?.rails?.[r]));

  let selectedProcessorRaw = $state<BillingProcessor | null>(null);
  let selectedProcessor = $derived(selectedProcessorRaw ?? rails[0] ?? null);
  let minMonths = $derived(selectedProcessor === 'nowpayments' ? cryptoMin : 1);

  let selectedMonthsRaw = $state<number | null>(null);
  let selectedMonths = $derived.by(() => {
    if (
      selectedMonthsRaw != null &&
      selectedMonthsRaw >= minMonths &&
      durations.some((d) => d.months === selectedMonthsRaw)
    ) {
      return selectedMonthsRaw;
    }
    return durations.find((d) => d.months >= minMonths)?.months ?? null;
  });
  let selectedDuration = $derived(durations.find((d) => d.months === selectedMonths) ?? null);

  const MAX_QTY = 50;
  let quantity = $state(1);
  function setQty(n: number) {
    quantity = Math.max(1, Math.min(MAX_QTY, Math.floor(n || 1)));
  }
  let totalCents = $derived((selectedDuration?.amountCents ?? 0) * quantity);

  // The buyer's purchased codes (gated on billing being live, like the panel).
  let codes = accountCodesQuery(() => !!billing?.enabled);

  const checkout = createMutation(() => ({
    mutationFn: (vars: { processor: BillingProcessor; months: number; quantity: number }) =>
      apiClient.post(
        '/api/v1/billing/checkout',
        { processor: vars.processor, months: vars.months, kind: 'gift', quantity: vars.quantity },
        CheckoutResponse,
      ),
    onSuccess: (res) => {
      window.location.href = res.redirectUrl;
    },
    onError: (err) => {
      toast.error(t('gift.startFailed'), { description: apiErrorMessage(err) });
    },
  }));

  function submit() {
    if (selectedProcessor && selectedMonths) {
      checkout.mutate({ processor: selectedProcessor, months: selectedMonths, quantity });
    }
  }

  const RING =
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background';
  function statusLabel(s: 'active' | 'redeemed' | 'revoked'): string {
    return s === 'redeemed'
      ? t('gift.statusRedeemed')
      : s === 'revoked'
        ? t('gift.statusRevoked')
        : t('gift.statusAvailable');
  }
</script>

{#if billing?.enabled && rails.length > 0 && durations.length > 0}
  <section class="space-y-4 rounded-xl border border-border bg-card p-4 sm:p-5">
    <div class="flex items-start gap-2.5">
      <Gift class="mt-0.5 size-5 shrink-0 text-primary" aria-hidden="true" />
      <div>
        <h2 class="font-display text-base font-semibold">{t('gift.title')}</h2>
        <p class="text-sm text-muted-foreground">{t('gift.subtitle')}</p>
      </div>
    </div>

    <!-- Method first (gates the durations: crypto minimum). -->
    <fieldset>
      <legend class="mb-2 text-xs font-medium text-muted-foreground">
        {t('upgrade.methodLabel')}
      </legend>
      <div class="grid gap-2 sm:grid-cols-3">
        {#each rails as r (r)}
          <button
            type="button"
            onclick={() => (selectedProcessorRaw = r)}
            aria-pressed={selectedProcessor === r}
            class="rounded-lg border p-3 text-start transition {RING} {selectedProcessor === r
              ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
              : 'border-border hover:border-primary/40'}"
          >
            <div class="flex items-center gap-1.5 text-sm font-semibold">
              {r === 'nowpayments'
                ? t('upgrade.payNowpayments')
                : r === 'stripe'
                  ? t('upgrade.payStripe')
                  : t('upgrade.payPaypal')}
              {#if r === 'nowpayments'}
                <span
                  class="rounded-full bg-primary/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary"
                >
                  {t('upgrade.payNowpaymentsBadge')}
                </span>
              {/if}
            </div>
          </button>
        {/each}
      </div>
      {#if selectedProcessor === 'nowpayments'}
        <p class="mt-2 text-xs text-primary/90">{t('upgrade.cryptoPrivacyNote')}</p>
      {/if}
    </fieldset>

    <fieldset>
      <legend class="mb-2 text-xs font-medium text-muted-foreground">
        {t('upgrade.durationLabel')}
      </legend>
      <div class="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {#each durations as d (d.months)}
          {@const locked = d.months < minMonths}
          {@const pct = savingsPct(d, durations)}
          <button
            type="button"
            disabled={locked}
            onclick={() => (selectedMonthsRaw = d.months)}
            aria-pressed={selectedMonths === d.months}
            class="rounded-lg border p-3 text-start transition {RING} disabled:cursor-not-allowed disabled:opacity-40 {selectedMonths ===
            d.months
              ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
              : 'border-border hover:border-primary/40'}"
          >
            <div class="text-sm font-semibold">{t('upgrade.months', { count: d.months })}</div>
            <div class="text-xs tabular-nums text-muted-foreground">
              {formatMoney(d.amountCents, currency)}
            </div>
            {#if d.months > 1}
              <div class="text-[0.7rem] tabular-nums text-muted-foreground">
                {t('upgrade.perMonth', {
                  price: formatMoney(Math.round(perMonthCents(d)), currency),
                })}
                {#if pct > 0}
                  <span class="font-medium text-primary">· {t('upgrade.save', { pct })}</span>
                {/if}
              </div>
            {/if}
          </button>
        {/each}
      </div>
    </fieldset>

    <div class="flex items-end gap-3">
      <div class="space-y-1">
        <label class="block text-xs font-medium text-muted-foreground" for="gift-qty">
          {t('gift.quantityLabel')}
        </label>
        <Input
          id="gift-qty"
          type="number"
          min={1}
          max={MAX_QTY}
          class="w-24"
          value={quantity}
          oninput={(e) => setQty((e.currentTarget as HTMLInputElement).valueAsNumber)}
        />
      </div>
    </div>

    <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div>
        {#if selectedDuration}
          <span class="text-sm font-semibold tabular-nums">
            {t('upgrade.total', { price: formatMoney(totalCents, currency) })}
          </span>
        {/if}
        <p class="text-xs text-muted-foreground">{t('upgrade.noStoreNote')}</p>
      </div>
      <Button
        onclick={submit}
        disabled={!selectedProcessor || !selectedMonths || checkout.isPending}
        class="w-full min-h-11 sm:w-auto"
      >
        {checkout.isPending ? t('gift.starting') : t('gift.buy')}
      </Button>
    </div>

    <!-- Codes you've bought -->
    <div class="border-t border-border/60 pt-4">
      <h3 class="text-sm font-semibold">{t('gift.boughtTitle')}</h3>
      {#if codes.isPending}
        <p class="mt-2 text-xs text-muted-foreground">{t('common.loading')}</p>
      {:else if (codes.data ?? []).length === 0}
        <p class="mt-2 text-xs text-muted-foreground">{t('gift.boughtEmpty')}</p>
      {:else}
        <ul class="mt-2 divide-y divide-border rounded-lg border border-border">
          {#each codes.data ?? [] as c (c.codePrefix + c.createdAt)}
            <li class="flex items-center justify-between gap-3 px-3 py-2">
              <code class="font-mono text-xs text-muted-foreground">{c.codePrefix}…</code>
              <span class="flex items-center gap-2 text-xs tabular-nums text-muted-foreground">
                {#if c.redeemedAt}{t('gift.redeemedOn', { date: formatDate(c.redeemedAt) })}{/if}
                <span
                  class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide {c.status ===
                  'redeemed'
                    ? 'bg-primary/10 text-primary'
                    : c.status === 'revoked'
                      ? 'bg-destructive/10 text-destructive'
                      : 'bg-secondary text-secondary-foreground'}"
                >
                  {statusLabel(c.status)}
                </span>
              </span>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  </section>
{/if}
