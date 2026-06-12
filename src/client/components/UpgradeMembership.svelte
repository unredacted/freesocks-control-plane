<script lang="ts">
  /**
   * Self-service membership purchase panel. Renders ONLY when billing is enabled
   * and at least one rail is live (it reads PublicConfig.billing). The member
   * picks a payment method + duration; "Continue to payment" creates a
   * processor-hosted invoice server-side and full-page redirects to it (the
   * strict CSP forbids an embedded payment SDK — redirect is the only option).
   * No payer identity is sent to the processor; the order is bound to the member
   * server-side via an opaque ref.
   *
   * Method is chosen FIRST because it gates the durations: the crypto rail
   * (NOWPayments) has a per-coin minimum payment (XMR's is high) and the payer
   * picks the coin on the hosted page, so terms below `cryptoMinMonths` would be
   * rejected there — we disable them here and the checkout action enforces it too.
   */
  import { Button } from '@client/components/ui/button';
  import { configQuery } from '../lib/queries';
  import { apiClient } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';
  import { CheckoutResponse, type BillingProcessor } from '../../shared/contracts/billing';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  interface Props {
    /** 'upgrade' for free users, 'extend' for expiring/expired members (heading copy). */
    mode?: 'upgrade' | 'extend';
  }
  let { mode = 'upgrade' }: Props = $props();

  const config = configQuery();
  let billing = $derived(config.data?.billing);
  let durations = $derived(billing?.durations ?? []);
  let currency = $derived(billing?.currency ?? 'USD');
  let cryptoMin = $derived(billing?.cryptoMinMonths ?? 3);

  // Render rails in a stable, sensible order, filtered to the ones turned on.
  const RAIL_ORDER: BillingProcessor[] = ['nowpayments', 'stripe', 'paypal'];
  let rails = $derived(RAIL_ORDER.filter((r) => billing?.rails?.[r]));

  // Selection: raw state overrides a derived default, so nothing needs an effect
  // and it stays reactive to config loading.
  let selectedMonthsRaw = $state<number | null>(null);
  let selectedProcessorRaw = $state<BillingProcessor | null>(null);
  let selectedProcessor = $derived(selectedProcessorRaw ?? rails[0] ?? null);

  // Crypto (NOWPayments) only offers terms >= cryptoMin; card/PayPal offer all.
  let minMonths = $derived(selectedProcessor === 'nowpayments' ? cryptoMin : 1);

  // Honor an explicit duration pick while it's valid for the chosen method,
  // otherwise fall to the cheapest allowed term — so switching to crypto with a
  // 1-month pick auto-moves to the first eligible term (never a dead-end selection).
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

  // Show the explainer only when crypto actually hides a term that's otherwise offered.
  let cryptoLimited = $derived(
    selectedProcessor === 'nowpayments' && durations.some((d) => d.months < cryptoMin),
  );

  function railLabel(r: BillingProcessor): string {
    return r === 'nowpayments'
      ? t('upgrade.payNowpayments')
      : r === 'stripe'
        ? t('upgrade.payStripe')
        : t('upgrade.payPaypal');
  }
  function railHint(r: BillingProcessor): string {
    return r === 'nowpayments'
      ? t('upgrade.payNowpaymentsHint')
      : r === 'stripe'
        ? t('upgrade.payStripeHint')
        : t('upgrade.payPaypalHint');
  }

  const checkout = createMutation(() => ({
    mutationFn: (vars: { processor: BillingProcessor; months: number }) =>
      apiClient.post('/api/v1/billing/checkout', vars, CheckoutResponse),
    onSuccess: (res) => {
      // Full-page redirect to the processor-hosted page (matches logout idiom).
      window.location.href = res.redirectUrl;
    },
    onError: (err) => {
      toast.error(t('upgrade.startFailed'), { description: apiErrorMessage(err) });
    },
  }));

  function submit() {
    if (selectedProcessor && selectedMonths) {
      checkout.mutate({ processor: selectedProcessor, months: selectedMonths });
    }
  }
</script>

{#if billing?.enabled && rails.length > 0 && durations.length > 0}
  <section id="upgrade" class="space-y-4 rounded-xl border border-primary/30 bg-card p-4 sm:p-5">
    <div>
      <h2 class="font-display text-base font-semibold">
        {mode === 'extend' ? t('upgrade.extendTitle') : t('upgrade.title')}
      </h2>
      <p class="text-sm text-muted-foreground">{t('upgrade.subtitle')}</p>
    </div>

    <!-- Method first: it gates which durations are available (crypto minimum). -->
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
            class="rounded-lg border p-3 text-start transition {selectedProcessor === r
              ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
              : 'border-border hover:border-primary/40'}"
          >
            <div class="text-sm font-semibold">{railLabel(r)}</div>
            <div class="text-xs text-muted-foreground">{railHint(r)}</div>
          </button>
        {/each}
      </div>
    </fieldset>

    <fieldset>
      <legend class="mb-2 text-xs font-medium text-muted-foreground">
        {t('upgrade.durationLabel')}
      </legend>
      <div class="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {#each durations as d (d.months)}
          {@const locked = d.months < minMonths}
          <button
            type="button"
            disabled={locked}
            onclick={() => (selectedMonthsRaw = d.months)}
            aria-pressed={selectedMonths === d.months}
            class="rounded-lg border p-3 text-start transition disabled:cursor-not-allowed disabled:opacity-40 {selectedMonths ===
            d.months
              ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
              : 'border-border hover:border-primary/40'}"
          >
            <div class="text-sm font-semibold">{t('upgrade.months', { count: d.months })}</div>
            <div class="text-xs tabular-nums text-muted-foreground">
              {formatMoney(d.amountCents, currency)}
            </div>
          </button>
        {/each}
      </div>
      {#if cryptoLimited}
        <p class="mt-2 text-xs text-muted-foreground">
          {t('upgrade.cryptoMinNote', { months: cryptoMin })}
        </p>
      {/if}
    </fieldset>

    <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div>
        {#if selectedDuration}
          <span class="text-sm font-semibold tabular-nums">
            {t('upgrade.total', { price: formatMoney(selectedDuration.amountCents, currency) })}
          </span>
        {/if}
        <p class="text-xs text-muted-foreground">{t('upgrade.noStoreNote')}</p>
      </div>
      <Button
        onclick={submit}
        disabled={!selectedProcessor || !selectedMonths || checkout.isPending}
        class="w-full sm:w-auto"
      >
        {checkout.isPending ? t('upgrade.starting') : t('upgrade.continue')}
      </Button>
    </div>
  </section>
{/if}
