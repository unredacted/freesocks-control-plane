<script lang="ts">
  /**
   * Standalone donation card: give any amount WITHOUT buying a membership (works
   * for members and free users alike). Mirrors the UpgradeMembership method picker
   * (redirect-to-processor; the CSP forbids an embedded SDK); the amount + live
   * impact come from the shared DonationAmountPicker. Submits a kind:'donation'
   * checkout. Renders only when billing + donations are enabled and a rail is live.
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
  import Heart from '@lucide/svelte/icons/heart';
  import DonationAmountPicker from './DonationAmountPicker.svelte';

  const config = configQuery();
  let billing = $derived(config.data?.billing);
  let donation = $derived(billing?.donation);
  let currency = $derived(billing?.currency ?? 'USD');

  const RAIL_ORDER: BillingProcessor[] = ['nowpayments', 'btcpay', 'stripe', 'paypal'];
  let rails = $derived(RAIL_ORDER.filter((r) => billing?.rails?.[r]));

  let selectedProcessorRaw = $state<BillingProcessor | null>(null);
  let selectedProcessor = $derived(selectedProcessorRaw ?? rails[0] ?? null);
  let cents = $state(0);

  let minCents = $derived(donation?.minAmountCents ?? 0);
  let belowMin = $derived(cents < minCents);

  function railLabel(r: BillingProcessor): string {
    return r === 'nowpayments'
      ? t('upgrade.payNowpayments')
      : r === 'btcpay'
        ? t('upgrade.payBtcpay')
        : r === 'stripe'
          ? t('upgrade.payStripe')
          : t('upgrade.payPaypal');
  }

  const checkout = createMutation(() => ({
    mutationFn: (vars: { processor: BillingProcessor; donationCents: number }) =>
      apiClient.post('/api/v1/billing/checkout', { ...vars, kind: 'donation' }, CheckoutResponse),
    onSuccess: (res) => {
      window.location.href = res.redirectUrl;
    },
    onError: (err) => toast.error(t('donate.startFailed'), { description: apiErrorMessage(err) }),
  }));

  function submit() {
    if (selectedProcessor && cents > 0 && !belowMin) {
      checkout.mutate({ processor: selectedProcessor, donationCents: cents });
    }
  }
</script>

{#if billing?.enabled && donation?.enabled && rails.length > 0}
  <section
    class="donation-sheen relative space-y-4 overflow-hidden rounded-xl border border-amber-500/40 bg-card p-4 ring-1 ring-amber-500/20 sm:p-5"
  >
    <div>
      <h2 class="flex items-center gap-2 font-display text-base font-semibold">
        <Heart class="size-4 shrink-0 text-amber-500" aria-hidden="true" />
        {t('donate.standaloneTitle')}
      </h2>
      <p class="text-sm text-muted-foreground">{t('donate.standaloneSubtitle')}</p>
    </div>

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
            class="rounded-lg border p-3 text-start text-sm font-semibold transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background {selectedProcessor ===
            r
              ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
              : 'border-border hover:border-primary/40'}"
          >
            {railLabel(r)}
          </button>
        {/each}
      </div>
    </fieldset>

    <fieldset>
      <legend class="mb-2 text-xs font-medium text-muted-foreground">
        {t('donate.amountLabel')}
      </legend>
      <DonationAmountPicker bind:cents />
      {#if minCents > 0}
        <p class="mt-2 text-xs text-muted-foreground">
          {t('donate.minNote', { amount: formatMoney(minCents, currency) })}
        </p>
      {/if}
    </fieldset>

    <div class="flex justify-end">
      <Button
        onclick={submit}
        disabled={!selectedProcessor || cents <= 0 || belowMin || checkout.isPending}
        class="min-h-11 w-full sm:w-auto"
      >
        {checkout.isPending
          ? t('donate.giving')
          : t('donate.give', { amount: formatMoney(cents > 0 ? cents : 0, currency) })}
      </Button>
    </div>
  </section>
{/if}
