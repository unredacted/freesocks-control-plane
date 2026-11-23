<script lang="ts">
  /**
   * Admin -> Billing: direct checkout for the crypto rails. "On FreeSocks"
   * shows the deposit address, amount, network, memo, QR and timer on our own
   * page (read server-side from the processor API), so payers who can't reach
   * nowpayments.io or the BTCPay host can still pay. The webhook and grant
   * path are the same as hosted. Saved with the rest of the billing form.
   */
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Input } from '@client/components/ui/input';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { formatMoney } from '../../lib/i18n/format';
  import {
    CoinCheckResponse,
    type CheckoutStyle,
    type DirectCheckoutView,
  } from '../../../shared/contracts/billing';
  import { toast } from 'svelte-sonner';

  interface Props {
    direct: DirectCheckoutView;
    currency: string;
  }
  let { direct = $bindable(), currency }: Props = $props();

  const STYLES: { value: CheckoutStyle; label: string }[] = [
    { value: 'hosted', label: "Processor's page (hosted)" },
    { value: 'direct', label: 'On FreeSocks (direct)' },
  ];

  function addCoin() {
    direct.nowpayments.coins = [
      ...direct.nowpayments.coins,
      { ticker: '', label: '', network: '', allowMemo: false },
    ];
  }
  function removeCoin(i: number) {
    direct.nowpayments.coins = direct.nowpayments.coins.filter((_, idx) => idx !== i);
  }
  function moveCoin(i: number, by: -1 | 1) {
    const list = [...direct.nowpayments.coins];
    const j = i + by;
    if (j < 0 || j >= list.length) return;
    [list[i], list[j]] = [list[j]!, list[i]!];
    direct.nowpayments.coins = list;
  }

  // --- "Check coins": read-only report against the NOWPayments account. ----
  let check = $state<CoinCheckResponse | null>(null);
  let checking = $state(false);
  async function runCheck() {
    checking = true;
    try {
      check = await apiClient.post('/api/v1/admin/billing/check-coins', {}, CoinCheckResponse);
      if (!check.ok && check.error) toast.error(check.error);
    } catch (err) {
      toast.error('Check failed', { description: apiErrorMessage(err) });
    } finally {
      checking = false;
    }
  }
  /** Warnings for one saved coin; the check runs against the SAVED list. */
  function warnings(ticker: string): string[] {
    const row = check?.coins.find((c) => c.ticker === ticker);
    if (!row) return [];
    const coin = direct.nowpayments.coins.find((c) => c.ticker === ticker);
    const out: string[] = [];
    if (row.enabledOnAccount === false) out.push('not switched on in the NOWPayments dashboard');
    if (row.needsMemo && coin && !coin.allowMemo) {
      out.push('uses a memo: payments will be refused until "Memo OK" is ticked');
    }
    if (
      row.minFiat != null &&
      check?.cheapestCryptoCents != null &&
      row.minFiat * 100 > check.cheapestCryptoCents
    ) {
      out.push(
        `minimum about ${formatMoney(Math.ceil(row.minFiat * 100), currency)} is above the cheapest crypto term`,
      );
    }
    return out;
  }

  let methodsText = $derived(direct.btcpay.methods.join(', '));
</script>

<div class="space-y-4 border-t border-border pt-4">
  <div>
    <h3 class="text-sm font-semibold">Direct checkout (crypto)</h3>
    <p class="mt-1 text-xs text-muted-foreground">
      "On FreeSocks" shows the address, exact amount, network, memo, QR code and timer on our own
      page, so a payer who can't reach the processor's site can still pay. Payments are confirmed
      and granted exactly as on the hosted page. Card and PayPal always stay hosted.
    </p>
  </div>

  <!-- NOWPayments -->
  <div class="space-y-3 rounded-lg border border-border p-3">
    <label class="block">
      <span class="mb-1 block text-xs font-medium text-muted-foreground">
        Crypto (NOWPayments) checkout
      </span>
      <select
        class="min-h-9 rounded-md border border-input bg-background px-2 text-sm"
        value={direct.nowpayments.style}
        onchange={(e) =>
          (direct.nowpayments.style = (e.currentTarget as HTMLSelectElement)
            .value as CheckoutStyle)}
      >
        {#each STYLES as s (s.value)}
          <option value={s.value}>{s.label}</option>
        {/each}
      </select>
    </label>

    <div>
      <p class="text-xs font-medium text-muted-foreground">Coins members can pick</p>
      <p class="mt-1 text-xs text-muted-foreground">
        Ticker is NOWPayments' code, which names the network (usdttrc20 = USDT on Tron). Unit and
        network are shown to members as written, so name the network exactly. A coin that needs a
        memo or destination tag is refused unless "Memo OK" is ticked. With no coins, the rail stays
        hosted.
      </p>
    </div>
    {#if direct.nowpayments.coins.length > 0}
      <div class="space-y-2">
        {#each direct.nowpayments.coins as c, i (i)}
          {@const warn = warnings(c.ticker)}
          <div class="flex flex-wrap items-center gap-2">
            <Input
              class="min-h-9 w-32 font-mono"
              placeholder="usdttrc20"
              aria-label="Ticker"
              value={c.ticker}
              oninput={(e) => (c.ticker = (e.currentTarget as HTMLInputElement).value.trim())}
            />
            <Input
              class="min-h-9 w-20"
              placeholder="USDT"
              aria-label="Unit"
              value={c.label}
              oninput={(e) => (c.label = (e.currentTarget as HTMLInputElement).value)}
            />
            <Input
              class="min-h-9 w-48"
              placeholder="Tron (TRC-20)"
              aria-label="Network"
              value={c.network}
              oninput={(e) => (c.network = (e.currentTarget as HTMLInputElement).value)}
            />
            <label class="flex items-center gap-1.5 text-xs">
              <Checkbox checked={c.allowMemo} onCheckedChange={(v) => (c.allowMemo = !!v)} />
              Memo OK
            </label>
            <Button variant="ghost" size="sm" onclick={() => moveCoin(i, -1)} aria-label="Move up">
              ↑
            </Button>
            <Button variant="ghost" size="sm" onclick={() => moveCoin(i, 1)} aria-label="Move down">
              ↓
            </Button>
            <Button variant="ghost" size="sm" onclick={() => removeCoin(i)}>Remove</Button>
            {#if warn.length > 0}
              <span class="basis-full text-xs text-amber-600 dark:text-amber-400">
                {c.ticker}: {warn.join('; ')}
              </span>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
    <div class="flex flex-wrap items-center gap-2">
      <Button variant="outline" size="sm" onclick={addCoin}>Add coin</Button>
      <Button variant="outline" size="sm" onclick={runCheck} disabled={checking}>
        {checking ? 'Checking…' : 'Check coins'}
      </Button>
      <span class="text-xs text-muted-foreground">
        Checks the saved list against your NOWPayments account. Creates nothing.
      </span>
    </div>
    {#if check?.ok}
      {@const flagged = check.coins.filter((c) => warnings(c.ticker).length > 0).length}
      {@const unread = check.coins.filter(
        (c) => c.enabledOnAccount == null && c.needsMemo == null && c.minFiat == null,
      ).length}
      <p
        class="text-xs {flagged || unread
          ? 'text-amber-600 dark:text-amber-400'
          : 'text-muted-foreground'}"
      >
        {#if flagged}
          {flagged} of {check.coins.length} coins need attention (see the notes above).
        {/if}
        {#if unread}
          NOWPayments returned nothing readable for {unread} of {check.coins.length} coins, so they are
          unchecked.
        {/if}
        {#if !flagged && !unread}
          All {check.coins.length} coins look usable. Minimums are indicative; the payment itself has
          the last word.
        {/if}
      </p>
    {/if}
  </div>

  <!-- BTCPay -->
  <div class="space-y-3 rounded-lg border border-border p-3">
    <label class="block">
      <span class="mb-1 block text-xs font-medium text-muted-foreground">
        Bitcoin (BTCPay) checkout
      </span>
      <select
        class="min-h-9 rounded-md border border-input bg-background px-2 text-sm"
        value={direct.btcpay.style}
        onchange={(e) =>
          (direct.btcpay.style = (e.currentTarget as HTMLSelectElement).value as CheckoutStyle)}
      >
        {#each STYLES as s (s.value)}
          <option value={s.value}>{s.label}</option>
        {/each}
      </select>
    </label>
    <label class="block">
      <span class="mb-1 block text-xs font-medium text-muted-foreground">Payment methods shown</span
      >
      <Input
        class="min-h-9 font-mono"
        placeholder="BTC-CHAIN, BTC-LN"
        value={methodsText}
        onchange={(e) =>
          (direct.btcpay.methods = (e.currentTarget as HTMLInputElement).value
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean))}
      />
      <span class="mt-1 block text-xs text-muted-foreground">
        BTCPay payment method ids, in the order shown. Only methods the invoice has activated
        appear; turn off "lazy payment methods" in the store, or the page falls back to BTCPay's
        own.
      </span>
    </label>
  </div>
</div>
