<script lang="ts">
  /**
   * The coin (and network) for a direct crypto checkout, from
   * GET /api/v1/billing/coins (the coins switched on in the NOWPayments
   * dashboard, or the operator's own list), already in display order: pinned
   * coins first. The first few are buttons; the full list is a native
   * drop-down (type-ahead works, and it is the most robust control on old
   * phones). The network is on every option because the same coin on the wrong
   * network is lost money.
   */
  import { t } from '../lib/i18n/index.svelte';

  interface Coin {
    ticker: string;
    label: string;
    network: string;
    memo: boolean;
    pinned: boolean;
  }
  interface Props {
    coins: Coin[];
    /** The picked ticker. */
    selected: string | null;
    onSelect: (ticker: string) => void;
  }
  let { coins, selected, onSelect }: Props = $props();

  const QUICK = 6;
  // Quick buttons: the operator's pinned coins (first six of a hand-written list).
  let quick = $derived(coins.filter((c) => c.pinned).slice(0, QUICK));
  let inQuick = $derived(quick.some((c) => c.ticker === selected));
  const optionText = (c: Coin) =>
    `${c.label} · ${c.network}${c.memo ? ` (${t('direct.needsMemo')})` : ''}`;
</script>

<fieldset>
  <legend class="mb-2 text-xs font-medium text-muted-foreground">{t('direct.coinLabel')}</legend>
  <div class="grid grid-cols-2 gap-2 sm:grid-cols-3">
    {#each quick as c (c.ticker)}
      <button
        type="button"
        onclick={() => onSelect(c.ticker)}
        aria-pressed={selected === c.ticker}
        class="rounded-lg border p-2.5 text-start transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background {selected ===
        c.ticker
          ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
          : 'border-border hover:border-primary/40'}"
      >
        <div class="text-sm font-semibold">{c.label}</div>
        <div class="text-xs text-muted-foreground">{c.network}</div>
      </button>
    {/each}
  </div>
  {#if coins.length > quick.length}
    <label class="mt-2 block">
      <span class="sr-only">{t('direct.allCoins')}</span>
      <select
        class="min-h-11 w-full rounded-lg border bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring {selected &&
        !inQuick
          ? 'border-primary ring-1 ring-primary/30'
          : 'border-border'}"
        value={inQuick ? '' : (selected ?? '')}
        onchange={(e) => {
          const v = (e.currentTarget as HTMLSelectElement).value;
          if (v) onSelect(v);
        }}
      >
        <option value="">{t('direct.allCoinsPlaceholder', { count: coins.length })}</option>
        {#each coins as c (c.ticker)}
          <option value={c.ticker}>{optionText(c)}</option>
        {/each}
      </select>
    </label>
  {/if}
  <p class="mt-2 text-xs text-muted-foreground">{t('direct.coinHint')}</p>
</fieldset>
