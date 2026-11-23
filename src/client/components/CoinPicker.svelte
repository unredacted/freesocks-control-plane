<script lang="ts">
  /**
   * The coin (and network) for a direct crypto checkout, from
   * GET /api/v1/billing/coins (the coins switched on in the NOWPayments
   * dashboard, or the operator's own list), already in display order. Pinned
   * coins are quick-pick buttons; every coin is in a searchable list below
   * (coin, ticker or network: "usdt", "trc20" and "tron" all find USDT on
   * Tron). The network is on every option because the same coin on the wrong
   * network is lost money. Plain buttons and an input: no third-party widget.
   */
  import { t } from '../lib/i18n/index.svelte';
  import Search from '@lucide/svelte/icons/search';

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
  let picked = $derived(coins.find((c) => c.ticker === selected) ?? null);

  // Search: every word must appear in the coin's unit, ticker or network, with
  // punctuation ignored so "trc20" matches "Tron (TRC-20)".
  const norm = (s: string) => s.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '');
  let query = $state('');
  let matches = $derived.by(() => {
    const words = query.split(/\s+/).map(norm).filter(Boolean);
    if (words.length === 0) return coins;
    return coins.filter((c) => {
      const hay = norm(`${c.label} ${c.ticker} ${c.network}`);
      return words.every((w) => hay.includes(w));
    });
  });

  const ROW =
    'flex w-full items-center justify-between gap-2 px-3 py-2 text-start text-sm transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring';
</script>

<fieldset>
  <legend class="mb-2 text-xs font-medium text-muted-foreground">{t('direct.coinLabel')}</legend>
  {#if quick.length > 0}
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
  {/if}

  {#if coins.length > quick.length}
    <div class="mt-2 rounded-lg border border-border">
      <label class="flex items-center gap-2 border-b border-border px-3">
        <Search class="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span class="sr-only">{t('direct.searchLabel')}</span>
        <input
          type="search"
          bind:value={query}
          placeholder={t('direct.searchPlaceholder', { count: coins.length })}
          autocomplete="off"
          spellcheck="false"
          class="min-h-11 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          onkeydown={(e) => {
            // Enter picks the top match instead of submitting anything.
            if (e.key === 'Enter') {
              e.preventDefault();
              if (matches[0]) onSelect(matches[0].ticker);
            }
          }}
        />
      </label>
      <div
        class="max-h-56 divide-y divide-border/60 overflow-y-auto"
        role="group"
        aria-label={t('direct.allCoins')}
      >
        {#each matches as c (c.ticker)}
          <button
            type="button"
            class="{ROW} {selected === c.ticker
              ? 'bg-primary/10 font-semibold'
              : 'hover:bg-muted/50'}"
            aria-pressed={selected === c.ticker}
            onclick={() => onSelect(c.ticker)}
          >
            <span>
              <span class="font-medium">{c.label}</span>
              <span class="text-muted-foreground"> · {c.network}</span>
            </span>
            {#if c.memo}
              <span class="shrink-0 text-[0.7rem] text-muted-foreground">
                {t('direct.needsMemo')}
              </span>
            {/if}
          </button>
        {:else}
          <p class="px-3 py-2 text-xs text-muted-foreground">{t('direct.noMatch')}</p>
        {/each}
      </div>
    </div>
    {#if picked && !inQuick}
      <p class="mt-2 text-xs" aria-live="polite">
        {t('direct.pickedCoin', { coin: picked.label, network: picked.network })}
      </p>
    {/if}
  {/if}
  <p class="mt-2 text-xs text-muted-foreground">{t('direct.coinHint')}</p>
</fieldset>
