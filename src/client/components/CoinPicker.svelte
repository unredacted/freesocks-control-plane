<script lang="ts">
  /**
   * The coin (and network) for a direct crypto checkout. The list is the
   * operator's allowlist from PublicConfig.billing.direct.nowpayments.coins;
   * its label and network are operator text shown verbatim. The network is
   * on every option because the same coin on the wrong network is lost money.
   */
  import { t } from '../lib/i18n/index.svelte';

  interface Coin {
    ticker: string;
    label: string;
    network: string;
  }
  interface Props {
    coins: Coin[];
    /** The picked ticker. */
    selected: string | null;
    onSelect: (ticker: string) => void;
  }
  let { coins, selected, onSelect }: Props = $props();
</script>

<fieldset>
  <legend class="mb-2 text-xs font-medium text-muted-foreground">{t('direct.coinLabel')}</legend>
  <div class="grid grid-cols-2 gap-2 sm:grid-cols-3">
    {#each coins as c (c.ticker)}
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
  <p class="mt-2 text-xs text-muted-foreground">{t('direct.coinHint')}</p>
</fieldset>
