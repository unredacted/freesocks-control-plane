<script lang="ts">
  /**
   * Shared donation-amount picker: preset chips (from the admin-configured
   * suggested amounts) + a custom input, with a live "adds ~N GB to every free
   * user" impact line. Used both as the optional add-on inside UpgradeMembership
   * and standalone in DonateCard. Reads the public donation config; renders
   * nothing when donations are disabled. `cents` is bindable (0 = none).
   */
  import { Input } from '@client/components/ui/input';
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';

  interface Props {
    /** Selected donation in cents (0 = none). Bindable. */
    cents: number;
    /** Show a "No thanks" (0) chip - used for the optional membership add-on. */
    allowNone?: boolean;
  }
  let { cents = $bindable(0), allowNone = false }: Props = $props();

  const config = configQuery();
  let donation = $derived(config.data?.billing?.donation);
  let currency = $derived(config.data?.billing?.currency ?? 'USD');
  let suggested = $derived(donation?.suggestedAmountsCents ?? []);
  let rate = $derived(donation?.bonusGbPerUsd ?? 0);

  let customText = $state('');
  // A positive value that isn't one of the presets is a custom amount.
  let isCustom = $derived(cents > 0 && !suggested.includes(cents));

  function pick(c: number) {
    cents = c;
    customText = '';
  }
  function onCustom(v: string) {
    customText = v;
    const dollars = Number(v);
    cents = Number.isFinite(dollars) && dollars > 0 ? Math.round(dollars * 100) : 0;
  }
  // Normalize the display ONLY when the user leaves the field. Reformatting on
  // every keystroke hijacked the caret: typing "44" became "4.00" after the
  // first key, and the next "4" landed as 4.04.
  function onCustomBlur() {
    if (customText !== '' && cents > 0) customText = (cents / 100).toFixed(2);
  }

  function fmtGb(gb: number): string {
    const r = Math.round(gb * 10) / 10;
    return Number.isInteger(r) ? String(r) : r.toFixed(1);
  }
  let impactGb = $derived(cents > 0 && rate > 0 ? (cents / 100) * rate : 0);

  const chipBase =
    'rounded-lg border px-3 py-1.5 text-sm font-medium tabular-nums transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background';
  const chipOn = 'border-amber-500 bg-amber-500/10 text-amber-700 dark:text-amber-300';
  const chipOff = 'border-border hover:border-amber-500/50';
</script>

{#if donation?.enabled}
  <div>
    <div class="flex flex-wrap items-center gap-2">
      {#if allowNone}
        <button
          type="button"
          onclick={() => pick(0)}
          aria-pressed={cents === 0}
          class="{chipBase} {cents === 0 ? chipOn : chipOff}"
        >
          {t('donate.none')}
        </button>
      {/if}
      {#each suggested as amt (amt)}
        <button
          type="button"
          onclick={() => pick(amt)}
          aria-pressed={cents === amt && !isCustom}
          class="{chipBase} {cents === amt && !isCustom ? chipOn : chipOff}"
        >
          {formatMoney(amt, currency)}
        </button>
      {/each}
      <div class="flex items-center gap-1">
        <span class="text-xs text-muted-foreground">{currency}</span>
        <Input
          type="number"
          min={0}
          step="0.01"
          class="min-h-9 w-24 {isCustom ? 'border-amber-500' : ''}"
          placeholder={t('donate.customPlaceholder')}
          value={customText}
          oninput={(e) => onCustom((e.currentTarget as HTMLInputElement).value)}
          onblur={onCustomBlur}
          aria-label={t('donate.custom')}
        />
      </div>
    </div>
    {#if impactGb > 0}
      <p class="mt-2 text-xs text-amber-600 dark:text-amber-400">
        {t('donate.impact', { gb: fmtGb(impactGb) })}
      </p>
    {/if}
  </div>
{/if}
