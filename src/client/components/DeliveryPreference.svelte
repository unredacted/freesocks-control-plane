<script lang="ts">
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import Zap from '@lucide/svelte/icons/zap';
  import Check from '@lucide/svelte/icons/check';
  import { t } from '../lib/i18n/index.svelte';
  import { deliveryPref, setDeliveryPref } from '../lib/deliveryPref.svelte';

  /**
   * "What matters most to you?" picker. Both options are always shown; the one
   * the server recommends (country-based) carries a "Recommended" badge and is
   * the highlighted default until the member picks. The choice is client-side
   * only (localStorage) — it reorders the delivery panels below, nothing more.
   */
  interface Props {
    /** Server's country-based recommendation (highlighted), if any. */
    suggested?: 'privacy' | 'evade';
  }
  let { suggested = 'evade' }: Props = $props();

  // Explicit choice wins; otherwise fall to the country suggestion.
  let selected = $derived(deliveryPref() ?? suggested);

  const OPTIONS = [
    { mode: 'evade', icon: Zap, titleKey: 'delivery.evadeTitle', bodyKey: 'delivery.evadeBody' },
    {
      mode: 'privacy',
      icon: ShieldCheck,
      titleKey: 'delivery.privacyTitle',
      bodyKey: 'delivery.privacyBody',
    },
  ] as const;
</script>

<section class="space-y-3 rounded-xl border border-border bg-card p-4 sm:p-5">
  <div>
    <h2 class="font-display text-base font-semibold">{t('delivery.title')}</h2>
    <p class="text-sm text-muted-foreground">{t('delivery.subtitle')}</p>
  </div>
  <div class="grid gap-3 sm:grid-cols-2">
    {#each OPTIONS as opt (opt.mode)}
      <button
        type="button"
        onclick={() => setDeliveryPref(opt.mode)}
        aria-pressed={selected === opt.mode}
        class="relative rounded-lg border p-4 text-start transition {selected === opt.mode
          ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
          : 'border-border hover:border-primary/40'}"
      >
        <div class="flex items-center justify-between gap-2">
          <span class="flex items-center gap-2 text-sm font-semibold">
            <opt.icon class="size-4 shrink-0 text-primary" />
            {t(opt.titleKey)}
          </span>
          {#if suggested === opt.mode}
            <span
              class="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary"
            >
              {t('delivery.recommended')}
            </span>
          {:else if selected === opt.mode}
            <Check class="size-4 shrink-0 text-primary" />
          {/if}
        </div>
        <p class="mt-1 text-xs text-muted-foreground">{t(opt.bodyKey)}</p>
      </button>
    {/each}
  </div>
</section>
