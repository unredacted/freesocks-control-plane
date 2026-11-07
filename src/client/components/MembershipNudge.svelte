<script lang="ts">
  /**
   * A short membership strip shown once a free member's key is set up
   * (/get-account, under the setup steps): the free allowance next to what a
   * membership adds, and one action to the account's Membership tab. Renders
   * nothing unless billing is on and a membership tier exists.
   */
  import { Button } from '@client/components/ui/button';
  import Zap from '@lucide/svelte/icons/zap';
  import { configQuery } from '../lib/queries';
  import { router } from '../stores/router.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';
  import { baselinePerMonth } from '../lib/billing';
  import { freeTier, membershipTier } from '../lib/tiers';

  const config = configQuery();
  let billingOn = $derived(config.data?.billing?.enabled ?? false);
  let member = $derived(membershipTier(config.data));
  let freeGb = $derived(freeTier(config.data)?.monthlyTrafficGb ?? 0);
  let monthlyCents = $derived(baselinePerMonth(config.data?.billing?.durations ?? []));
  let price = $derived(
    monthlyCents !== null
      ? formatMoney(Math.round(monthlyCents), config.data?.billing?.currency ?? 'USD')
      : null,
  );
</script>

{#if billingOn && member}
  <section
    aria-labelledby="nudge-title"
    class="shimmer-border flex flex-wrap items-center gap-x-6 gap-y-4 rounded-lg px-5 py-4 sm:px-6"
  >
    <span
      class="flex size-11 shrink-0 items-center justify-center rounded-sm bg-primary text-primary-foreground"
    >
      <Zap class="size-5" aria-hidden="true" />
    </span>
    <div class="min-w-0 flex-[1_1_18rem] space-y-1">
      <p id="nudge-title" class="font-display text-lg font-bold text-foreground">
        {freeGb > 0 ? t('get.nudge.titleCapped', { gb: freeGb }) : t('get.nudge.title')}
      </p>
      <p class="text-[15px] text-muted-foreground">
        {member.monthlyTrafficGb === 0 ? t('get.nudge.bodyUnlimited') : t('get.nudge.body')}
        {#if price}{' '}{t('upgrade.fromPerMonth', { price })}{/if}
      </p>
    </div>
    <Button size="lg" onclick={() => router.navigate('/account?tab=membership')}>
      {t('get.nudge.cta')}
    </Button>
  </section>
{/if}
