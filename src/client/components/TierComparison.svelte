<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import Minus from '@lucide/svelte/icons/minus';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { configQuery } from '../lib/queries';

  /**
   * Side-by-side feature comparison for free vs paid tiers. The bandwidth and
   * device numbers are pulled live from `/api/v1/config` (the actual
   * DB-enforced limits), so they can't drift from the seed; the static card
   * scaffold below supplies presentational copy (validity, mirrors) and a
   * fallback when config hasn't loaded. Pricing is not shown here because we
   * don't manage billing; once the membership signup flow is live, the
   * paid-tier cards will gain a CTA. Until then they show "Coming soon".
   */
  interface Props {
    currentTierSlug: string;
  }
  let { currentTierSlug }: Props = $props();

  const config = configQuery();

  interface TierCard {
    slug: string;
    name: string;
    features: {
      bandwidth: string;
      devices: string;
      validity: string;
      mirrors: boolean;
    };
  }
  const tiers: TierCard[] = [
    {
      slug: 'free',
      name: 'Free',
      features: {
        bandwidth: '50 GB / month',
        devices: '1 device',
        validity: '30-day key',
        mirrors: true,
      },
    },
    {
      slug: 'member',
      name: 'Member',
      features: {
        bandwidth: '500 GB / month',
        devices: '3 devices',
        validity: 'Continuous',
        mirrors: true,
      },
    },
    {
      slug: 'patron',
      name: 'Patron',
      features: {
        bandwidth: 'Unlimited',
        devices: '5 devices',
        validity: 'Continuous',
        mirrors: true,
      },
    },
  ];

  // Live, DB-enforced limits keyed by slug; overlaid onto the scaffold above.
  const liveLimits = $derived(new Map((config.data?.tiers ?? []).map((t) => [t.slug, t])));
  function bandwidthLabel(slug: string, fallback: string): string {
    const t = liveLimits.get(slug);
    if (!t) return fallback;
    return t.monthlyTrafficGb === 0 ? 'Unlimited' : `${t.monthlyTrafficGb} GB / month`;
  }
  function deviceLabel(slug: string, fallback: string): string {
    const t = liveLimits.get(slug);
    if (!t) return fallback;
    return `${t.deviceLimit} device${t.deviceLimit === 1 ? '' : 's'}`;
  }
</script>

<section class="space-y-4">
  <div>
    <h2 class="text-xl font-display font-bold tracking-tight">Tiers</h2>
    <p class="text-sm text-muted-foreground">
      What each tier includes. Pricing and signup live on the Unredacted member portal.
    </p>
  </div>

  <div class="grid gap-3 md:grid-cols-3">
    {#each tiers as tier (tier.slug)}
      {@const isCurrent = tier.slug === currentTierSlug}
      <div
        class="rounded-xl border p-5 space-y-4 relative overflow-hidden bg-card {isCurrent
          ? 'ring-1 ring-primary/30 border-primary/30'
          : 'border-border'}"
      >
        {#if isCurrent}
          <div
            class="absolute top-0 left-0 px-2 py-1 rounded-br-lg bg-secondary text-secondary-foreground text-[10px] font-semibold uppercase tracking-wider"
          >
            Your tier
          </div>
        {/if}

        <div class="space-y-1 pt-3">
          <h3 class="text-lg font-display font-semibold">{tier.name}</h3>
        </div>

        <ul class="space-y-2 text-sm">
          <li class="flex items-start gap-2">
            <Check class="size-4 text-primary shrink-0 mt-0.5" />
            {#if config.isPending}
              <Skeleton class="h-4 w-28" />
            {:else}
              <span class="tabular-nums">{bandwidthLabel(tier.slug, tier.features.bandwidth)}</span>
            {/if}
          </li>
          <li class="flex items-start gap-2">
            <Check class="size-4 text-primary shrink-0 mt-0.5" />
            {#if config.isPending}
              <Skeleton class="h-4 w-20" />
            {:else}
              <span class="tabular-nums">{deviceLabel(tier.slug, tier.features.devices)}</span>
            {/if}
          </li>
          <li class="flex items-start gap-2">
            <Check class="size-4 text-primary shrink-0 mt-0.5" />
            <span>{tier.features.validity}</span>
          </li>
          <li class="flex items-start gap-2">
            {#if tier.features.mirrors}
              <Check class="size-4 text-primary shrink-0 mt-0.5" />
            {:else}
              <Minus class="size-4 text-muted-foreground/40 shrink-0 mt-0.5" />
            {/if}
            <span class="text-muted-foreground">Mirror URLs</span>
          </li>
        </ul>

        {#if !isCurrent && tier.slug !== 'free'}
          <!--
            Membership signup isn't wired end-to-end yet. Render a disabled
            "coming soon" affordance instead of linking out to a join page
            that's still being designed.
          -->
          <Button
            variant="outline"
            class="w-full"
            size="sm"
            disabled
            aria-disabled="true"
            title="Membership signup is coming soon"
          >
            Coming soon
          </Button>
        {/if}
      </div>
    {/each}
  </div>
</section>
