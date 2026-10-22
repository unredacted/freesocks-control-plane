<script lang="ts">
  /**
   * One load balancer plan in a line (docs/edges.md § "Plans and prices"): its
   * price a month (and an hour), traffic terms, bandwidth, whether it takes a
   * node outside the provider, and where the price comes from. A size FCP
   * refuses for a node (`size_not_multicloud`) says so in its reason's words.
   *
   * Props:
   *   plan: PlanLike
   */
  import { SETUP_ACCOUNT_REASON_COPY } from '@client/lib/edgeCodes';
  import {
    bandwidthWords,
    outsideWords,
    planPriceWords,
    planRefused,
    sourceWords,
    trafficWords,
    type PlanLike,
  } from '../lib/planWords';

  interface Props {
    plan: PlanLike;
  }
  let { plan }: Props = $props();

  const facts = $derived(
    [
      planPriceWords(plan),
      trafficWords(plan.traffic),
      bandwidthWords(plan.bandwidthMbps),
      outsideWords(plan),
    ].filter((x) => x !== ''),
  );
  const refused = $derived(planRefused(plan));
</script>

<p class="text-muted-foreground text-xs">
  {facts.join('. ')}. {sourceWords(plan)}.
</p>
{#if refused}
  <p class="text-destructive text-xs">{SETUP_ACCOUNT_REASON_COPY.size_not_multicloud.explain}</p>
{/if}
