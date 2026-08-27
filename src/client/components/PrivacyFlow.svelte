<script lang="ts">
  import { onMount } from 'svelte';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import RadioTower from '@lucide/svelte/icons/radio-tower';
  import Cloud from '@lucide/svelte/icons/cloud';
  import Server from '@lucide/svelte/icons/server';
  import Globe from '@lucide/svelte/icons/globe';
  import ArrowRight from '@lucide/svelte/icons/arrow-right';
  import ArrowDown from '@lucide/svelte/icons/arrow-down';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * "Who sees what": the path a member's traffic takes, as a PIPELINE of five
   * stops under the "What we store" claims - one card per stop with the
   * what-it-sees text ALWAYS visible (nothing hides behind hover), joined by
   * animated directional connectors. A row on desktop, a column on mobile.
   *
   * Deliberately a diagram, not a chart: the content is a sequence, so it is
   * plain HTML - it renders with the page, translates, and costs the public
   * bundle nothing. The one branch in the real topology (Privacy Mode skips
   * the CDN) is carried by the badge on the CDN card + the two-line mode
   * legend below, which kept beating every two-path layout for legibility.
   *
   * Motion: a highlight walks the pipeline (same cadence family as the hero
   * rotation) so the sequence reads as movement; a pointer on any card takes
   * over the highlight, and reduced-motion users get a calm static row (the
   * arrows still carry direction).
   */
  const HOPS = [
    { id: 'you', icon: Smartphone, name: 'home.flow.youName', sees: 'home.flow.youSees' },
    { id: 'isp', icon: RadioTower, name: 'home.flow.ispName', sees: 'home.flow.ispSees' },
    {
      id: 'cdn',
      icon: Cloud,
      name: 'home.flow.cdnName',
      sees: 'home.flow.cdnSees',
      badge: 'home.flow.cdnBadge',
    },
    { id: 'node', icon: Server, name: 'home.flow.nodeName', sees: 'home.flow.nodeSees' },
    { id: 'web', icon: Globe, name: 'home.flow.webName', sees: 'home.flow.webSees' },
  ] as const;

  // The walking highlight. `hovered` (pointer) always wins over the cycle.
  let cycleIdx = $state(0);
  let hovered = $state<number | null>(null);
  let reducedMotion = $state(false);
  onMount(() => {
    reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reducedMotion) return;
    const id = window.setInterval(() => {
      if (!document.hidden && hovered === null) cycleIdx = (cycleIdx + 1) % HOPS.length;
    }, 1800);
    return () => window.clearInterval(id);
  });
  const activeIdx = $derived(hovered ?? (reducedMotion ? null : cycleIdx));
</script>

<div class="space-y-5 border-t border-border/60 pt-8">
  <div class="max-w-2xl space-y-2">
    <h3 class="text-xl font-display font-bold tracking-tight">{t('home.flow.title')}</h3>
    <p class="text-sm text-muted-foreground leading-relaxed">{t('home.flow.subtitle')}</p>
  </div>

  <ol class="flex flex-col gap-0 lg:flex-row lg:items-stretch">
    {#each HOPS as hop, i (hop.id)}
      {@const Icon = hop.icon}
      {@const active = activeIdx === i}
      <li class="flex flex-col lg:flex-1 lg:flex-row lg:items-stretch">
        <div
          role="presentation"
          onpointerenter={() => (hovered = i)}
          onpointerleave={() => (hovered = null)}
          class="flex-1 rounded-lg border bg-card p-4 transition-all duration-300 {active
            ? 'border-primary/60 bg-primary/5 lg:-translate-y-0.5'
            : 'border-border'}"
        >
          <div class="flex items-center gap-2">
            <span
              class="flex size-8 shrink-0 items-center justify-center rounded-full transition-all duration-300 {active
                ? 'scale-110 bg-primary text-primary-foreground'
                : 'bg-primary/10 text-primary'}"
              aria-hidden="true"
            >
              <Icon class="size-4" />
            </span>
            <p class="text-sm font-semibold leading-tight">{t(hop.name)}</p>
          </div>
          {#if 'badge' in hop}
            <p
              class="mt-2 inline-block rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground"
            >
              {t(hop.badge)}
            </p>
          {/if}
          <p class="mt-2 text-xs text-muted-foreground leading-relaxed">{t(hop.sees)}</p>
        </div>
        {#if i < HOPS.length - 1}
          <!-- Directional connector: an animated dashed line + arrowhead
               (horizontal in the row layout, vertical when stacked). The dash
               drift only runs when motion is welcome. -->
          <div
            class="flex items-center justify-center gap-0 self-center py-1.5 transition-opacity duration-300 lg:px-0.5 lg:py-0 {active
              ? 'opacity-100'
              : 'opacity-60'}"
            aria-hidden="true"
          >
            <span class="flow-line hidden lg:block"></span>
            <ArrowRight class="hidden size-4 shrink-0 text-primary lg:block rtl:rotate-180" />
            <span class="flow-line-v lg:hidden"></span>
            <ArrowDown class="size-4 shrink-0 text-primary lg:hidden" />
          </div>
        {/if}
      </li>
    {/each}
  </ol>

  <!-- The two routes, one line each. -->
  <div class="max-w-2xl space-y-1 text-xs text-muted-foreground leading-relaxed">
    <p>
      <span class="font-semibold text-foreground">{t('delivery.freedomTitle')}:</span>
      {t('home.flow.captionFreedom')}
    </p>
    <p>
      <span class="font-semibold text-foreground">{t('delivery.privacyTitle')}:</span>
      {t('home.flow.captionPrivacy')}
    </p>
  </div>
</div>

<style>
  /* The traveling dash: a repeating gradient whose phase advances, reading as
     packets moving toward the arrowhead. Static dashes when reduced motion is
     preferred (the pattern still shows direction via the arrow). */
  .flow-line {
    width: 14px;
    height: 2px;
    background-image: repeating-linear-gradient(90deg, var(--primary) 0 4px, transparent 4px 8px);
    background-size: 8px 2px;
  }
  .flow-line-v {
    width: 2px;
    height: 14px;
    background-image: repeating-linear-gradient(180deg, var(--primary) 0 4px, transparent 4px 8px);
    background-size: 2px 8px;
  }
  @media (prefers-reduced-motion: no-preference) {
    .flow-line {
      animation: flow-x 0.9s linear infinite;
    }
    .flow-line-v {
      animation: flow-y 0.9s linear infinite;
    }
  }
  @keyframes flow-x {
    to {
      background-position-x: 8px;
    }
  }
  @keyframes flow-y {
    to {
      background-position-y: 8px;
    }
  }
  /* RTL: the dashes should drift toward the (flipped) arrow. */
  :global([dir='rtl']) .flow-line {
    animation-direction: reverse;
  }
</style>
