<script lang="ts">
  /**
   * One provider account as a card: Connected / Problem / Not tested, how many
   * addresses are used, and the trust line (plan 1.7, exact words). The card
   * opens the account page.
   *
   * Props:
   *   account: EdgeProviderAccountAdmin
   *   usage?: { liveEdges; maxLiveEdges } | null    from providers/usage
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import Link from '@client/components/Link.svelte';
  import type { EdgeProviderAccountAdmin } from '@shared/contracts/edges';
  import { EDGE_PROVIDER_META } from '@client/lib/edgeProviderMeta';
  import FakeBadge from '../components/FakeBadge.svelte';
  import { providerLabel } from '../lib/format';
  import { edgesPaths } from '../lib/routes';
  import { isTested } from '../providers/accountWords';
  import StatusDot from './StatusDot.svelte';
  import type { Dot } from './nodeStatus';

  interface Props {
    account: EdgeProviderAccountAdmin;
    usage?: { liveEdges: number; maxLiveEdges: number } | null;
  }
  let { account: a, usage = null }: Props = $props();

  const layer = $derived(EDGE_PROVIDER_META[a.provider].layer);
  const state = $derived.by((): { label: string; dot: Dot } => {
    if (!a.enabled) return { label: 'Disabled', dot: 'grey' };
    if (a.lastTestError !== null) return { label: 'Problem', dot: 'red' };
    if (isTested(a)) return { label: 'Connected', dot: 'green' };
    return { label: 'Not tested', dot: 'amber' };
  });
  const date = (iso: string) => new Date(iso).toLocaleDateString();
  const trust = $derived.by((): string => {
    if (a.qualified && a.qualification) {
      if (a.qualification.by === 'auto')
        return `Trusted automatically, checked with a real session on ${date(a.qualification.at)}.`;
      // An endpoint confirmation carries the edge it was tried on; the manual
      // "Trust override" carries none and never claims a session happened.
      return a.qualification.edgeId && layer !== 'l7'
        ? `Tried with a real session by you on ${date(a.qualification.at)}.`
        : `Trusted by you on ${date(a.qualification.at)}.`;
    }
    if (a.qualified) return 'Trusted.';
    if (isTested(a)) return 'Reached from outside. Not yet tried with a real session.';
    return 'Not tried yet.';
  });
</script>

<Link
  href={edgesPaths.provider(a.id)}
  class="bg-card hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 items-start gap-3 rounded-lg border p-3 outline-none focus-visible:ring-3"
>
  <StatusDot dot={state.dot} class="mt-1.5" />
  <span class="min-w-0 flex-1">
    <span class="flex flex-wrap items-baseline gap-x-2">
      <span class="font-medium">{a.name}</span>
      <span class="text-muted-foreground text-xs">
        {providerLabel(a.provider)}, {layer === 'l7' ? 'CDN front' : 'load balancer'}
      </span>
      <FakeBadge fake={a.fake} />
    </span>
    <span class="text-muted-foreground block text-sm">
      {state.label}{#if usage}, {usage.liveEdges} of {usage.maxLiveEdges} addresses used{/if}.
    </span>
    <span class="text-muted-foreground block text-sm">{trust}</span>
  </span>
  <ChevronRight
    class="text-muted-foreground mt-1 size-4 shrink-0 rtl:rotate-180"
    aria-hidden="true"
  />
</Link>
