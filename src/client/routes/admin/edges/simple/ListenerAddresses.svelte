<script lang="ts">
  /**
   * One transport's addresses on the node page: a reduced pool strip (one health
   * dot per address in use, a spare cell per spare) and a plain line per
   * address (In use / Spare / Retiring, health, tested or not).
   *
   * Props: listener; edges (every non-destroyed edge of the origin); onTest(edgeId)
   */
  import type { EdgeAdmin, RelayListenerAdmin } from '@shared/contracts/edges';
  import { Button } from '@client/components/ui/button';
  import { healthLabel } from '@client/lib/edgeCodes';
  import PoolStrip from '../components/PoolStrip.svelte';
  import type { PoolEntry } from '../lib/types';

  interface Props {
    listener: RelayListenerAdmin;
    edges: EdgeAdmin[];
    onTest: (edgeId: string) => void;
  }
  let { listener, edges, onTest }: Props = $props();

  const mine = $derived(edges.filter((e) => e.listenerId === listener.id));
  const inUse = $derived(mine.filter((e) => e.publication === 'published'));
  const spares = $derived(
    mine.filter((e) => e.publication === 'unpublished' && e.status === 'active'),
  );
  const retiring = $derived(mine.filter((e) => e.publication === 'draining'));
  const entries = $derived<PoolEntry[]>(
    inUse.map((e, i) => ({
      poolIndex: e.poolIndex ?? i,
      edgeId: e.id,
      provider: e.provider,
      managed: e.managed,
      addresses: e.addresses,
      layer: e.layer,
      listenerId: e.listenerId,
      health: e.health,
      status: e.status,
      unreachableIn:
        e.reachability?.byCountry
          .filter((c) => c.verdict === 'unreachable')
          .map((c) => c.country) ?? [],
      mixedIn:
        e.reachability?.byCountry.filter((c) => c.verdict === 'mixed').map((c) => c.country) ?? [],
    })),
  );
  const address = (e: EdgeAdmin) =>
    e.addresses.hostname ?? e.addresses.v4 ?? e.addresses.v6 ?? e.name;
  const WORD = { published: 'In use', unpublished: 'Spare', draining: 'Retiring' } as const;
  const tested = (e: EdgeAdmin): string | null => {
    if (!e.verification.required) return null;
    if (e.verification.current) return 'tested';
    if (e.verification.stale) return 'retest needed';
    return 'not tested yet';
  };
</script>

<div class="mt-2 space-y-2">
  <PoolStrip
    publishedEdgeIds={inUse.map((e) => e.id)}
    desired={Math.max(inUse.length, 1)}
    standbys={spares.map((e) => e.id)}
    draining={retiring.length}
    {entries}
  />
  {#if mine.length === 0}
    <p class="text-muted-foreground text-sm">No address yet.</p>
  {:else}
    <ul class="space-y-1 text-sm">
      {#each [...inUse, ...spares, ...retiring] as e (e.id)}
        {@const t = tested(e)}
        <li class="flex flex-wrap items-center gap-x-2">
          <span class="font-mono text-xs">{address(e)}</span>
          <span class="text-muted-foreground">
            {WORD[e.publication]}, {healthLabel(e.health).toLowerCase()}{#if t}, {t}{/if}
          </span>
          {#if t && t !== 'tested'}
            <Button variant="link" size="sm" class="h-auto p-0" onclick={() => onTest(e.id)}>
              Test it
            </Button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>
