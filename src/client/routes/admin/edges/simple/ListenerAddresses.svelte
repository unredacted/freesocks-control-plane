<script lang="ts">
  /**
   * One transport's addresses on the node page: a reduced pool strip (one health
   * dot per address in use, a spare cell per spare) and a plain line per
   * address (In use / Spare, the provider's own check of the node, whether it
   * answers from outside, tested or not). A retiring address says
   * what that means and when it is deleted (drainWords.ts), with "Delete now"
   * ("Stop tracking" for an address FCP did not create) and "Keep as a spare"
   * when the caller can act on it.
   *
   * Under each address in use or spare: what it counts as from each checked
   * country and its "Countries" menu (EdgeCountryActions), when the caller
   * passes the checks; and, where the deployment has FCP's own client check,
   * what its newest check found and "Check with FCP's client" (real sing-box and
   * Xray sessions through the address, docs/edges.md "FCP's own client check").
   *
   * Props: listener; edges (every non-destroyed edge of the origin); onTest(edgeId);
   *        publishable? (the spare the server says can be put in use now, or null)
   *        with onPublish() (the caller confirms and publishes it)
   *        onRetiring?(edge, 'delete' | 'keep') (the caller confirms; absent = no actions)
   *        countries? (the checks from each country, `edgeCountriesQuery`; absent = not shown)
   */
  import type {
    EdgeAdmin,
    EdgeCountriesResponse,
    RelayListenerAdmin,
  } from '@shared/contracts/edges';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { clientCheckEdge, clientCheckStatusQuery, edgeKeys } from '@client/lib/edgesApi';
  import {
    OUTSIDE_REACH_LABELS,
    PLAIN_ATTENTION_ACTION_LABELS,
    healthLabel,
    outsideReachOf,
  } from '@client/lib/edgeCodes';
  import EdgeCountryActions from '../components/EdgeCountryActions.svelte';
  import PoolStrip from '../components/PoolStrip.svelte';
  import type { PoolEntry } from '../lib/types';
  import { endNowWords, retiringWords } from './drainWords';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { clientCheckLine, clientCheckToast } from './clientCheckWords';

  interface Props {
    listener: RelayListenerAdmin;
    edges: EdgeAdmin[];
    onTest: (edgeId: string) => void;
    publishable?: string | null;
    onPublish?: () => void;
    onRetiring?: (edge: EdgeAdmin, action: 'delete' | 'keep') => void;
    countries?: EdgeCountriesResponse | null;
  }
  let {
    listener,
    edges,
    onTest,
    publishable = null,
    onPublish,
    onRetiring,
    countries = null,
  }: Props = $props();

  const qc = useQueryClient();
  const clientCheckStatus = clientCheckStatusQuery();
  const canClientCheck = $derived(clientCheckStatus.data?.configured === true);
  let checking = $state<string | null>(null);
  async function clientCheck(e: EdgeAdmin) {
    checking = e.id;
    try {
      const t = clientCheckToast(await clientCheckEdge(e.id));
      toast[t.tone](t.title, { description: t.body });
      await qc.invalidateQueries({ queryKey: edgeKeys.all });
    } catch (err) {
      toast.error(edgeErrorMessage(err));
    } finally {
      checking = null;
    }
  }

  const mine = $derived(edges.filter((e) => e.listenerId === listener.id));
  const inUse = $derived(mine.filter((e) => e.publication === 'published'));
  const spares = $derived(
    mine.filter((e) => e.publication === 'unpublished' && e.status === 'active'),
  );
  // Draining, or already being deleted at the provider (Delete now, or the drain ran out).
  const retiring = $derived(
    mine.filter((e) => e.publication === 'draining' || e.status === 'destroying'),
  );
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
  // The provider's check is not the members' view: whether it answers from outside, apart.
  const reachWord = (e: EdgeAdmin) =>
    OUTSIDE_REACH_LABELS[outsideReachOf(e.reachability)].toLowerCase();
  const tested = (e: EdgeAdmin): string | null => {
    if (!e.verification.required || retiring.includes(e)) return null;
    // A second address the provider reported later: served only once tested.
    if (e.verification.current && e.verification.learnedAddress)
      return `tested; new address ${e.verification.learnedAddress} not served until tested`;
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
    <ul class={['text-sm', countries ? 'space-y-3' : 'space-y-1']}>
      {#each [...inUse, ...spares, ...retiring] as e (e.id)}
        {@const t = tested(e)}
        {@const r = retiring.includes(e) ? retiringWords(e) : null}
        <li>
          <div class="flex flex-wrap items-center gap-x-2">
            <span class="font-mono text-xs">{address(e)}</span>
            {#if r}
              <span class="text-muted-foreground">{r.word}. {r.line}</span>
              {#if onRetiring && r.canDelete}
                <Button
                  variant="link"
                  size="sm"
                  class="text-destructive h-auto min-h-11 p-0 sm:min-h-0"
                  onclick={() => onRetiring(e, 'delete')}
                >
                  {endNowWords(e, address(e)).label}
                </Button>
              {/if}
              {#if onRetiring && r.canKeep}
                <Button
                  variant="link"
                  size="sm"
                  class="h-auto min-h-11 p-0 sm:min-h-0"
                  onclick={() => onRetiring(e, 'keep')}
                >
                  Keep as a spare
                </Button>
              {/if}
            {:else}
              <span class="text-muted-foreground">
                {WORD[e.publication]}, {healthLabel(e.health).toLowerCase()}, {reachWord(e)}{#if t}, {t}{/if}
              </span>
            {/if}
            {#if t && t !== 'tested'}
              <Button
                variant="link"
                size="sm"
                class="h-auto min-h-11 p-0 sm:min-h-0"
                onclick={() => onTest(e.id)}
              >
                Test it
              </Button>
            {/if}
            {#if canClientCheck && !r && e.layer !== 'l7'}
              <Button
                variant="link"
                size="sm"
                class="h-auto min-h-11 p-0 sm:min-h-0"
                disabled={checking !== null}
                onclick={() => void clientCheck(e)}
              >
                {checking === e.id ? 'Checking...' : "Check with FCP's client"}
              </Button>
            {/if}
            {#if onPublish && e.id === publishable}
              <Button
                variant="link"
                size="sm"
                class="h-auto min-h-11 p-0 sm:min-h-0"
                onclick={onPublish}
              >
                {PLAIN_ATTENTION_ACTION_LABELS.publish}
              </Button>
            {/if}
          </div>
          {#if !r && clientCheckLine(e.clientCheck)}
            <p class="text-muted-foreground text-xs">{clientCheckLine(e.clientCheck)}</p>
          {/if}
          {#if countries && !r}
            <EdgeCountryActions edgeId={e.id} name={address(e)} data={countries} />
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>
