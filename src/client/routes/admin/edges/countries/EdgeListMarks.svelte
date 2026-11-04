<script lang="ts">
  /**
   * On an edge's sheet: what every watched allowlist says about its addresses
   * (docs/edges.md "Edge addresses against allowlists"), with "Seen it" on an
   * address that left a list (it clears the attention item until the address
   * is listed again and leaves again; it names the departure it saw, so a
   * stale sheet cannot clear a newer one). Renders nothing when no list watches.
   *
   * Props: edgeId: string
   * All wording lives in ./listWords.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import {
    countryListKeys,
    edgeListMarksQuery,
    invalidateCountryLists,
    markEdgeAddressSeen,
  } from '@client/lib/countryListsApi';
  import { invalidateCountries, invalidateOverview } from '@client/lib/edgesApi';
  import { edgesPaths } from '../lib/routes';
  import { countryLabel } from './words';
  import { listErrorWords, markRowWords, marksWaitLine } from './listWords';

  let { edgeId }: { edgeId: string } = $props();
  const qc = useQueryClient();
  const marks = edgeListMarksQuery(() => edgeId);
  let busy = $state<string | null>(null);
  const now = $derived(marks.dataUpdatedAt || Date.now());

  async function seen(listId: string, markId: string, leftAt: number) {
    busy = markId;
    try {
      await markEdgeAddressSeen(listId, markId, leftAt);
      toast.success('Noted. It asks again only if it is listed and leaves again.');
    } catch (e) {
      toast.error(listErrorWords(e instanceof ApiCallError ? e.payload.error.code : null));
    } finally {
      busy = null;
      void qc.invalidateQueries({ queryKey: countryListKeys.marks(edgeId) });
      invalidateCountryLists(qc);
      invalidateOverview(qc);
      invalidateCountries(qc);
    }
  }
</script>

{#if marks.data && marks.data.lists.some((l) => l.addresses.length > 0)}
  <section class="space-y-2">
    <h3 class="text-sm font-semibold">Lists of what works</h3>
    <ul class="space-y-2 text-sm">
      {#each marks.data.lists.filter((l) => l.addresses.length > 0) as l (l.listId)}
        {@const wait = marksWaitLine(l, marks.data.enabled)}
        <li class="space-y-1">
          <p>
            <Link
              href={edgesPaths.list(l.listId)}
              class="font-medium underline-offset-2 hover:underline"
            >
              {l.label}
            </Link>
            <span class="text-muted-foreground">{countryLabel(l.country)}</span>
          </p>
          {#if wait}<p class="text-muted-foreground text-xs">{wait}</p>{/if}
          <ul class="space-y-1">
            {#each l.addresses as a (a.family)}
              <li class="flex flex-wrap items-center justify-between gap-2">
                <span class={a.state === 'left' ? 'text-amber-700 dark:text-amber-400' : ''}>
                  <span class="font-mono break-all">{a.address}</span>
                  {markRowWords(a, now)}
                </span>
                {#if a.needsLook && a.markId && a.leftAt !== null}
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy !== null}
                    onclick={() => void seen(l.listId, a.markId!, a.leftAt!)}
                  >
                    Seen it
                  </Button>
                {/if}
              </li>
            {/each}
          </ul>
        </li>
      {/each}
    </ul>
  </section>
{/if}
