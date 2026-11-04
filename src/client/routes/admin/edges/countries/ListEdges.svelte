<script lang="ts">
  /**
   * An allowlist's edge-address check (docs/edges.md "Edge addresses against
   * allowlists"): the switch, why checks wait when they do, and how the active
   * edges' addresses stand against the version in use. An address that leaves
   * the list raises an attention item; its edge's sheet has "Seen it".
   *
   * Props:
   *   list: CountryListView    an allowlist
   *   switchOn: boolean        `edge.lists.enabled`
   *   counts: CountryListDetail['edges']
   * All wording lives in ./listWords.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Card, CardContent } from '@client/components/ui/card';
  import { Switch } from '@client/components/ui/switch';
  import { ApiCallError } from '@client/lib/api';
  import { invalidateCountryLists, updateCountryList } from '@client/lib/countryListsApi';
  import type { CountryListDetail, CountryListView } from '@shared/contracts/countryLists';
  import { edgeCountsLine, listErrorWords, watchLine, watchWaitsLine } from './listWords';

  let {
    list,
    switchOn,
    counts,
  }: { list: CountryListView; switchOn: boolean; counts: CountryListDetail['edges'] } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  let busy = $state(false);

  async function setWatch(on: boolean) {
    busy = true;
    try {
      await updateCountryList(list.id, { watchEdges: on });
      toast.success(on ? 'Edge addresses are checked against it now.' : 'No longer checked.');
    } catch (e) {
      toast.error(listErrorWords(e instanceof ApiCallError ? e.payload.error.code : null));
    } finally {
      busy = false;
      invalidateCountryLists(qc);
    }
  }

  const waits = $derived(list.watchEdges ? watchWaitsLine(list, switchOn) : null);
</script>

<Card class="mt-4">
  <CardContent class="space-y-2 py-5 text-sm">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="min-w-0 flex-1">
        <h2 class="text-base font-medium">
          <label for={`${uid}-watch`}>Check edge addresses against it</label>
        </h2>
        <p class="text-muted-foreground">{watchLine(list.watchEdges)}</p>
      </div>
      <Switch
        id={`${uid}-watch`}
        checked={list.watchEdges}
        disabled={busy}
        onCheckedChange={(on) => void setWatch(on)}
      />
    </div>
    {#if waits}
      <p class="text-amber-700 dark:text-amber-400">{waits}</p>
    {/if}
    {#if list.watchEdges && counts}
      <p>{edgeCountsLine(counts)}</p>
    {/if}
    <p class="text-muted-foreground">
      Where a country lets through only listed addresses and names, both must be on it. The
      country's page says how many of each transport's server names the lists hold.
    </p>
  </CardContent>
</Card>
