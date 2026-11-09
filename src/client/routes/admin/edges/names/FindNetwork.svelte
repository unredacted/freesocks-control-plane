<script lang="ts">
  /**
   * SNIs found on one network (`/admin/servers/snis/find/:slug`; docs/edges.md
   * "Finding names"): the sites grouped by the address they live on (each a
   * possible cover site with the SNIs it serves), and every found SNI. "Make
   * an SNI list with this cover site" opens the one "Add an SNI list" dialog
   * (AddSniListDialog), prefilled: that cover site, port 443, HTTP/2 only, this
   * network. The list starts with the cover site only; its SNIs are added from
   * the list below, through the list's normal path.
   *
   * All wording lives in ./lib/huntWords.ts (pure, unit-tested).
   */
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import { familiesQuery, huntNetworkQuery } from '@client/lib/sniApi';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import AddSniListDialog from './AddSniListDialog.svelte';
  import HuntTable from './HuntTable.svelte';
  import type { AddListFrom } from './lib/addList';
  import { ctWords } from './lib/huntWords';
  import { sniErrorWords } from './lib/words';

  let { slug }: { slug: string } = $props();
  const view = huntNetworkQuery(() => slug);
  // Every family (the network list names only the first ones), those on this network.
  const families = familiesQuery();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);
  let onNetwork = $derived(
    (families.data?.families ?? [])
      .filter((f) => f.network?.slug === slug)
      .map((f) => ({ slug: f.slug, label: f.label })),
  );

  // The first addresses, then every one on asking (none is ever left out).
  const GROUPS_FIRST = 20;
  let allGroups = $state(false);

  // --- an SNI list from a group: the one dialog, prefilled ---------------------------------------
  let open = $state(false);
  let from = $state<AddListFrom>({ kind: 'site' });
  function startFamily(best: string) {
    from = {
      kind: 'site',
      prefill: { coverSite: best, port: 443, requireH2: true, network: slug },
    };
    open = true;
  }
</script>

<p class="mb-2 text-sm">
  <Link href={edgesPaths.findNames()} class="text-muted-foreground underline underline-offset-4">
    Find more
  </Link>
</p>

{#if view.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if view.isError}
  <p class="text-destructive text-sm">{sniErrorWords(codeOf(view.error))}</p>
{:else if view.data}
  {@const v = view.data}
  <SectionHeader
    title={`SNIs on ${v.scope.label}`}
    description="Real sites whose every address is on this network. Each is checked as an SNI list would check it, and checked again when added to a list."
  />

  <Card>
    <CardHeader>
      <CardTitle class="text-base">Possible cover sites, by address</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      <p class="text-muted-foreground">
        SNIs on one address can share a cover site. Make an SNI list with one of them as its cover
        site, then add the others.
      </p>
      {#if v.groups.length === 0}
        <p class="text-muted-foreground">No site of this network has been found and checked yet.</p>
      {:else}
        <ul class="divide-y rounded-md border" aria-label="Sites by address">
          {#each allGroups ? v.groups : v.groups.slice(0, GROUPS_FIRST) as g (g.address)}
            <li class="flex flex-wrap items-center justify-between gap-3 p-3">
              <div class="min-w-0 flex-1">
                <p class="font-mono break-all">{g.address}</p>
                <p class="text-muted-foreground">
                  {g.passing} of {g.names}
                  {g.names === 1 ? 'SNI' : 'SNIs'} usable, such as
                  <span class="font-mono">{g.best}</span>.
                </p>
              </div>
              <Button
                size="sm"
                variant="outline"
                class="h-11 sm:h-8"
                disabled={g.passing === 0}
                onclick={() => startFamily(g.best)}
              >
                Make an SNI list with this cover site
              </Button>
            </li>
          {/each}
        </ul>
        {#if v.groups.length > GROUPS_FIRST}
          <Button variant="outline" size="sm" onclick={() => (allGroups = !allGroups)}>
            {allGroups ? `Show the first ${GROUPS_FIRST}` : `Show all ${v.groups.length} addresses`}
          </Button>
        {/if}
      {/if}
      {#if v.families.length > 0}
        <div class="space-y-1">
          <p class="font-medium">Found for the SNI lists on this network</p>
          <p class="text-muted-foreground">
            Each was checked against its list's cover site and is shown on that list's page.
          </p>
          <ul>
            {#each v.families as f (f.slug)}
              <li>
                <Link href={edgesPaths.family(f.slug)} class="underline underline-offset-4">
                  {f.label}
                </Link>: {f.candidates.total} found, {f.candidates.ready} usable.
              </li>
            {/each}
          </ul>
        </div>
      {/if}
      {#if v.ct.length > 0}
        <div class="space-y-1">
          <p class="font-medium">Certificate logs</p>
          <ul class="text-muted-foreground">
            {#each v.ct as r (r.domain)}
              <li>{ctWords(r)}</li>
            {/each}
          </ul>
        </div>
      {/if}
    </CardContent>
  </Card>

  <Card class="mt-6">
    <CardHeader>
      <CardTitle class="text-base">SNIs</CardTitle>
    </CardHeader>
    <CardContent class="text-sm">
      {#if onNetwork.length === 0}
        <p class="text-muted-foreground mb-3">
          No SNI list is on this network yet. Make one above to add SNIs to it.
        </p>
      {/if}
      <HuntTable kind="network" {slug} families={onNetwork} />
    </CardContent>
  </Card>
{/if}

<AddSniListDialog
  bind:open
  {from}
  onAdded={() =>
    toast.success('SNI list made. Add its SNIs from the list below. Each is checked first.')}
/>
