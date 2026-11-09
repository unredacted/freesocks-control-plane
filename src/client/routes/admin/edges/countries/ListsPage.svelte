<script lang="ts">
  /**
   * Admin -> Servers -> Countries -> Country lists (`/admin/servers/countries/lists`):
   * every community list FCP follows, what it holds, whether a version waits
   * for a person, and whether its source still confirms it. Each row opens
   * the list (ListPage). A lookup box at the bottom.
   *
   * All wording lives in ./listWords.ts (pure, unit-tested).
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { router } from '@client/stores/router.svelte';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent } from '@client/components/ui/card';
  import Link from '@client/components/Link.svelte';
  import { countryListsQuery } from '@client/lib/countryListsApi';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import ListDialog from './ListDialog.svelte';
  import ListLookup from './ListLookup.svelte';
  import { countryLabel } from './words';
  import { countsLine, freshnessLine, listBadge, REGIME_WORDS, sourceLine } from './listWords';

  const lists = countryListsQuery();
  let adding = $state(false);
  let now = $state(Date.now());
</script>

<SectionHeader
  title="Country lists"
  description="Community lists of hostnames and addresses that work, or are blocked, in a country. FCP keeps each change as a version and holds any that looks wrong for you. Lists are evidence only and never change what members get."
  back={{ href: edgesPaths.countries(), label: 'Countries' }}
>
  {#snippet actions()}
    <Button size="sm" onclick={() => (adding = true)}>Add a list</Button>
  {/snippet}
</SectionHeader>

{#if lists.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if lists.isError}
  <p class="text-destructive text-sm">The lists could not be loaded. Try again shortly.</p>
{:else if lists.data}
  {#if !lists.data.enabled}
    <Card class="mb-4">
      <CardContent class="text-muted-foreground py-4 text-sm">
        Country lists are off. Nothing is fetched or read automatically, but you can still add lists
        and read them by hand.
        <Link href={edgesPaths.settings({ section: 'lists' })} class="underline underline-offset-2">
          Turn them on in Settings.
        </Link>
      </CardContent>
    </Card>
  {/if}
  {#if lists.data.lists.length === 0}
    <Card>
      <CardContent class="text-muted-foreground py-8 text-center text-sm">
        No list yet. Add one by its address, or paste a copy.
      </CardContent>
    </Card>
  {:else}
    <ul class="space-y-3" aria-label="Country lists">
      {#each lists.data.lists as l (l.id)}
        {@const badge = listBadge(l)}
        <li>
          <Link
            href={edgesPaths.list(l.id)}
            class="hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 items-center gap-3 rounded-lg border px-4 py-3 outline-none focus-visible:ring-3"
          >
            <span class="min-w-0 flex-1">
              <span class="flex flex-wrap items-center gap-2">
                <span class="font-medium">{l.label}</span>
                <Badge variant={badge.tone}>{badge.label}</Badge>
              </span>
              <span class="text-muted-foreground block text-sm">
                {countryLabel(l.country)}, {REGIME_WORDS[l.regime].label.toLowerCase()}.
                {sourceLine(l)}
              </span>
              <span class="text-muted-foreground block text-sm">
                {l.active ? countsLine(l.active.counts) : ''}
                {freshnessLine(l, lists.data.staleDays, now)}
              </span>
            </span>
            <ChevronRight
              class="text-muted-foreground size-4 shrink-0 rtl:rotate-180"
              aria-hidden="true"
            />
          </Link>
        </li>
      {/each}
    </ul>
  {/if}
  <ListLookup />
  <ListDialog
    bind:open={adding}
    defaultFetchHours={lists.data.defaultFetchHours}
    onSaved={(id) => router.navigate(edgesPaths.list(id))}
  />
{/if}
