<script lang="ts">
  /**
   * An account's "Countries": each location against each checked country
   * (docs/edges.md "Checks from each country"). A cell is the location's grade
   * there (Works, Blocked, Some addresses blocked, Not checked yet) with its
   * age, the operator's mark on the location and a conflict when the mark
   * disagrees with the checks. "Mark for a country" per location writes a group
   * mark (Works there, Blocked there, Use the checks): it counts for every
   * address in the location. A CDN account has one row: a front has no place.
   *
   * Props:
   *   account: EdgeProviderAccountAdmin
   */
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as Table from '@client/components/ui/table';
  import Link from '@client/components/Link.svelte';
  import { countryName } from '@client/lib/countries';
  import { EDGE_PROVIDER_META } from '@client/lib/edgeProviderMeta';
  import { edgeCountriesQuery } from '@client/lib/edgesApi';
  import type { EdgeProviderAccountAdmin } from '@shared/contracts/edges';
  import AdminListState from '../../AdminListState.svelte';
  import CountryMarkDialog from '../components/CountryMarkDialog.svelte';
  import { locationGrades, locationGroupKey } from '../lib/countryChecks';
  import { edgesPaths } from '../lib/routes';
  import { gradeWords } from '../lib/statusWords';

  interface Props {
    account: EdgeProviderAccountAdmin;
  }
  let { account }: Props = $props();

  const countries = edgeCountriesQuery();
  const data = $derived(countries.data ?? null);
  const layer = $derived(EDGE_PROVIDER_META[account.provider].layer);

  let now = $state(Date.now());
  $effect(() => {
    const t = setInterval(() => (now = Date.now()), 30_000);
    return () => clearInterval(t);
  });

  // One row per location; a CDN front has no place, so its account is one row.
  const rows = $derived.by(() => {
    if (layer === 'l7') {
      const key = locationGroupKey({ provider: account.provider, placeKey: null, layer });
      return [{ id: 'global', label: 'Everywhere (CDN front)', enabled: true, key }];
    }
    return account.locations.map((l) => ({
      id: l.id,
      label: l.label,
      enabled: l.enabled,
      key: locationGroupKey({ provider: account.provider, placeKey: l.placeKey, layer }),
    }));
  });
  const cells = $derived(
    rows.map((r) => ({
      row: r,
      cells: locationGrades(data, r.key).map((c) => ({ ...c, words: gradeWords(c, now) })),
    })),
  );
  const conflicts = $derived(cells.flatMap((r) => r.cells).filter((c) => c.conflict).length);

  let marking = $state<{ key: string; label: string } | null>(null);
  let markOpen = $state(false);
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Countries</CardTitle>
    <CardDescription>
      How addresses in each location fare from the countries you check. Censors block ranges, so
      addresses of one location tend to share their fate. A mark counts for every address in the
      location and wins over the checks.
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-3">
    {#if countries.isPending}
      <Skeleton class="h-24 w-full" />
    {:else if countries.isError}
      <AdminListState error={countries.error} onRetry={() => void countries.refetch()} />
    {:else if !data || data.countries.length === 0}
      <p class="text-muted-foreground text-sm">
        No country is checked yet. Choose them in the
        <Link href={edgesPaths.settings({ section: 'probes' })} class="underline"
          >probe settings</Link
        >.
      </p>
    {:else if rows.length === 0}
      <p class="text-muted-foreground text-sm">This account has no location yet.</p>
    {:else}
      {#if !data.enabled}
        <p class="text-muted-foreground text-sm">
          Checks from each country are switched off, so nothing new is recorded. Turn them on in the
          <Link href={edgesPaths.settings({ section: 'probes' })} class="underline"
            >probe settings</Link
          >.
        </p>
      {/if}
      {#if conflicts > 0}
        <p class="text-sm text-amber-700 dark:text-amber-400" role="status">
          {conflicts === 1
            ? 'One of your marks disagrees with the checks.'
            : `${conflicts} of your marks disagree with the checks.`} Look at the cells below.
        </p>
      {/if}
      <Table.Root class="text-xs">
        <Table.Header>
          <Table.Row>
            <Table.Head>Location</Table.Head>
            {#each data.countries as c (c)}
              <Table.Head title={c}>{countryName(c, 'en')}</Table.Head>
            {/each}
            <Table.Head><span class="sr-only">Actions</span></Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each cells as r (r.row.id)}
            <Table.Row>
              <Table.Cell class="min-w-28 align-top font-medium whitespace-normal">
                {r.row.label}
                {#if !r.row.enabled}
                  <span class="text-muted-foreground block font-normal">Switched off</span>
                {/if}
              </Table.Cell>
              {#each r.cells as c (c.country)}
                <Table.Cell class="align-top">
                  <Badge variant={c.words.tone}>{c.words.label}</Badge>
                  {#if c.words.age}
                    <span class="text-muted-foreground block">{c.words.age}</span>
                  {/if}
                  {#if c.words.mark}<span class="block">{c.words.mark}</span>{/if}
                  {#if c.words.conflict}
                    <span class="block text-amber-700 dark:text-amber-400">{c.words.conflict}</span>
                  {/if}
                </Table.Cell>
              {/each}
              <Table.Cell class="text-end align-top">
                {#if r.row.key}
                  {@const key = r.row.key}
                  <Button
                    variant="outline"
                    size="sm"
                    class="h-11 sm:h-8"
                    onclick={() => {
                      marking = { key, label: r.row.label };
                      markOpen = true;
                    }}
                  >
                    Mark for a country
                  </Button>
                {/if}
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    {/if}
  </CardContent>
</Card>

{#if marking && data}
  <CountryMarkDialog
    bind:open={markOpen}
    scope="group"
    ref={marking.key}
    name={marking.label}
    countries={data.countries}
    marks={data.marks.filter((m) => m.scope === 'group' && m.groupKey === marking?.key)}
  />
{/if}
