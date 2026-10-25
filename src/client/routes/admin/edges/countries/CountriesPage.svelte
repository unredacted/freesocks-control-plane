<script lang="ts">
  /**
   * Admin -> Edges -> Countries (`/admin/edges/countries`): every country on the
   * censored-country list with how many published addresses and server names
   * work or are blocked there, nodes at risk, and how many members there hold
   * a blocked address. Each row opens the country (CountryPage).
   *
   * All wording lives in ./words.ts (pure, unit-tested).
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Card, CardContent } from '@client/components/ui/card';
  import Link from '@client/components/Link.svelte';
  import { countryViewSummaryQuery } from '@client/lib/edgesApi';
  import SectionHeader from '../components/SectionHeader.svelte';
  import StatusDot from '../simple/StatusDot.svelte';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';
  import { countryDot, countryLabel, percent, switchNotes, totalsLine } from './words';

  const summary = countryViewSummaryQuery();
  let now = $derived(summary.data?.generatedAt ?? Date.now());
</script>

<SectionHeader
  title="Countries"
  description="For each censored country: which of your addresses and server names work there, why FCP thinks so, and what a member there is handed today."
/>

{#if summary.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if summary.isError}
  <p class="text-destructive text-sm">The countries could not be loaded. Try again shortly.</p>
{:else if summary.data}
  {@const notes = switchNotes(summary.data.switches, null)}
  {#if notes.length > 0}
    <Card class="mb-4">
      <CardContent class="text-muted-foreground space-y-1 py-4 text-sm">
        {#each notes as n (n)}<p>{n}</p>{/each}
        <p>
          <Link href={edgesPaths.settings()} class="underline underline-offset-2">
            Edges settings
          </Link>
          ·
          <Link href="/admin/settings" class="underline underline-offset-2">
            Censored countries
          </Link>
        </p>
      </CardContent>
    </Card>
  {/if}

  {#if summary.data.countries.length === 0}
    <Card>
      <CardContent class="text-muted-foreground py-8 text-center text-sm">
        No country is on the censored-country list.
        <Link href="/admin/settings" class="underline underline-offset-2">Add one in Settings.</Link
        >
      </CardContent>
    </Card>
  {:else}
    <ul class="space-y-3" aria-label="Countries">
      {#each summary.data.countries as c (c.country)}
        <li>
          <Link
            href={edgesPaths.country(c.country)}
            class="hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 items-center gap-3 rounded-lg border px-4 py-3 outline-none focus-visible:ring-3"
          >
            <StatusDot dot={countryDot(c.totals)} />
            <span class="min-w-0 flex-1">
              <span class="block font-medium">{countryLabel(c.country)}</span>
              <span class="text-muted-foreground block text-sm">{totalsLine(c.totals)}</span>
              <span class="text-muted-foreground block text-sm">
                {#if c.totals.originsAtRisk > 0}
                  <span class="text-destructive font-medium">
                    {c.totals.originsAtRisk === 1
                      ? 'One node has no working address there.'
                      : `${c.totals.originsAtRisk} nodes have no working address there.`}
                  </span>
                {/if}
                {#if c.worstOnBlocked !== null && c.worstOnBlocked > 0}
                  Up to {percent(c.worstOnBlocked)} of members there hold a blocked address.
                {/if}
                {c.listed.nameChecksRun
                  ? 'Names are checked from inside.'
                  : 'Names are not checked from inside.'}
                {c.totals.lastEvidenceAt
                  ? `Newest evidence ${relativeTime(c.totals.lastEvidenceAt, now)}.`
                  : 'No evidence yet.'}
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
{/if}
