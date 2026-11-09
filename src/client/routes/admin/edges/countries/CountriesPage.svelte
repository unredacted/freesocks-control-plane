<script lang="ts">
  /**
   * Admin -> Servers -> Countries (`/admin/servers/countries`): every country on
   * the censored-country list with how many published addresses and SNIs work
   * or are blocked there, nodes at risk, how many members there hold a blocked
   * address, and when the outside probes from there fall short (not asked, or
   * a source gone quiet and why). Each row opens the country (CountryPage).
   *
   * Below the rows: the list itself (CensoredCountriesCard, "Add a country"),
   * and the Delivery card ("Where members connect from", CountryDeliveryCard).
   * Both moved here from Admin -> Settings, which keeps link cards.
   *
   * All wording lives in ./words.ts (pure, unit-tested).
   */
  import { tick } from 'svelte';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent } from '@client/components/ui/card';
  import Link from '@client/components/Link.svelte';
  import { countryViewSummaryQuery } from '@client/lib/edgesApi';
  import SectionHeader from '../components/SectionHeader.svelte';
  import StatusDot from '../simple/StatusDot.svelte';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';
  import CensoredCountriesCard from './CensoredCountriesCard.svelte';
  import CountriesNav from './CountriesNav.svelte';
  import CountryDeliveryCard from './CountryDeliveryCard.svelte';
  import { CENSORED_LIST_USES } from './censored';
  import {
    countryDot,
    countryLabel,
    coverageNote,
    percent,
    switchNotes,
    totalsLine,
  } from './words';

  const summary = countryViewSummaryQuery();
  let now = $derived(summary.data?.generatedAt ?? Date.now());

  const EDITOR_ID = 'censored-countries';
  const DELIVERY_ID = 'country-delivery';
  /** Scroll to a card below and put the keyboard on its first control. */
  async function goTo(id: string) {
    await tick();
    const el = document.getElementById(id);
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    el.querySelector<HTMLElement>('input, button, select, textarea')?.focus({
      preventScroll: true,
    });
  }
</script>

<CountriesNav current="countries" />

<SectionHeader
  title="Countries"
  description="For each censored country: which addresses and SNIs work there, why FCP thinks so, and what members there are handed today."
>
  {#snippet actions()}
    <Button size="sm" variant="outline" onclick={() => goTo(DELIVERY_ID)}>Delivery</Button>
    <Button size="sm" onclick={() => goTo(EDITOR_ID)}>Add a country</Button>
  {/snippet}
</SectionHeader>

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
          <Link href={edgesPaths.settings()} class="underline underline-offset-2">Settings</Link>
        </p>
      </CardContent>
    </Card>
  {/if}

  {#if summary.data.countries.length === 0}
    <Card>
      <CardContent class="text-muted-foreground py-8 text-center text-sm">
        No country is on the censored-country list. Add one below.
      </CardContent>
    </Card>
  {:else}
    <ul class="space-y-3" aria-label="Countries">
      {#each summary.data.countries as c (c.country)}
        {@const probesNote = coverageNote(
          c.probes,
          summary.data.sources,
          summary.data.switches.probes,
          now,
        )}
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
                {#if c.meantFor.blocked > 0}
                  <span class="text-destructive font-medium">
                    {c.meantFor.blocked === 1
                      ? 'A location set for it is blocked there.'
                      : `${c.meantFor.blocked} locations set for it are blocked there.`}
                  </span>
                {:else if c.meantFor.locations > 0}
                  {c.meantFor.locations === 1
                    ? 'One location is set for it.'
                    : `${c.meantFor.locations} locations are set for it.`}
                {/if}
                {c.listed.nameChecksRun
                  ? 'SNIs are checked from inside.'
                  : 'SNIs are not checked from inside.'}
                {c.totals.lastEvidenceAt
                  ? `Newest evidence ${relativeTime(c.totals.lastEvidenceAt, now)}.`
                  : 'No evidence yet.'}
              </span>
              {#if probesNote}
                <span class="block text-sm text-amber-700 dark:text-amber-300">{probesNote}</span>
              {/if}
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

<div class="mt-8 space-y-6">
  <p class="text-muted-foreground text-sm">{CENSORED_LIST_USES}</p>
  <CensoredCountriesCard id={EDITOR_ID} />
  <CountryDeliveryCard id={DELIVERY_ID} />
</div>
