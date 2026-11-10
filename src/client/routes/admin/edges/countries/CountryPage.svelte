<script lang="ts">
  /**
   * Admin -> Servers -> Countries -> one country
   * (`/admin/servers/countries/<CC>[?section=]`): "Can members here connect?"
   * One section at a time, picked by the section bar (./sections.ts):
   *
   *   Summary                      the totals, how many keys are set to it (counts only,
   *                                ./keyWords.ts), what is switched off, and one line per section
   *   Addresses for this country   locations set for it, then every origin's transports and
   *                                addresses: what they count as here, why, and what members
   *                                here are handed (CountryAddresses; holds the slot for the
   *                                per-country edges design)
   *   SNIs                         the SNIs of each REALITY transport from here (CountrySnis)
   *   Lists                        the country lists FCP follows for it (CountryListsCard)
   *   Probes                       the Probes tab's matrix with only this country (CountryProbes)
   *   Checks from here             its two switches on the censored-country list (CountryChecks)
   *   Exit                         where new keys of members who chose it go (CountryExit)
   *
   * "Mark an address for this country" (header) picks an address, then opens the
   * mark dialog (CountryMarkAddress).
   *
   * Props: code: string (ISO 3166-1 alpha-2, upper case)
   * All wording lives in ./words.ts and ./sections.ts (pure, unit-tested).
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Card, CardContent } from '@client/components/ui/card';
  import Link from '@client/components/Link.svelte';
  import { countryViewQuery } from '@client/lib/edgesApi';
  import { searchParam } from '@client/lib/urlState.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';
  import CountryAddresses from './CountryAddresses.svelte';
  import CountryChecks from './CountryChecks.svelte';
  import CountryExit from './CountryExit.svelte';
  import CountryListsCard from './CountryListsCard.svelte';
  import CountryMarkAddress from './CountryMarkAddress.svelte';
  import CountryProbes from './CountryProbes.svelte';
  import CountrySectionBar from './CountrySectionBar.svelte';
  import CountrySnis from './CountrySnis.svelte';
  import {
    COUNTRY_SECTIONS,
    addressesDigest,
    checksDigest,
    countrySectionOf,
    exitDigest,
    snisDigest,
    type CountrySection,
  } from './sections';
  import { countryLabel, coverageLines, coverageNote, switchNotes, totalsLine } from './words';
  import { KEYS_SCOPE, keysLine } from './keyWords';

  interface Props {
    code: string;
  }
  let { code }: Props = $props();

  const view = countryViewQuery(() => code);
  let now = $derived(view.data?.generatedAt ?? Date.now());
  const sectionParam = searchParam('section');
  const section = $derived(countrySectionOf(sectionParam.value));
  const labelOf = (id: CountrySection) => COUNTRY_SECTIONS.find((s) => s.id === id)?.label ?? id;
</script>

<SectionHeader
  title={countryLabel(code)}
  back={{ href: edgesPaths.countries(), label: 'All countries' }}
  description="What works from here, why FCP thinks so, and what a member here is handed today."
>
  {#snippet actions()}
    {#if view.data}
      <CountryMarkAddress {code} origins={view.data.origins} listed={!!view.data.listed} />
    {/if}
  {/snippet}
</SectionHeader>

<CountrySectionBar {code} current={section} />

{#if view.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if view.isError}
  <p class="text-destructive text-sm">This country could not be loaded. Try again shortly.</p>
{:else if view.data}
  {@const v = view.data}
  {#if section === 'summary'}
    {@const notes = [
      ...(v.listed
        ? []
        : ['This country is not on the censored-country list, so nothing is checked from here.']),
      ...switchNotes(v.switches, v.listed),
    ]}
    {@const probesNote = coverageNote(v.probes, v.sources, v.switches.probes, now)}
    {@const digests = [
      { id: 'addresses' as const, line: addressesDigest(v.totals, v.meantFor) },
      { id: 'snis' as const, line: snisDigest(v.totals) },
      { id: 'lists' as const, line: 'The country lists FCP follows for it.' },
      {
        id: 'probes' as const,
        line:
          probesNote ??
          (v.switches.probes
            ? (coverageLines(v.probes, v.sources, true, now)[0] ?? 'Outside probes from here.')
            : 'Probes are off.'),
      },
      { id: 'checks' as const, line: checksDigest(v.listed) },
      {
        id: 'exit' as const,
        line: exitDigest(
          v.exits.map((e) => e.label),
          v.switches.steering,
        ),
      },
    ]}
    <Card class="mb-6">
      <CardContent class="space-y-1 py-4 text-sm">
        <p class="font-medium">{totalsLine(v.totals)}</p>
        {#if v.totals.originsAtRisk > 0}
          <p class="text-destructive">
            {v.totals.originsAtRisk === 1
              ? 'One node has no working published address here.'
              : `${v.totals.originsAtRisk} nodes have no working published address here.`}
          </p>
        {/if}
        <p class="text-muted-foreground">
          {v.totals.lastEvidenceAt
            ? `Newest evidence ${relativeTime(v.totals.lastEvidenceAt, now)}.`
            : 'No evidence from here yet.'}
          {v.controls.length > 0 ? `Control countries: ${v.controls.join(', ')}.` : ''}
        </p>
        {#each notes as n (n)}<p class="text-muted-foreground">{n}</p>{/each}
      </CardContent>
    </Card>

    <Card class="mb-6">
      <CardContent class="space-y-1 py-4 text-sm" aria-label="Keys set to this country">
        <p class="font-medium tabular-nums">
          {keysLine(v.keys, v.keys.counted, 'this country') ??
            'Keys by country are not counted yet. The first count runs a few minutes after an update.'}
        </p>
        <p class="text-muted-foreground">{KEYS_SCOPE}</p>
      </CardContent>
    </Card>

    <ul class="grid gap-3 sm:grid-cols-2" aria-label="Sections">
      {#each digests as d (d.id)}
        <li>
          <Link
            href={edgesPaths.country(code, { section: d.id })}
            class="hover:bg-accent/40 focus-visible:ring-ring/50 flex h-full items-center gap-3 rounded-lg border px-4 py-3 outline-none focus-visible:ring-3"
          >
            <span class="min-w-0 flex-1">
              <span class="block font-medium">{labelOf(d.id)}</span>
              <span class="text-muted-foreground block text-sm">{d.line}</span>
            </span>
            <ChevronRight
              class="text-muted-foreground size-4 shrink-0 rtl:rotate-180"
              aria-hidden="true"
            />
          </Link>
        </li>
      {/each}
    </ul>
  {:else if section === 'addresses'}
    <!-- The per-country edges card goes in CountryAddresses' `perCountry` slot. -->
    <CountryAddresses {code} view={v} />
  {:else if section === 'snis'}
    <CountrySnis view={v} />
  {:else if section === 'lists'}
    <CountryListsCard {code} />
  {:else if section === 'probes'}
    <CountryProbes {code} view={v} />
  {:else if section === 'checks'}
    <CountryChecks {code} view={v} />
  {:else if section === 'exit'}
    <CountryExit {code} view={v} />
  {/if}
{/if}
