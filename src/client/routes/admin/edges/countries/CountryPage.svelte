<script lang="ts">
  /**
   * Admin -> Edges -> Countries -> one country (`/admin/edges/countries/<CC>`):
   * every enabled origin, each of its transports, and for each its addresses
   * and server names: what they count as from this country, why (a mark, the
   * checks with controls, the checks from inside, the probes, member reports)
   * and how old that is, plus what a member here is handed today (the
   * assignment itself over a sample of keys). Read only: marks and checks are
   * made on the node and name pages.
   *
   * Props: code: string (ISO 3166-1 alpha-2, upper case)
   * All wording lives in ./words.ts (pure, unit-tested).
   */
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Badge } from '@client/components/ui/badge';
  import Link from '@client/components/Link.svelte';
  import { countryViewQuery } from '@client/lib/edgesApi';
  import type { CountryViewAddress, CountryViewOrigin } from '@shared/contracts/edges';
  import SectionHeader from '../components/SectionHeader.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import ProtocolBadge from '../components/ProtocolBadge.svelte';
  import StatusDot from '../simple/StatusDot.svelte';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';
  import {
    STATE_WORDS,
    addressWhy,
    checksLine,
    countryLabel,
    handedWords,
    handshakeLine,
    markLine,
    gradeLine,
    nameWhy,
    percent,
    probesLine,
    reportsLine,
    realHostLine,
    addressRealHostLine,
    targetAddsLine,
    TARGET_ADDS_FLAG_WORDS,
    roundLine,
    switchNotes,
    totalsLine,
    untilLine,
    HANDED_SCOPE,
  } from './words';

  interface Props {
    code: string;
  }
  let { code }: Props = $props();

  const view = countryViewQuery(() => code);
  let now = $derived(view.data?.generatedAt ?? Date.now());

  function originHref(o: CountryViewOrigin): string {
    return o.kind === 'panel-node' ? edgesPaths.node(o.slug) : edgesPaths.relay(o.slug);
  }
  function addressHref(o: CountryViewOrigin, a: CountryViewAddress): string {
    return a.edgeId
      ? edgesPaths.relay(o.slug, { tab: 'edges', edge: a.edgeId })
      : edgesPaths.relay(o.slug);
  }
  function evidenceLines(a: CountryViewAddress): string[] {
    return [
      markLine(a, now),
      gradeLine(a, now),
      roundLine(a, now),
      handshakeLine(a, now),
      probesLine(a, now),
      addressRealHostLine(a, now),
    ].filter((x): x is string => !!x);
  }
  function handedLine(a: CountryViewAddress): string | null {
    const parts: string[] = [];
    if (a.handed.primary > 0) parts.push(`first address for ${percent(a.handed.primary)}`);
    if (a.handed.backup > 0) parts.push(`backup for ${percent(a.handed.backup)}`);
    return parts.length > 0 ? `Handed out here: ${parts.join(', ')} of members.` : null;
  }
</script>

<SectionHeader
  title={countryLabel(code)}
  back={{ href: edgesPaths.countries(), label: 'All countries' }}
  description="What works from here, why FCP thinks so, and what a member here is handed today."
/>

{#if view.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if view.isError}
  <p class="text-destructive text-sm">This country could not be loaded. Try again shortly.</p>
{:else if view.data}
  {@const v = view.data}
  {@const notes = [
    ...(v.listed
      ? []
      : ['This country is not on the censored-country list, so nothing is checked from here.']),
    ...switchNotes(v.switches, v.listed?.nameChecksRun ?? false),
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
      <p class="text-muted-foreground">{HANDED_SCOPE}</p>
    </CardContent>
  </Card>

  {#if v.origins.length === 0}
    <Card>
      <CardContent class="text-muted-foreground py-8 text-center text-sm">
        No origin is switched on.
      </CardContent>
    </Card>
  {/if}

  <div class="space-y-6">
    {#each v.origins as o (o.relayId)}
      <Card>
        <CardHeader>
          <CardTitle class="flex flex-wrap items-center gap-2 text-base">
            <Link href={originHref(o)} class="underline-offset-2 hover:underline">
              {o.label ?? o.nodeName ?? o.slug}
            </Link>
            {#if o.atRisk}
              <Badge variant="destructive">No working address here</Badge>
            {/if}
            {#if !o.enabled}
              <Badge variant="outline">Switched off</Badge>
            {/if}
          </CardTitle>
        </CardHeader>
        <CardContent class="space-y-6 text-sm">
          {#each o.listeners as l (l.listenerId)}
            <section aria-label={`Transport ${l.key}`} class="space-y-3">
              <div class="flex flex-wrap items-center gap-2">
                <ProtocolBadge
                  protocol={l.protocol}
                  streamTransport={l.streamTransport}
                  security={l.security}
                />
                <span class="text-muted-foreground">Transport {l.key}</span>
                {#if !l.usable}<Badge variant="outline">Not in use</Badge>{/if}
              </div>

              {#if targetAddsLine(l, now)}
                <div
                  class={l.targetAdds?.flagged
                    ? 'space-y-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2'
                    : 'text-muted-foreground'}
                >
                  <p>{targetAddsLine(l, now)}</p>
                  {#if l.targetAdds?.flagged}<p>{TARGET_ADDS_FLAG_WORDS}</p>{/if}
                </div>
              {/if}

              <div class="bg-muted/40 space-y-1 rounded-md px-3 py-2">
                <p class="font-medium">What a member here is handed</p>
                {#each handedWords(l.members) as line (line)}
                  <p class="text-muted-foreground">{line}</p>
                {/each}
              </div>

              <div>
                <h3 class="mb-2 font-medium">Addresses</h3>
                {#if l.addresses.length === 0}
                  <p class="text-muted-foreground">No address in use or spare.</p>
                {:else}
                  <ul class="divide-border divide-y rounded-md border" aria-label="Addresses">
                    {#each l.addresses as a (a.edgeId ?? a.address)}
                      {@const words = STATE_WORDS[a.state]}
                      <li class="space-y-1 px-3 py-2">
                        <div class="flex flex-wrap items-center gap-2">
                          <StatusDot dot={words.dot} />
                          <span class="font-medium">{words.label}</span>
                          <Link
                            href={addressHref(o, a)}
                            class="font-mono break-all underline-offset-2 hover:underline"
                          >
                            {a.address}
                          </Link>
                          {#if a.v6}
                            <span class="text-muted-foreground font-mono break-all">
                              {a.v6.address}
                              ({a.v6.state
                                ? STATE_WORDS[a.v6.state].label.toLowerCase()
                                : 'not known'})
                            </span>
                          {/if}
                          {#if a.publication}
                            <StatusBadge kind="publication" value={a.publication} />
                          {/if}
                          <span class="text-muted-foreground">
                            {[a.provider, a.location, a.layer === 'l7' ? 'CDN front' : null]
                              .filter(Boolean)
                              .join(' · ')}
                          </span>
                        </div>
                        <p class="text-muted-foreground">
                          {addressWhy(a)}
                          {untilLine(a.until, now) ?? ''}
                        </p>
                        {#if handedLine(a)}
                          <p class="text-muted-foreground">{handedLine(a)}</p>
                        {/if}
                        {#if evidenceLines(a).length > 0}
                          <details>
                            <summary class="text-muted-foreground cursor-pointer select-none">
                              Evidence
                            </summary>
                            <ul class="text-muted-foreground mt-1 list-disc space-y-0.5 ps-5">
                              {#each evidenceLines(a) as line (line)}<li>{line}</li>{/each}
                            </ul>
                          </details>
                        {/if}
                      </li>
                    {/each}
                  </ul>
                {/if}
              </div>

              {#if l.names.length > 0}
                <div>
                  <h3 class="mb-2 font-medium">Server names</h3>
                  <ul class="divide-border divide-y rounded-md border" aria-label="Server names">
                    {#each l.names as n (n.name)}
                      {@const words = STATE_WORDS[n.state]}
                      <li class="space-y-1 px-3 py-2">
                        <div class="flex flex-wrap items-center gap-2">
                          <StatusDot dot={words.dot} />
                          <span class="font-medium">{words.label}</span>
                          <span class="font-mono break-all">{n.name}</span>
                          {#if n.family}
                            <Link
                              href={edgesPaths.family(n.family)}
                              class="text-muted-foreground underline underline-offset-2"
                            >
                              {n.family}
                            </Link>
                          {/if}
                          {#if n.status === 'retired'}
                            <Badge variant="outline">Draining</Badge>
                          {:else if !n.offered}
                            <Badge variant="outline">Not offered here</Badge>
                          {/if}
                          {#if n.qualified === false}
                            <Badge variant="outline">Its target stopped serving it</Badge>
                          {/if}
                        </div>
                        <p class="text-muted-foreground">
                          {nameWhy(n)}
                          {n.markAt ? ` Marked ${relativeTime(n.markAt, now)}.` : ''}
                          {n.handed > 0 ? ` Handed to ${percent(n.handed)} of members here.` : ''}
                        </p>
                        {#if checksLine(n, now)}
                          <p class="text-muted-foreground">{checksLine(n, now)}</p>
                        {/if}
                        {#if realHostLine(n, now)}
                          <p class="text-muted-foreground">{realHostLine(n, now)}</p>
                        {/if}
                        {#if reportsLine(n)}
                          <p class="text-muted-foreground">{reportsLine(n)}</p>
                        {/if}
                      </li>
                    {/each}
                  </ul>
                </div>
              {/if}
            </section>
          {/each}

          {#if o.direct}
            {@const words = STATE_WORDS[o.direct.state]}
            <section aria-label="The node itself" class="space-y-1">
              <h3 class="font-medium">The node itself</h3>
              <div class="flex flex-wrap items-center gap-2">
                <StatusDot dot={words.dot} />
                <span class="font-medium">{words.label}</span>
                <span class="font-mono break-all">{o.direct.address}</span>
              </div>
              <p class="text-muted-foreground">{addressWhy(o.direct)}</p>
              {#each evidenceLines(o.direct) as line (line)}
                <p class="text-muted-foreground">{line}</p>
              {/each}
            </section>
          {/if}
        </CardContent>
      </Card>
    {/each}
  </div>
{/if}
