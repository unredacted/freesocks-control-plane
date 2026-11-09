<script lang="ts">
  /**
   * The country page's "Addresses for this country" section: the locations set
   * for this country (with "Add a location for this country"), then every
   * enabled origin, each of its transports, and for each its addresses: what
   * they count as from here, why (a mark, the checks with controls, the checks
   * from inside, the probes), how old that is, and what a member here is
   * handed today. The SNIs of each transport are in the SNIs section.
   *
   * SLOT: the per-country edges design (addresses kept for one country, its
   * own pool and budget) puts its card where `perCountry` renders, between the
   * locations and the origins. Nothing renders there until it lands.
   *
   * Props:
   *   code: string                 the country (ISO 3166-1 alpha-2)
   *   view: CountryViewResponse
   *   perCountry?: Snippet         the per-country edges card (see SLOT)
   * All wording lives in ./words.ts (pure, unit-tested).
   */
  import type { Snippet } from 'svelte';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Badge } from '@client/components/ui/badge';
  import Link from '@client/components/Link.svelte';
  import type {
    CountryViewAddress,
    CountryViewOrigin,
    CountryViewResponse,
  } from '@shared/contracts/edges';
  import StatusBadge from '../components/StatusBadge.svelte';
  import ProtocolBadge from '../components/ProtocolBadge.svelte';
  import StatusDot from '../simple/StatusDot.svelte';
  import { edgesPaths } from '../lib/routes';
  import { protocolLine } from '../lib/format';
  import {
    HANDED_SCOPE,
    STATE_WORDS,
    addressListsLine,
    addressWhy,
    countryLabel,
    handedWords,
    pathLine,
    handshakeLine,
    markLine,
    gradeLine,
    meantForWords,
    percent,
    probesLine,
    addressRealHostLine,
    addressTimingLine,
    targetAddsLine,
    TARGET_ADDS_FLAG_WORDS,
    roundLine,
    staleAnswersLine,
    untilLine,
  } from './words';

  interface Props {
    code: string;
    view: CountryViewResponse;
    perCountry?: Snippet;
  }
  let { code, view: v, perCountry }: Props = $props();
  let now = $derived(v.generatedAt);

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
      staleAnswersLine(a, now),
      addressRealHostLine(a, now),
      addressTimingLine(a, now),
    ].filter((x): x is string => !!x);
  }
  function handedLine(a: CountryViewAddress): string | null {
    const parts: string[] = [];
    if (a.handed.primary > 0) parts.push(`first address for ${percent(a.handed.primary)}`);
    if (a.handed.backup > 0) parts.push(`backup for ${percent(a.handed.backup)}`);
    return parts.length > 0 ? `Handed out here: ${parts.join(', ')} of members.` : null;
  }
</script>

<div class="space-y-6">
  <p class="text-muted-foreground text-sm">{HANDED_SCOPE}</p>
  <Card>
    <CardHeader class="pb-2">
      <CardTitle class="text-base">Locations for {countryLabel(code)}</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      {#if v.meantFor.length === 0}
        <p class="text-muted-foreground">
          No location is set for this country, so members here get addresses by what works here.
        </p>
      {:else}
        <ul class="divide-y rounded-md border">
          {#each v.meantFor as l (l.locationId)}
            {@const w = meantForWords(l)}
            <li class="space-y-0.5 p-3">
              <p class="flex flex-wrap items-center gap-2 font-medium">
                <Link href={edgesPaths.provider(l.accountId)}>{l.label}</Link>
                {#if l.blocked}<Badge variant="destructive">Blocked here</Badge>{/if}
              </p>
              <p class={l.blocked ? 'text-destructive' : 'text-muted-foreground'}>{w.state}</p>
              <p class="text-muted-foreground text-xs">{w.detail}</p>
            </li>
          {/each}
        </ul>
      {/if}
      <div class="flex flex-wrap items-center gap-3">
        <Link
          href={edgesPaths.providers()}
          class="border-input hover:bg-accent inline-flex h-8 items-center rounded-md border px-3 text-sm"
        >
          Add a location for this country
        </Link>
        <span class="text-muted-foreground text-xs">
          Open the provider account, then set the location's countries.
        </span>
      </div>
    </CardContent>
  </Card>

  {#if perCountry}{@render perCountry()}{/if}

  {#if v.origins.length === 0}
    <Card>
      <CardContent class="text-muted-foreground py-8 text-center text-sm">
        No origin is switched on.
      </CardContent>
    </Card>
  {/if}

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
          <section aria-label={protocolLine(l)} class="space-y-3">
            <div class="flex flex-wrap items-center gap-2">
              <ProtocolBadge
                protocol={l.protocol}
                streamTransport={l.streamTransport}
                security={l.security}
              />
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
                      {#if pathLine(a, code)}
                        <p class="text-muted-foreground">{pathLine(a, code)}</p>
                      {/if}
                      {#if addressListsLine(a, now)}
                        <p
                          class={a.lists.some((m) => m.state === 'left')
                            ? 'text-amber-700 dark:text-amber-400'
                            : 'text-muted-foreground'}
                        >
                          {addressListsLine(a, now)}
                        </p>
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
