<script lang="ts">
  /**
   * The country page's "Addresses for this country" section: the locations set
   * for this country (with "Add a location"), then every enabled origin, each
   * of its transports, and for each its addresses. Every line says one thing:
   *
   *   a transport    its protocol, what members here are handed in one line
   *                  (words.ts `handedSummary`), the shares worth a look, and a
   *                  handshake-gap flag; the full words behind "How members
   *                  here are handed this".
   *   an address     state, address (its IPv6 one, provider and location under it),
   *                  its share of members here, its path in ms (columns in a wide
   *                  card, folded under the address in a narrow one); why it counts
   *                  as it does, how long that stands, its lists and the
   *                  evidence behind the row's disclosure.
   *
   * The SNIs of each transport are in the SNIs section.
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
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import Info from '@lucide/svelte/icons/info';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Badge } from '@client/components/ui/badge';
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import type {
    CountryViewAddress,
    CountryViewListener,
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
    handedShort,
    handedSummary,
    handedWords,
    pathLine,
    handshakeLine,
    markLine,
    gradeLine,
    meantForWords,
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

  // Which rows and transports are opened, by key (all closed at first).
  let open = $state<Record<string, boolean>>({});
  const toggle = (key: string) => (open[key] = !open[key]);

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
  const where = (a: CountryViewAddress) =>
    [a.provider, a.location, a.layer === 'l7' ? 'CDN front' : null].filter(Boolean).join(' · ');
  const listLeft = (a: CountryViewAddress) => a.lists.some((m) => m.state === 'left');
  /** The handshake gap, short: "Handshake +51 ms" (null: none measured, or none). */
  const gapChip = (l: CountryViewListener) =>
    l.targetAdds && l.targetAdds.ms > 0 ? `Handshake +${l.targetAdds.ms} ms` : null;

  /** The address rows' columns: state, address, then (in a wide card) share and path, toggle. */
  const GRID =
    'grid grid-cols-[5.5rem_minmax(0,1fr)_1.75rem] gap-x-3 px-3 @xl:grid-cols-[5.5rem_minmax(0,1fr)_11rem_4rem_1.75rem]';
  const TOGGLE =
    'text-muted-foreground hover:text-foreground focus-visible:ring-ring/50 inline-flex items-center gap-1 rounded-sm text-sm outline-none focus-visible:ring-3';
</script>

{#snippet addressRow(o: CountryViewOrigin, a: CountryViewAddress, key: string)}
  {@const words = STATE_WORDS[a.state]}
  {@const share = handedShort(a.handed)}
  {@const isOpen = !!open[key]}
  <li>
    <div class={cn(GRID, 'items-start py-2')}>
      <span class="flex items-center gap-1.5 pt-px text-sm font-medium">
        <StatusDot dot={words.dot} />
        {words.label}
      </span>
      <span class="min-w-0">
        <Link
          href={addressHref(o, a)}
          class="block truncate font-mono text-sm underline-offset-2 hover:underline"
          title={a.address}
        >
          {a.address}
        </Link>
        <span class="text-muted-foreground block truncate text-xs" title={where(a)}>
          {#if a.v6}
            <span class="font-mono">{a.v6.address}</span>
            {#if a.v6.state !== a.state}
              ({a.v6.state ? STATE_WORDS[a.v6.state].label.toLowerCase() : 'not known'})
            {/if}
            <span aria-hidden="true"> · </span>
          {/if}
          {where(a)}
          <!-- Narrow: the two figure columns are hidden, so their figures sit here. -->
          <span class="@xl:hidden">
            {[share, a.path ? `${a.path.ms} ms` : null]
              .filter(Boolean)
              .map((f) => ` · ${f}`)
              .join('')}
          </span>
        </span>
      </span>
      <span class="text-muted-foreground hidden pt-px text-sm tabular-nums @xl:block">
        {share ?? ''}
      </span>
      <span class="text-muted-foreground hidden pt-px text-end text-sm tabular-nums @xl:block">
        {a.path ? `${a.path.ms} ms` : ''}
      </span>
      <button
        type="button"
        class={cn(TOGGLE, 'justify-self-end')}
        aria-expanded={isOpen}
        aria-label={`${isOpen ? 'Hide' : 'Show'} why for ${a.address}`}
        onclick={() => toggle(key)}
      >
        {#if listLeft(a)}
          <TriangleAlert class="size-4 text-amber-600 dark:text-amber-400" aria-hidden="true" />
        {/if}
        <ChevronDown
          class={cn('size-4 transition-transform', isOpen && 'rotate-180')}
          aria-hidden="true"
        />
      </button>
    </div>
    {#if isOpen}
      <div class="text-muted-foreground space-y-1 px-3 pb-3 text-sm">
        <p>
          {#if a.publication}
            <StatusBadge kind="publication" value={a.publication} class="me-1 align-text-bottom" />
          {/if}
          {addressWhy(a)}
          {untilLine(a.until, now) ?? ''}
        </p>
        {#if pathLine(a, code)}<p>{pathLine(a, code)}</p>{/if}
        {#if addressListsLine(a, now)}
          <p class={listLeft(a) ? 'text-amber-700 dark:text-amber-400' : undefined}>
            {addressListsLine(a, now)}
          </p>
        {/if}
        {#if evidenceLines(a).length > 0}
          <p class="text-foreground pt-1 font-medium">Evidence</p>
          <ul class="list-disc space-y-0.5 ps-5">
            {#each evidenceLines(a) as line (line)}<li>{line}</li>{/each}
          </ul>
        {/if}
      </div>
    {/if}
  </li>
{/snippet}

<div class="space-y-6">
  <details class="group text-sm">
    <summary
      class="text-muted-foreground hover:text-foreground inline-flex cursor-pointer list-none items-center gap-1.5 select-none"
    >
      <Info class="size-4" aria-hidden="true" />
      Whose numbers these are
    </summary>
    <p class="text-muted-foreground mt-1 max-w-prose">{HANDED_SCOPE}</p>
  </details>

  <Card>
    <CardHeader class="pb-2">
      <CardTitle class="text-base">Locations for {countryLabel(code)}</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      {#if v.meantFor.length === 0}
        <p class="text-muted-foreground">
          None set: members here get addresses by what works here.
          <Link
            href={edgesPaths.providers()}
            class="text-primary ms-1 underline underline-offset-4"
            title="Open the provider account, then set the location's countries."
          >
            Add a location
          </Link>
        </p>
      {:else}
        <ul class="divide-y rounded-md border">
          {#each v.meantFor as l (l.locationId)}
            {@const w = meantForWords(l)}
            <li class="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-2">
              <Link href={edgesPaths.provider(l.accountId)} class="font-medium">{l.label}</Link>
              <span class={l.blocked ? 'text-destructive' : 'text-muted-foreground'}>
                {w.state}
              </span>
              <!-- Shown, not a tooltip: touch and keyboard users have no hover. -->
              <span class="text-muted-foreground w-full text-xs">{w.detail}</span>
            </li>
          {/each}
        </ul>
        <Link
          href={edgesPaths.providers()}
          class="text-primary text-sm underline underline-offset-4"
          title="Open the provider account, then set the location's countries."
        >
          Add a location
        </Link>
      {/if}
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
      <CardHeader class="pb-3">
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
      <CardContent class="space-y-5 text-sm">
        {#each o.listeners as l (l.listenerId)}
          {@const summary = handedSummary(l.members)}
          {@const gap = gapChip(l)}
          {@const handKey = `hand:${o.relayId}:${l.listenerId}`}
          <section aria-label={protocolLine(l)} class="space-y-2">
            <div class="flex flex-wrap items-center gap-x-2 gap-y-1">
              <ProtocolBadge
                protocol={l.protocol}
                streamTransport={l.streamTransport}
                security={l.security}
              />
              {#if !l.usable}<Badge variant="outline">Not in use</Badge>{/if}
              {#if gap}
                <Badge
                  variant={l.targetAdds?.flagged ? 'warning' : 'muted'}
                  title="How much longer a handshake takes on its addresses than on its SNIs' real sites"
                >
                  {gap}{l.targetAdds?.flagged ? ', flagged' : ''}
                </Badge>
              {/if}
              <span class="text-muted-foreground">{summary.line}</span>
              {#each summary.alerts as alert (alert)}
                <span class="text-amber-700 dark:text-amber-400">{alert}</span>
              {/each}
            </div>
            <button
              type="button"
              class={TOGGLE}
              aria-expanded={!!open[handKey]}
              onclick={() => toggle(handKey)}
            >
              How members here are handed this
              <ChevronDown
                class={cn('size-4 transition-transform', open[handKey] && 'rotate-180')}
                aria-hidden="true"
              />
            </button>
            {#if open[handKey]}
              <div class="bg-muted/40 text-muted-foreground space-y-1 rounded-md px-3 py-2">
                {#each handedWords(l.members) as line (line)}<p>{line}</p>{/each}
                {#if targetAddsLine(l, now)}
                  <p>{targetAddsLine(l, now)}</p>
                  {#if l.targetAdds?.flagged}<p>{TARGET_ADDS_FLAG_WORDS}</p>{/if}
                {/if}
              </div>
            {/if}

            {#if l.addresses.length === 0}
              <p class="text-muted-foreground">No address in use or spare.</p>
            {:else}
              <div class="@container rounded-md border">
                <div
                  class={cn(
                    GRID,
                    'text-muted-foreground hidden border-b py-1.5 text-xs font-medium @xl:grid',
                  )}
                  aria-hidden="true"
                >
                  <span>Here</span>
                  <span>Address</span>
                  <span>Members here</span>
                  <span class="text-end">Path</span>
                  <span></span>
                </div>
                <ul class="divide-y" aria-label="Addresses">
                  {#each l.addresses as a (a.edgeId ?? a.address)}
                    {@render addressRow(
                      o,
                      a,
                      `a:${o.relayId}:${l.listenerId}:${a.edgeId ?? a.address}`,
                    )}
                  {/each}
                </ul>
              </div>
            {/if}
          </section>
        {/each}
        {#if o.direct}
          {@const d = o.direct}
          {@const words = STATE_WORDS[d.state]}
          {@const key = `direct:${o.relayId}`}
          <section aria-label="The node itself" class="space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-medium">The node itself</span>
              <StatusDot dot={words.dot} />
              <span>{words.label}</span>
              <span class="text-muted-foreground font-mono break-all">{d.address}</span>
              <button
                type="button"
                class={TOGGLE}
                aria-expanded={!!open[key]}
                aria-label={`${open[key] ? 'Hide' : 'Show'} why for the node itself`}
                onclick={() => toggle(key)}
              >
                <ChevronDown
                  class={cn('size-4 transition-transform', open[key] && 'rotate-180')}
                  aria-hidden="true"
                />
              </button>
            </div>
            {#if open[key]}
              <div class="text-muted-foreground space-y-1">
                <p>{addressWhy(d)}</p>
                {#each evidenceLines(d) as line (line)}<p>{line}</p>{/each}
              </div>
            {/if}
          </section>
        {/if}
      </CardContent>
    </Card>
  {/each}
</div>
