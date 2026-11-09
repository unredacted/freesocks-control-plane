<script lang="ts">
  /**
   * The country page's "SNIs" section: for every enabled origin and each of
   * its REALITY transports, the SNIs in use and what each counts as from
   * here, why (a mark, the checks from inside, real-site checks, the lists,
   * member reports) and how many members here are handed it. Read only:
   * marks are made on the SNI list's page (the SNIs tab).
   *
   * SLOT: the one-list-per-country card (each SNI once over every node, with
   * shared / only for it / not used) goes first, above the per-node lists.
   *
   * Props:
   *   view: CountryViewResponse
   * All wording lives in ./words.ts (pure, unit-tested).
   */
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Badge } from '@client/components/ui/badge';
  import Link from '@client/components/Link.svelte';
  import type { CountryViewResponse } from '@shared/contracts/edges';
  import StatusDot from '../simple/StatusDot.svelte';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';
  import {
    STATE_WORDS,
    checksLine,
    listsLine,
    nameWhy,
    namePoolLines,
    namesOnListsLine,
    percent,
    realHostLine,
    reportsLine,
  } from './words';

  let { view: v }: { view: CountryViewResponse } = $props();
  let now = $derived(v.generatedAt);

  // Only the origins and transports that have an SNI here.
  const withNames = $derived(
    v.origins
      .map((o) => ({ origin: o, listeners: o.listeners.filter((l) => l.names.length > 0) }))
      .filter((x) => x.listeners.length > 0),
  );
  const poolLines = $derived(v.listed?.nameChecksRun ? namePoolLines(v.namePool) : []);
</script>

<div class="space-y-6">
  <!-- SLOT: the country's SNI card (each SNI once over every node) goes here. -->

  {#if poolLines.length > 0}
    <Card>
      <CardContent class="text-muted-foreground space-y-1 py-4 text-sm">
        {#each poolLines as line (line)}<p>{line}</p>{/each}
      </CardContent>
    </Card>
  {/if}

  {#if withNames.length === 0}
    <Card>
      <CardContent class="text-muted-foreground py-8 text-center text-sm">
        No node uses an SNI here.
        <Link href={edgesPaths.names()} class="underline underline-offset-2">SNI lists</Link>
      </CardContent>
    </Card>
  {/if}

  {#each withNames as { origin: o, listeners } (o.relayId)}
    <Card>
      <CardHeader>
        <CardTitle class="text-base">{o.label ?? o.nodeName ?? o.slug}</CardTitle>
      </CardHeader>
      <CardContent class="space-y-6 text-sm">
        {#each listeners as l (l.listenerId)}
          <section aria-label={`SNIs of transport ${l.key}`} class="space-y-2">
            <p class="text-muted-foreground">Transport {l.key}</p>
            {#if namesOnListsLine(l)}
              <p class="text-muted-foreground">{namesOnListsLine(l)}</p>
            {/if}
            <ul class="divide-border divide-y rounded-md border" aria-label="SNIs">
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
                      <Badge variant="outline">The cover site stopped serving it</Badge>
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
                  {#if listsLine(n)}
                    <p class="text-muted-foreground">{listsLine(n)}</p>
                  {/if}
                  {#if reportsLine(n)}
                    <p class="text-muted-foreground">{reportsLine(n)}</p>
                  {/if}
                </li>
              {/each}
            </ul>
          </section>
        {/each}
      </CardContent>
    </Card>
  {/each}
</div>
