<script lang="ts">
  /**
   * The server names (SNIs) of one country, once over every node and
   * transport in use (`CountryViewResponse.snis`): each with its name list,
   * what it counts as there, how many members there are handed it, and
   * whether it is shared, only for this country, or not used there.
   * Read only: marks are made on the name list's page.
   *
   * Props: code: string (ISO 3166-1 alpha-2), snis: CountryViewSni[]
   * All wording lives in ./sniWords.ts (pure, unit-tested).
   */
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Badge } from '@client/components/ui/badge';
  import Link from '@client/components/Link.svelte';
  import type { CountryViewSni } from '@shared/contracts/edges';
  import StatusDot from '../simple/StatusDot.svelte';
  import { edgesPaths } from '../lib/routes';
  import { STATE_WORDS } from './words';
  import {
    SNI_CARD_EMPTY,
    SNI_CARD_INTRO,
    sniCardTitle,
    sniHandedLine,
    sniScopeBadge,
    sniScopeLine,
    sniVerdictLine,
  } from './sniWords';

  interface Props {
    code: string;
    snis: CountryViewSni[];
  }
  let { code, snis }: Props = $props();
</script>

<Card class="mb-6">
  <CardHeader class="pb-2">
    <CardTitle class="text-base">{sniCardTitle(code)}</CardTitle>
  </CardHeader>
  <CardContent class="space-y-2 text-sm">
    <p class="text-muted-foreground">{SNI_CARD_INTRO}</p>
    {#if snis.length === 0}
      <p class="text-muted-foreground">{SNI_CARD_EMPTY}</p>
    {:else}
      <ul class="divide-y rounded-md border" aria-label="Server names (SNIs)">
        {#each snis as s (s.name)}
          {@const words = STATE_WORDS[s.state]}
          {@const badge = sniScopeBadge(s, code)}
          <li class="space-y-0.5 px-3 py-2">
            <div class="flex flex-wrap items-center gap-2">
              <StatusDot dot={words.dot} />
              <span class="font-medium">{words.label}</span>
              <span class="font-mono break-all">{s.name}</span>
              {#if s.family}
                <Link
                  href={edgesPaths.family(s.family)}
                  class="text-muted-foreground underline underline-offset-2"
                >
                  {s.familyLabel ?? s.family}
                </Link>
              {/if}
              {#if badge}
                <Badge variant={s.scope === 'not_here' ? 'outline' : 'secondary'}>{badge}</Badge>
              {/if}
            </div>
            <p class="text-muted-foreground">{sniScopeLine(s, code)}</p>
            <p class="text-muted-foreground">
              {sniVerdictLine(s)}
              {sniHandedLine(s) ?? ''}
            </p>
          </li>
        {/each}
      </ul>
    {/if}
  </CardContent>
</Card>
