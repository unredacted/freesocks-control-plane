<script lang="ts">
  /**
   * The SNIs of one country, once over every node and
   * transport in use (`CountryViewResponse.snis`): each with its name list,
   * what it counts as there, how many members there are handed it,
   * whether it is shared, only for this country, or not used there, and
   * whether a list of what works puts it first there.
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
    sniPreferLine,
    SNI_PREFER_BADGE,
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
      <ul class="divide-y rounded-md border" aria-label="SNIs">
        {#each snis as s (s.name)}
          {@const words = STATE_WORDS[s.state]}
          {@const badge = sniScopeBadge(s, code)}
          {@const prefer = sniPreferLine(s)}
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
              {#if prefer}
                <Badge variant="secondary">{SNI_PREFER_BADGE}</Badge>
              {/if}
            </div>
            <p class="text-muted-foreground">{sniScopeLine(s, code)}</p>
            <p class="text-muted-foreground">
              {sniVerdictLine(s)}
              {sniHandedLine(s) ?? ''}
            </p>
            {#if prefer}
              <p
                class={s.preferDoubt
                  ? 'text-amber-700 dark:text-amber-400'
                  : 'text-muted-foreground'}
              >
                {prefer}
              </p>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </CardContent>
</Card>
