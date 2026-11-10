<script lang="ts">
  /**
   * The country lists FCP follows for one country, on that country's page.
   *
   * Props: code: string (ISO 3166-1 alpha-2, upper case)
   * All wording lives in ./listWords.ts (pure, unit-tested).
   */
  import { Badge } from '@client/components/ui/badge';
  import { Card, CardContent } from '@client/components/ui/card';
  import Link from '@client/components/Link.svelte';
  import { countryListsQuery } from '@client/lib/countryListsApi';
  import { edgesPaths } from '../lib/routes';
  import { countsLine, listBadge, PREFER_BADGE, REGIME_WORDS } from './listWords';

  let { code }: { code: string } = $props();
  const lists = countryListsQuery(() => code);
</script>

<Card class="mb-6">
  <CardContent class="space-y-2 py-4 text-sm">
    <p class="font-medium">Country lists</p>
    {#if lists.isError}
      <p class="text-muted-foreground">The lists could not be loaded.</p>
    {:else if (lists.data?.lists.length ?? 0) === 0}
      <p class="text-muted-foreground">
        FCP follows no list for this country.
        <Link href={edgesPaths.lists()} class="underline underline-offset-2">Add one.</Link>
      </p>
    {:else}
      <ul class="space-y-1">
        {#each lists.data?.lists ?? [] as l (l.id)}
          {@const badge = listBadge(l)}
          <li class="flex flex-wrap items-center gap-2">
            <Link href={edgesPaths.list(l.id)} class="underline-offset-2 hover:underline">
              {l.label}
            </Link>
            <Badge variant={badge.tone}>{badge.label}</Badge>
            {#if l.preferNames}<Badge variant="secondary">{PREFER_BADGE}</Badge>{/if}
            <span class="text-muted-foreground">
              {REGIME_WORDS[l.regime].label}. {l.active ? countsLine(l.active.counts) : ''}
            </span>
          </li>
        {/each}
      </ul>
    {/if}
  </CardContent>
</Card>
