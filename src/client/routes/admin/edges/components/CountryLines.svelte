<script lang="ts">
  /**
   * One edge from each checked country (docs/edges.md "Checks from each
   * country"): a line per country with what it counts as there (works, blocked
   * since, down, not checked), where that comes from (its own checks, its
   * location, a mark), when it was checked, the reason in words and a mark
   * that disagrees with the checks. Words: lib/statusWords.ts `countryLine`.
   *
   * Props:
   *   lines: EdgeCountryLine[]    lib/countryChecks.ts `edgeCountryLines`
   *   checking?: boolean          a check the operator asked for has not come back yet
   *   label?: string              the list's accessible name
   */
  import { Badge } from '@client/components/ui/badge';
  import { countryName } from '@client/lib/countries';
  import type { EdgeCountryLine } from '../lib/countryChecks';
  import { countryLine } from '../lib/statusWords';

  interface Props {
    lines: EdgeCountryLine[];
    checking?: boolean;
    label?: string;
  }
  let { lines, checking = false, label = 'From each country' }: Props = $props();

  let now = $state(Date.now());
  $effect(() => {
    const t = setInterval(() => (now = Date.now()), 30_000);
    return () => clearInterval(t);
  });
  const words = $derived(lines.map((l) => countryLine(l, now)));
</script>

{#if words.length > 0}
  <ul class="space-y-1.5 text-xs" aria-label={label}>
    {#each words as w (w.country)}
      <li class="min-w-0">
        <div class="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span class="font-medium" title={w.country}>{countryName(w.country, 'en')}</span>
          <Badge variant={w.tone}>{w.label}</Badge>
          {#if w.from}<span class="text-muted-foreground">{w.from}</span>{/if}
          {#if w.checked}<span class="text-muted-foreground">{w.checked}</span>{/if}
        </div>
        {#if w.reason}<p class="text-muted-foreground mt-0.5">{w.reason}</p>{/if}
        {#if w.conflict}
          <p class="mt-0.5 text-amber-700 dark:text-amber-400">{w.conflict}</p>
        {/if}
      </li>
    {/each}
  </ul>
  {#if checking}
    <p class="text-muted-foreground mt-1 text-xs" role="status">
      Checking from every country. Results show here as they come back.
    </p>
  {/if}
{/if}
