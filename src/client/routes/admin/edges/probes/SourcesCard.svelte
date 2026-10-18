<script lang="ts">
  /**
   * Whether each enabled probe source is bringing back evidence (`GET
   * probes/sources`): working, working with failures, or failing with its last
   * failure in words. A source that errors is never read as a block, so the
   * countries only it covers read "not known"; this panel is where that shows
   * (attention `probe_source_failing` points here too). No Card of its own.
   */
  import { Badge } from '@client/components/ui/badge';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import AdminListState from '../../AdminListState.svelte';
  import { probeSourcesQuery } from '../../../../lib/edgesApi';
  import { edgesPaths } from '../lib/routes';
  import { sourceWords } from '../lib/statusWords';
  import { PROBE_SOURCE_LABELS } from './matrix';

  const sources = probeSourcesQuery();
  let now = $state(Date.now());
  $effect(() => {
    const t = setInterval(() => (now = Date.now()), 30_000);
    return () => clearInterval(t);
  });
  const rows = $derived(
    (sources.data?.sources ?? []).map((h) => ({ h, words: sourceWords(h, now) })),
  );
</script>

{#if sources.isPending}
  <Skeleton class="h-16 w-full" />
{:else if sources.isError}
  <AdminListState error={sources.error} onRetry={() => void sources.refetch()} />
{:else if rows.length === 0}
  <p class="text-muted-foreground text-sm">
    No source is in use: probes are off, or no source is switched on with its key.
    <Link href={edgesPaths.settings({ section: 'probes' })} class="underline">Probe settings</Link>.
  </p>
{:else}
  <ul class="divide-y text-sm" aria-label="Probe sources">
    {#each rows as { h, words } (h.source)}
      <li class="flex flex-col gap-1 py-2 sm:flex-row sm:items-start sm:gap-4">
        <span class="font-medium sm:w-40 sm:shrink-0"
          >{PROBE_SOURCE_LABELS[h.source] ?? h.source}</span
        >
        <span class="min-w-0 flex-1">
          <Badge variant={words.tone}>{words.label}</Badge>
          <span class="text-muted-foreground mt-1 block text-xs">{words.detail}</span>
        </span>
      </li>
    {/each}
  </ul>
{/if}
