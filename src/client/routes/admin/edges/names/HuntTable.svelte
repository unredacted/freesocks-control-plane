<script lang="ts">
  /**
   * Names found on one network (docs/edges.md "Finding names"): three
   * filters (usable, not usable, all), each name with its state and a one-line
   * reason, what was measured (the handshakes, timing, countries, OONI,
   * sources, the score) under Details, and the other names of one site folded
   * behind the first. Picked names can be added to a name list (its normal
   * path: each is checked like a pasted name), ignored (the name or its whole
   * site), checked again, measured now, or have their sites looked up in
   * certificate logs. Nothing here is applied by itself.
   *
   * All wording lives in ./lib/huntWords.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Collapsible from '@client/components/ui/collapsible';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { ApiCallError } from '@client/lib/api';
  import {
    actOnCandidates,
    addCandidates,
    huntCandidatesQuery,
    invalidateSni,
    lookUpCt,
    type CandidateAction,
  } from '@client/lib/sniApi';
  import type { SniCandidateRow } from '../../../../../shared/contracts/sni';
  import {
    HUNT_FILTERS,
    HUNT_FILTER_LABEL,
    HUNT_FILTER_STATE,
    candidateWords,
    countryWords,
    extraWords,
    matchesHuntFilter,
    nearWords,
    scoreWords,
    siteOoniWords,
    sourcesWords,
    type HuntFilter,
  } from './lib/huntWords';
  import { addedWords, suggestionReason } from './lib/transportWords';
  import { sniErrorWords, type Dot } from './lib/words';

  let {
    kind,
    slug,
    families,
  }: {
    kind: 'network' | 'family';
    slug: string;
    /** Where picked names may be added: the name lists on the network. */
    families: { slug: string; label: string }[];
  } = $props();

  const qc = useQueryClient();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);
  const DOT: Record<Dot, string> = {
    green: 'bg-emerald-500',
    amber: 'bg-amber-500',
    red: 'bg-destructive',
    grey: 'bg-muted-foreground/50',
  };
  const SELECT = 'border-border bg-background min-h-9 rounded-md border px-2 py-1.5 text-sm';
  const isFamily = $derived(kind === 'family');

  let busy = $state(false);
  async function run<T>(work: () => Promise<T>): Promise<T | null> {
    busy = true;
    try {
      return await work();
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
      return null;
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }

  let filter = $state<HuntFilter>('usable');
  let picked = $state<string[]>([]);
  // One state's pages at a time, best first; "Show more" reads the next page.
  const list = huntCandidatesQuery(
    () => kind,
    () => slug,
    () => HUNT_FILTER_STATE[filter],
  );
  let loaded = $derived((list.data?.pages ?? []).flatMap((p) => p.candidates));
  let shown = $derived(loaded.filter((c) => matchesHuntFilter(c, filter)));
  let allPicked = $derived(shown.length > 0 && shown.every((c) => picked.includes(c.id)));
  // One entry per site (best name first); its other names fold behind it.
  let sites = $derived.by(() => {
    const by = new Map<string, SniCandidateRow[]>();
    for (const c of shown) by.set(c.site, [...(by.get(c.site) ?? []), c]);
    return [...by.values()];
  });
  let opened = $state<string[]>([]);
  const toggle = (id: string, on: boolean) =>
    (picked = on ? [...picked, id] : picked.filter((x) => x !== id));
  const toggleAll = (on: boolean) => (picked = on ? shown.map((c) => c.id) : []);
  const pickedRows = $derived(loaded.filter((c) => picked.includes(c.id)));

  let family = $state('');
  $effect(() => {
    if (!family && families.length === 1) family = families[0]!.slug;
  });

  /** Split in the sizes one request takes (the server reads at most that many). */
  const chunks = <T,>(xs: T[], n: number) =>
    Array.from({ length: Math.ceil(xs.length / n) }, (_, i) => xs.slice(i * n, i * n + n));

  async function act(action: CandidateAction, kind?: 'name' | 'site') {
    // A whole site is one action whichever of its names is picked: one id a
    // site, ten sites a request (the server reads each site's names once).
    const ids =
      kind === 'site' ? [...new Map(pickedRows.map((c) => [c.site, c.id])).values()] : [...picked];
    const r = await run(async () => {
      let changed = 0;
      for (const part of chunks(ids, kind === 'site' ? 10 : 200))
        changed += (await actOnCandidates(action, part, kind)).changed;
      return { changed };
    });
    if (r) {
      picked = [];
      toast.success(
        action === 'measure'
          ? 'Measured next, within the hour’s budget.'
          : action === 'recheck'
            ? 'Checked again on the next run.'
            : `${r.changed} changed.`,
      );
    }
  }
  async function add() {
    if (!family) return;
    const names = pickedRows.map((c) => c.name);
    const r = await run(async () => {
      const lines = [];
      let added = 0;
      for (const part of chunks(names, 500)) {
        const one = await addCandidates(family, part);
        added += one.added;
        lines.push(...one.lines);
      }
      return { added, lines };
    });
    if (r) {
      picked = [];
      toast.success(addedWords(r));
    }
  }
  async function lookUp() {
    const sites = [...new Set(pickedRows.map((c) => c.site))];
    const scope = isFamily ? { family: slug } : { network: slug };
    const r = await run(async () => {
      let queued = 0;
      let cached = 0;
      for (const part of chunks(sites, 10)) {
        const one = await lookUpCt(part, scope);
        queued += one.queued;
        cached += one.cached;
      }
      return { queued, cached };
    });
    if (r) {
      picked = [];
      toast.success(
        r.queued > 0
          ? `Reading the certificate logs for ${r.queued} ${r.queued === 1 ? 'site' : 'sites'}.`
          : 'Already read in full this week.',
      );
    }
  }
</script>

<div class="space-y-3">
  <div class="flex flex-wrap gap-2" role="group" aria-label="Show">
    {#each HUNT_FILTERS as id (id)}
      <Button
        variant={filter === id ? 'default' : 'outline'}
        size="sm"
        aria-pressed={filter === id}
        onclick={() => {
          filter = id;
          picked = [];
        }}
      >
        {HUNT_FILTER_LABEL[id]}
      </Button>
    {/each}
  </div>

  {#if picked.length > 0}
    <div class="bg-muted/30 flex flex-wrap items-center gap-2 rounded-md border p-2">
      <span class="px-1">{picked.length} picked</span>
      {#if families.length > 0}
        <label class="flex items-center gap-2">
          <span class="text-muted-foreground">Add to</span>
          <select bind:value={family} class={SELECT} aria-label="Name list">
            <option value="" disabled>name list</option>
            {#each families as f (f.slug)}
              <option value={f.slug}>{f.label}</option>
            {/each}
          </select>
        </label>
        <Button size="sm" disabled={busy || !family} onclick={add}>Add</Button>
      {/if}
      <Button variant="outline" size="sm" disabled={busy} onclick={() => act('recheck')}>
        Check again
      </Button>
      <Button variant="outline" size="sm" disabled={busy} onclick={() => act('measure')}>
        Measure now
      </Button>
      <Button variant="outline" size="sm" disabled={busy} onclick={lookUp}>
        Look up certificate logs
      </Button>
      <Button variant="outline" size="sm" disabled={busy} onclick={() => act('ignore', 'name')}>
        Ignore
      </Button>
      <Button variant="outline" size="sm" disabled={busy} onclick={() => act('ignore', 'site')}>
        Ignore the whole site
      </Button>
      {#if pickedRows.some((c) => c.state === 'ignored')}
        <Button variant="outline" size="sm" disabled={busy} onclick={() => act('unignore')}>
          Stop ignoring
        </Button>
      {/if}
    </div>
  {/if}

  {#if list.isError}
    <p class="text-destructive">{sniErrorWords(codeOf(list.error))}</p>
  {:else if list.isPending}
    <p class="text-muted-foreground">Loading…</p>
  {:else if shown.length === 0 && !list.hasNextPage}
    <p class="text-muted-foreground">Nothing here.</p>
  {:else}
    <div class="flex items-center gap-2 px-1">
      <Checkbox
        checked={allPicked}
        onCheckedChange={(v) => toggleAll(v === true)}
        aria-label="Pick every name shown"
      />
      <span class="text-muted-foreground">{shown.length} shown, best first</span>
    </div>
    <ul class="divide-y rounded-md border" aria-label="Found names">
      {#each sites as names (names[0]!.site)}
        {@const more = names.length - 1}
        {@const open = opened.includes(names[0]!.site)}
        {#each open ? names : names.slice(0, 1) as c (c.id)}
          {@const w = candidateWords(c)}
          {@const extra = extraWords(c)}
          {@const countries = countryWords(c)}
          {@const site = siteOoniWords(c)}
          <li class="flex items-start gap-3 p-3">
            <Checkbox
              checked={picked.includes(c.id)}
              onCheckedChange={(v) => toggle(c.id, v === true)}
              aria-label={`Pick ${c.name}`}
            />
            <div class="min-w-0 flex-1 space-y-1">
              <p class="flex flex-wrap items-center gap-2">
                <span
                  class={`inline-block size-2 shrink-0 rounded-full ${DOT[w.dot]}`}
                  aria-hidden="true"
                ></span>
                <span class="font-mono break-words">{c.name}</span>
              </p>
              <p class="text-muted-foreground">
                {w.dot === 'green' ? suggestionReason(c) : w.sentence}
              </p>
              <Collapsible.Root>
                <Collapsible.Trigger
                  class="group text-muted-foreground hover:text-foreground flex min-h-11 items-center gap-1 text-xs sm:min-h-0"
                >
                  <ChevronRight
                    class="size-3.5 transition-transform group-data-[state=open]:rotate-90"
                    aria-hidden="true"
                  />
                  Details
                </Collapsible.Trigger>
                <Collapsible.Content class="text-muted-foreground mt-1 space-y-0.5 text-xs">
                  <p>{w.sentence}{extra ? ` ${extra}` : ''}</p>
                  {#if c.check && c.check.code === null}
                    <p>{nearWords(c, isFamily)}</p>
                    {#if countries.length > 0}<p>{countries.join(' · ')}</p>{/if}
                    {#if site}<p>{site}</p>{/if}
                  {/if}
                  <p>Found in: {sourcesWords(c)}.</p>
                  <p>{scoreWords(c)}</p>
                </Collapsible.Content>
              </Collapsible.Root>
            </div>
          </li>
        {/each}
        {#if more > 0}
          <li class="px-3 py-2">
            <Button
              variant="link"
              size="sm"
              class="h-auto p-0"
              onclick={() =>
                (opened = open
                  ? opened.filter((x) => x !== names[0]!.site)
                  : [...opened, names[0]!.site])}
            >
              {open
                ? `Fold the names of ${names[0]!.site}`
                : `And ${more} more ${more === 1 ? 'name' : 'names'} of ${names[0]!.site}`}
            </Button>
          </li>
        {/if}
      {/each}
    </ul>
    {#if list.hasNextPage}
      <Button
        variant="outline"
        size="sm"
        disabled={list.isFetchingNextPage}
        onclick={() => void list.fetchNextPage()}
      >
        {list.isFetchingNextPage ? 'Loading…' : 'Show more'}
      </Button>
    {/if}
  {/if}
</div>
