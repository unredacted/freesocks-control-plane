<script lang="ts">
  /**
   * Candidate names of one network or one family (docs/edges.md "Finding
   * names"): each with qualification's own verdict, the extra handshakes,
   * what was measured, and the score. Picked candidates can be added to a
   * family (its normal path: each is qualified like a pasted name), ignored
   * (the name or its whole site), checked again, measured now, or have their
   * sites looked up in certificate logs. Nothing here is applied by itself.
   *
   * All wording lives in ./lib/huntWords.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { ApiCallError } from '@client/lib/api';
  import {
    actOnCandidates,
    addCandidates,
    invalidateSni,
    lookUpCt,
    type CandidateAction,
  } from '@client/lib/sniApi';
  import type { SniHuntScopeView } from '../../../../../shared/contracts/sni';
  import {
    HUNT_FILTERS,
    HUNT_FILTER_LABEL,
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
  import { importWords, sniErrorWords, type Dot } from './lib/words';

  let {
    view,
    families,
  }: {
    view: SniHuntScopeView;
    /** Where picked names may be added: the family itself on its page, the network's families on a network. */
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
  const isFamily = $derived(view.scope.kind === 'family');

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

  let filter = $state<HuntFilter>('ready');
  let picked = $state<string[]>([]);
  let shown = $derived(view.candidates.filter((c) => matchesHuntFilter(c, filter)));
  let allPicked = $derived(shown.length > 0 && shown.every((c) => picked.includes(c.id)));
  const toggle = (id: string, on: boolean) =>
    (picked = on ? [...picked, id] : picked.filter((x) => x !== id));
  const toggleAll = (on: boolean) => (picked = on ? shown.map((c) => c.id) : []);
  const pickedRows = $derived(view.candidates.filter((c) => picked.includes(c.id)));

  let family = $state('');
  $effect(() => {
    if (!family && families.length === 1) family = families[0]!.slug;
  });

  async function act(action: CandidateAction, kind?: 'name' | 'site') {
    const ids = [...picked];
    const r = await run(() => actOnCandidates(action, ids, kind));
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
    const r = await run(() => addCandidates(family, names));
    if (r) {
      picked = [];
      toast.success(importWords(r).join(' '));
    }
  }
  async function lookUp() {
    const sites = [...new Set(pickedRows.map((c) => c.site))].slice(0, 10);
    const scope = isFamily ? { family: view.scope.slug } : { network: view.scope.slug };
    const r = await run(() => lookUpCt(sites, scope));
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
          <select bind:value={family} class={SELECT} aria-label="Family">
            <option value="" disabled>family</option>
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
      {#if filter === 'ignored'}
        <Button variant="outline" size="sm" disabled={busy} onclick={() => act('unignore')}>
          Stop ignoring
        </Button>
      {/if}
    </div>
  {/if}

  {#if shown.length === 0}
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
    <ul class="divide-y rounded-md border" aria-label="Candidate names">
      {#each shown as c (c.id)}
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
              <span class="font-mono break-all">{c.name}</span>
              {#if c.listed}<span class="text-muted-foreground text-xs">(on the shortlist)</span
                >{/if}
            </p>
            <p>{w.sentence}{extra ? ` ${extra}` : ''}</p>
            {#if c.check && c.check.code === null}
              <p class="text-muted-foreground">{nearWords(c, isFamily)}</p>
              {#if countries.length > 0}
                <p class="text-muted-foreground">{countries.join(' · ')}</p>
              {/if}
              {#if site}<p class="text-muted-foreground">{site}</p>{/if}
            {/if}
            <p class="text-muted-foreground">{sourcesWords(c)} · {scoreWords(c)}</p>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</div>
