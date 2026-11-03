<script lang="ts">
  /**
   * One country list (`/admin/edges/countries/lists/:id`): where it comes
   * from and when its source last confirmed it, a version waiting for you
   * (why it waits, what changed, Use it or Throw it away), the version in
   * use, fetch now or paste a new copy, the version history, and a lookup.
   *
   * Props:
   *   id: string    the list's id
   *
   * All wording lives in ./listWords.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { router } from '@client/stores/router.svelte';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent } from '@client/components/ui/card';
  import { Label } from '@client/components/ui/label';
  import { ApiCallError } from '@client/lib/api';
  import {
    countryListQuery,
    decideCountryListVersion,
    fetchCountryListNow,
    invalidateCountryLists,
    removeCountryList,
    uploadCountryList,
  } from '@client/lib/countryListsApi';
  import { UPLOAD_MAX_BYTES, type CountryListVersion } from '@shared/contracts/countryLists';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';
  import ListDialog from './ListDialog.svelte';
  import ListFeeds from './ListFeeds.svelte';
  import ListLookup from './ListLookup.svelte';
  import { countryLabel } from './words';
  import {
    countsLine,
    diffLine,
    droppedLine,
    freshnessLine,
    holdReasonWords,
    listBadge,
    listErrorWords,
    outcomeFailed,
    outcomeWords,
    REGIME_WORDS,
    sourceLine,
    STATUS_WORDS,
  } from './listWords';

  let { id }: { id: string } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const detail = countryListQuery(() => id);
  let now = $state(Date.now());
  let busy = $state(false);
  let editing = $state(false);
  let removeOpen = $state(false);
  let pasteText = $state('');
  let progress = $state<string | null>(null);
  let pasteBytes = $derived(new TextEncoder().encode(pasteText).length);

  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);
  async function run<T>(work: () => Promise<T>, done?: string): Promise<T | null> {
    busy = true;
    try {
      const r = await work();
      if (done) toast.success(done);
      return r;
    } catch (e) {
      toast.error(listErrorWords(codeOf(e)));
      return null;
    } finally {
      busy = false;
      progress = null;
      invalidateCountryLists(qc);
    }
  }

  async function paste() {
    if (!pasteText.trim() || pasteBytes > UPLOAD_MAX_BYTES) return;
    const r = await run(
      () =>
        uploadCountryList(id, pasteText, (sent, total) => {
          progress = total > 1 ? `Sending part ${sent} of ${total}…` : 'Sending…';
        }),
      'Pasted. FCP is reading it now.',
    );
    if (r !== null) pasteText = '';
  }

  const decide = (versionId: string, decision: 'approve' | 'reject') =>
    run(
      () => decideCountryListVersion(id, versionId, decision),
      decision === 'approve' ? 'That version is in use now.' : 'That version was thrown away.',
    );

  const shortCounts = (v: CountryListVersion) => countsLine(v.counts);
</script>

{#if detail.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if detail.isError}
  <SectionHeader title="Country list" back={{ href: edgesPaths.lists(), label: 'Country lists' }} />
  <p class="text-destructive text-sm">{listErrorWords(codeOf(detail.error))}</p>
{:else if detail.data}
  {@const l = detail.data.list}
  {@const badge = listBadge(l)}
  <SectionHeader
    title={l.label}
    description={`${countryLabel(l.country)}. ${REGIME_WORDS[l.regime].explain}`}
    back={{ href: edgesPaths.lists(), label: 'Country lists' }}
  >
    {#snippet badges()}
      <Badge variant={badge.tone}>{badge.label}</Badge>
    {/snippet}
    {#snippet actions()}
      <Button size="sm" variant="outline" disabled={busy} onclick={() => (editing = true)}>
        Edit
      </Button>
      <Button
        size="sm"
        variant="ghost"
        class="text-destructive"
        disabled={busy}
        onclick={() => (removeOpen = true)}
      >
        Remove
      </Button>
    {/snippet}
  </SectionHeader>

  <Card>
    <CardContent class="space-y-2 py-5 text-sm">
      <p>{sourceLine(l)} {freshnessLine(l, detail.data.staleDays, now)}</p>
      {#if l.networks.length > 0}
        <p class="text-muted-foreground">
          Covers the networks {l.networks.map((n) => `AS${n}`).join(', ')}.
        </p>
      {/if}
      {#if l.lastFetch}
        <p
          class={outcomeFailed(l.lastFetch.outcome) ? 'text-destructive' : 'text-muted-foreground'}
        >
          Last read {relativeTime(l.lastFetch.at, now)}: {outcomeWords(l.lastFetch.outcome)}
        </p>
      {/if}
      {#if l.busy}
        <p class="text-muted-foreground">Reading it now…</p>
      {/if}
      {#if l.source.kind === 'url'}
        <Button
          size="sm"
          disabled={busy || !!l.busy}
          onclick={() => void run(() => fetchCountryListNow(id), 'Fetching it now.')}
        >
          Fetch now
        </Button>
      {:else}
        <form
          class="space-y-2 pt-2"
          onsubmit={(e) => {
            e.preventDefault();
            void paste();
          }}
        >
          <Label for={`${uid}-paste`}>Paste a new copy</Label>
          <textarea
            id={`${uid}-paste`}
            bind:value={pasteText}
            rows="6"
            class="border-input bg-background w-full rounded-md border px-3 py-2 font-mono text-xs"
            placeholder="example.com&#10;*.example.org&#10;192.0.2.0/24"
            autocapitalize="off"
            spellcheck={false}
          ></textarea>
          <p class="text-muted-foreground text-xs">
            One name, wildcard, address or range per line. Lines starting with # are skipped. At
            most 4 MB: a larger list needs an address.
          </p>
          {#if pasteBytes > UPLOAD_MAX_BYTES}
            <p class="text-destructive text-xs">That is more than 4 MB.</p>
          {/if}
          <Button
            type="submit"
            size="sm"
            disabled={busy || !!l.busy || !pasteText.trim() || pasteBytes > UPLOAD_MAX_BYTES}
          >
            {progress ?? 'Send'}
          </Button>
        </form>
      {/if}
    </CardContent>
  </Card>

  {#if l.held}
    {@const h = l.held}
    <Card class="mt-4 border-amber-500/40">
      <CardContent class="space-y-2 py-5 text-sm">
        <h2 class="text-base font-medium">A version waits for you</h2>
        <p class="text-muted-foreground">Read {relativeTime(h.at, now)}.</p>
        <ul class="list-disc space-y-1 ps-5">
          {#each h.heldReasons as r (r)}<li>{holdReasonWords(r)}</li>{/each}
        </ul>
        <p>{countsLine(h.counts)}</p>
        {#if diffLine(h.diff)}<p class="text-muted-foreground">{diffLine(h.diff)}</p>{/if}
        {#if droppedLine(h.counts)}<p class="text-muted-foreground">{droppedLine(h.counts)}</p>{/if}
        {#if h.samples.length > 0}
          <div>
            <p class="text-muted-foreground">Lines it could not use, for example:</p>
            <ul class="font-mono text-xs">
              {#each h.samples as s, i (i)}<li class="break-all">{s}</li>{/each}
            </ul>
          </div>
        {/if}
        <div class="flex flex-wrap gap-2 pt-1">
          <Button size="sm" disabled={busy} onclick={() => void decide(h.id, 'approve')}>
            Use it
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onclick={() => void decide(h.id, 'reject')}
          >
            Throw it away
          </Button>
        </div>
      </CardContent>
    </Card>
  {/if}

  {#if l.active}
    <Card class="mt-4">
      <CardContent class="space-y-2 py-5 text-sm">
        <h2 class="text-base font-medium">In use</h2>
        <p>{countsLine(l.active.counts)}</p>
        {#if diffLine(l.active.diff)}
          <p class="text-muted-foreground">{diffLine(l.active.diff)}</p>
        {/if}
        {#if droppedLine(l.active.counts)}
          <p class="text-muted-foreground">{droppedLine(l.active.counts)}</p>
        {/if}
        <p class="text-muted-foreground">
          Read {relativeTime(l.active.at, now)}{l.active.byPerson
            ? ', put in use by a person'
            : ''}.
        </p>
      </CardContent>
    </Card>
  {/if}

  <ListFeeds list={l} />

  {#if detail.data.versions.length > 0}
    <Card class="mt-4">
      <CardContent class="py-5 text-sm">
        <h2 class="mb-2 text-base font-medium">Versions</h2>
        <ul class="divide-y rounded-md border" aria-label="Versions">
          {#each detail.data.versions as v (v.id)}
            <li class="flex flex-wrap items-baseline justify-between gap-2 p-3">
              <span class="min-w-0 flex-1">
                <span class="font-medium">{STATUS_WORDS[v.status]}</span>
                <span class="text-muted-foreground">
                  {relativeTime(v.at, now)}, {v.source === 'fetch' ? 'fetched' : 'pasted'}.
                  {shortCounts(v)}
                </span>
              </span>
            </li>
          {/each}
        </ul>
      </CardContent>
    </Card>
  {/if}

  <ListLookup />

  <ListDialog bind:open={editing} list={l} defaultFetchHours={l.fetchEveryHours} />
  <ConfirmDialog
    bind:open={removeOpen}
    title={`Remove the list ${l.label}?`}
    body="Its versions and history go too. Nothing that members get changes."
    confirmLabel="Remove list"
    danger
    onConfirm={async () => {
      const r = await run(() => removeCountryList(id), 'List removed.');
      if (r !== null) router.navigate(edgesPaths.lists());
    }}
  />
{/if}
