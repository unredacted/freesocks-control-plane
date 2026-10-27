<script lang="ts">
  /**
   * "Add suggestions" (docs/edges.md "Finding names"): the found names a name
   * list may add (usable: its cover site serves them, nobody decided yet),
   * best first, grouped by site so names of one site read as one entry. Each
   * row says in one line why it is worth adding; what was measured (the
   * handshakes, timing, countries, sources, the score) is under Details.
   * Adding goes through the list's normal path: each name is checked again,
   * then sent to the node like any other.
   *
   * Props: open (bindable), family (the list's short id), label.
   */
  import { createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Collapsible from '@client/components/ui/collapsible';
  import * as Dialog from '@client/components/ui/dialog';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { ApiCallError } from '@client/lib/api';
  import {
    actOnCandidates,
    addCandidates,
    fetchHuntScope,
    invalidateSni,
    sniKeys,
  } from '@client/lib/sniApi';
  import type { SniCandidateRow } from '../../../../../shared/contracts/sni';
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { countryWords, extraWords, nearWords, scoreWords, sourcesWords } from './lib/huntWords';
  import { addedWords, offerable, suggestionReason } from './lib/transportWords';
  import { sniErrorWords } from './lib/words';

  let {
    open = $bindable(false),
    family,
    label,
  }: { open: boolean; family: string; label: string } = $props();
  const qc = useQueryClient();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  // The first page of the list's undecided finds, best first (200: more than anyone adds at once).
  const found = createQuery(() => ({
    queryKey: [...sniKeys.hunt, 'suggestions', family] as const,
    queryFn: () => fetchHuntScope('family', family, 'new'),
    enabled: open,
  }));
  let rows = $derived(offerable(found.data?.candidates ?? []));
  // One entry per site, in the order of its best name.
  let sites = $derived.by(() => {
    const by = new Map<string, SniCandidateRow[]>();
    for (const r of rows) by.set(r.site, [...(by.get(r.site) ?? []), r]);
    return [...by.entries()].map(([site, names]) => ({ site, names }));
  });

  let picked = $state<string[]>([]);
  let seeded = $state(false);
  $effect(() => {
    if (!open) {
      seeded = false;
      return;
    }
    // Everything offered starts picked; unpick what you do not want.
    if (!seeded && found.data) {
      picked = rows.map((r) => r.id);
      seeded = true;
    }
  });
  const toggle = (id: string, on: boolean) =>
    (picked = on ? [...picked, id] : picked.filter((x) => x !== id));

  let busy = $state(false);
  async function add() {
    const names = rows.filter((r) => picked.includes(r.id)).map((r) => r.name);
    busy = true;
    try {
      let added = 0;
      const lines = [];
      for (let i = 0; i < names.length; i += 500) {
        const r = await addCandidates(family, names.slice(i, i + 500));
        added += r.added;
        lines.push(...r.lines);
      }
      open = false;
      toast.success(addedWords({ added, lines }));
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }
  async function ignore(c: SniCandidateRow) {
    try {
      await actOnCandidates('ignore', [c.id], 'name');
      picked = picked.filter((x) => x !== c.id);
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      invalidateSni(qc);
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-2xl`}>
    <Dialog.Header>
      <Dialog.Title>Add suggestions</Dialog.Title>
      <Dialog.Description>
        More names the cover site serves, found on its certificate, in certificate logs or in lists
        you added to {label}. Best first.
      </Dialog.Description>
    </Dialog.Header>

    {#if found.isPending}
      <div class="space-y-2"><Skeleton class="h-10 w-full" /><Skeleton class="h-10 w-full" /></div>
    {:else if found.isError}
      <p class="text-destructive text-sm">{sniErrorWords(codeOf(found.error))}</p>
    {:else if rows.length === 0}
      <p class="text-muted-foreground text-sm">No suggestion is waiting right now.</p>
    {:else}
      <div class="flex items-center gap-2 text-sm">
        <Checkbox
          checked={picked.length === rows.length}
          onCheckedChange={(v) => (picked = v === true ? rows.map((r) => r.id) : [])}
          aria-label="Pick every suggestion"
        />
        <span class="text-muted-foreground">{picked.length} of {rows.length} picked</span>
      </div>
      <ul class="divide-y rounded-md border text-sm" aria-label="Suggestions">
        {#each sites as s (s.site)}
          <li class="p-3">
            {#if s.names.length > 1}
              <p class="text-muted-foreground mb-1 text-xs">{s.site}, {s.names.length} names</p>
            {/if}
            <ul class="space-y-2">
              {#each s.names as c (c.id)}
                {@const extra = extraWords(c)}
                {@const countries = countryWords(c)}
                <li class="flex items-start gap-3">
                  <Checkbox
                    class="mt-0.5"
                    checked={picked.includes(c.id)}
                    onCheckedChange={(v) => toggle(c.id, v === true)}
                    aria-label={`Pick ${c.name}`}
                  />
                  <div class="min-w-0 flex-1">
                    <p class="font-mono break-all">{c.name}</p>
                    <p class="text-muted-foreground">{suggestionReason(c)}</p>
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
                        <p>
                          The cover site serves it{c.check?.tlsVersion === 'TLSv1.3'
                            ? ' over TLS 1.3'
                            : ''}{c.check?.alpn === 'h2' ? ' and HTTP/2' : ''}.
                        </p>
                        {#if extra}<p>{extra}</p>{/if}
                        <p>{nearWords(c, true)}</p>
                        {#if countries.length > 0}<p>{countries.join(' · ')}</p>{/if}
                        <p>Found in: {sourcesWords(c)}.</p>
                        <p>{scoreWords(c)}</p>
                      </Collapsible.Content>
                    </Collapsible.Root>
                  </div>
                  <Button variant="ghost" size="sm" onclick={() => ignore(c)}>Ignore</Button>
                </li>
              {/each}
            </ul>
          </li>
        {/each}
      </ul>
    {/if}

    <Dialog.Footer class={STICKY_FOOTER}>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button disabled={busy || picked.length === 0} onclick={add}>
        {busy ? 'Adding…' : `Add ${picked.length === 1 ? '1 name' : `${picked.length} names`}`}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
