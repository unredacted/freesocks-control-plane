<script lang="ts">
  /**
   * Server names, Advanced (`/admin/edges/find-names`; docs/edges.md "The
   * page"): what most setups never need, in one place. Finding names (its
   * switch, its line saying what is true now; each network's "Search it" and
   * where its nodes are, taken from a node when one of its ports was managed),
   * the top-sites search (a secondary button that says its cost first), the
   * networks, imports (a pasted list or a seed file), and checks from inside
   * countries. Sources are passive only: no address range is ever scanned.
   * Nothing found is added by itself.
   *
   * Wording lives in ./lib/huntWords.ts and ./lib/words.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import {
    cancelSweep,
    createFamily,
    createNetwork,
    familiesQuery,
    huntQuery,
    importCandidates,
    invalidateSni,
    patchSniConfig,
    setNetworkHunt,
    startSweep,
  } from '@client/lib/sniApi';
  import type { SniHuntImported, SniHuntOverview } from '../../../../../shared/contracts/sni';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import CountryChecksCard from './CountryChecksCard.svelte';
  import NetworksCard from './NetworksCard.svelte';
  import { edgesPaths } from '../lib/routes';
  import {
    huntImportWords,
    huntSwitchLine,
    parsePlace,
    placeLine,
    sweepCostWords,
    sweepWords,
  } from './lib/huntWords';
  import { sniErrorWords } from './lib/words';

  const qc = useQueryClient();
  const uid = $props.id();
  const hunt = huntQuery();
  const families = familiesQuery();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);
  const SELECT = 'border-border bg-background min-h-9 rounded-md border px-2 py-1.5 text-sm';

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

  const sweeping = (s: SniHuntOverview['sweep']) =>
    s?.state === 'running' || s?.state === 'downloading';

  // --- where a network's nodes are ------------------------------------------------------------
  let places = $state<Record<string, { country: string; city: string }>>({});
  // Networks whose place is being changed (else it is shown in one line).
  let changing = $state<string[]>([]);
  let sweepOpen = $state(false);
  const placeOf = (n: SniHuntOverview['networks'][number]) =>
    places[n.slug] ?? { country: n.hunt.place?.country ?? '', city: n.hunt.place?.city ?? '' };
  async function saveHunt(n: SniHuntOverview['networks'][number], enabled: boolean) {
    const p = placeOf(n);
    const place = p.country.trim() ? parsePlace(p.country, p.city) : null;
    if (p.country.trim() && !place) {
      toast.error(sniErrorWords('edge.network.bad_place'));
      return;
    }
    const done = await run(() => setNetworkHunt(n.slug, { enabled, ...(place ? { place } : {}) }));
    if (done !== null) {
      toast.success('Saved.');
      changing = changing.filter((s) => s !== n.slug);
    }
  }

  // --- imports -------------------------------------------------------------------------------
  let importText = $state('');
  let importScope = $state('');
  let seedMode = $state(false);
  let result = $state<SniHuntImported | null>(null);
  async function doImport() {
    let body: Parameters<typeof importCandidates>[0];
    if (seedMode) {
      let seed: unknown;
      try {
        seed = JSON.parse(importText);
      } catch {
        toast.error(sniErrorWords('edge.sni.hunt.bad_seed'));
        return;
      }
      body = { seed };
    } else {
      const [kind, slug] = importScope.split(':');
      if (!slug) return;
      body =
        kind === 'family'
          ? { family: slug, text: importText }
          : { network: slug, text: importText };
    }
    const r = await run(() => importCandidates(body));
    if (!r) return;
    result = r;
    importText = '';
    toast.success(huntImportWords(r));
  }
</script>

<p class="mb-2 text-sm">
  <Link href={edgesPaths.names()} class="text-muted-foreground underline underline-offset-4">
    Server names
  </Link>
</p>

<SectionHeader
  title="Server names: advanced"
  description="Most setups need none of this: a node's page finds names on its cover site's certificate. Here: finding names across your networks, the networks themselves, imports, and checks from inside countries. Names come from public sources only (a top-sites list looked up in DNS, certificates, certificate logs, lists you paste); no address range is ever scanned, and nothing found is used until you add it to a name list."
/>

{#if hunt.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if hunt.isError}
  <p class="text-destructive text-sm">{sniErrorWords(codeOf(hunt.error))}</p>
{:else if hunt.data}
  {@const h = hunt.data}
  <div class="mb-6 flex items-start gap-3 text-sm">
    <Switch
      id={`${uid}-enabled`}
      class="mt-0.5"
      disabled={busy}
      aria-describedby={`${uid}-enabled-help`}
      bind:checked={
        () => h.config.enabled, (v) => void run(() => patchSniConfig({ hunt: { enabled: v } }))
      }
    />
    <div>
      <label for={`${uid}-enabled`} class="font-medium">Finding names</label>
      <p id={`${uid}-enabled-help`} class="text-muted-foreground">
        {huntSwitchLine(h.config.enabled, h.config.sweepEveryDays)}
      </p>
    </div>
  </div>

  <Card class="mt-6">
    <CardHeader>
      <CardTitle class="text-base">Finding names on each network</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      {#if h.networks.length === 0}
        <p class="text-muted-foreground">No network yet. Add one under Networks below.</p>
      {:else}
        <ul class="divide-y rounded-md border" aria-label="Networks">
          {#each h.networks as n (n.slug)}
            {@const p = placeOf(n)}
            <li class="space-y-2 p-3">
              <div class="flex flex-wrap items-center justify-between gap-3">
                <div class="min-w-0 flex-1">
                  <p class="font-medium">{n.label}</p>
                  <p class="text-muted-foreground">
                    {n.candidates.total}
                    {n.candidates.total === 1 ? 'name' : 'names'} found on it, {n.candidates.ready} usable.
                    {n.ranges.v4 + n.ranges.v6 === 0 ? ' It has no address ranges yet.' : ''}
                  </p>
                </div>
                <label class="flex items-center gap-2">
                  <Switch
                    disabled={busy}
                    bind:checked={() => n.hunt.enabled, (v) => void saveHunt(n, v)}
                  />
                  <span>Include it in the top-sites search</span>
                </label>
                <Link href={edgesPaths.findNetwork(n.slug)} class="underline underline-offset-4">
                  Open
                </Link>
              </div>
              {#if n.hunt.place && !changing.includes(n.slug)}
                <p class="flex flex-wrap items-center gap-2">
                  <span class="text-muted-foreground">
                    {placeLine(n.hunt.place, n.hunt.placeFrom)}
                  </span>
                  <Button
                    variant="link"
                    size="sm"
                    class="h-auto p-0"
                    onclick={() => (changing = [...changing, n.slug])}
                  >
                    Change
                  </Button>
                </p>
              {:else}
                <div class="flex flex-wrap items-end gap-2">
                  <div class="space-y-1">
                    <Label for={`${uid}-${n.slug}-cc`}>Its nodes are in (country code)</Label>
                    <Input
                      id={`${uid}-${n.slug}-cc`}
                      class="w-24"
                      value={p.country}
                      placeholder="US"
                      oninput={(e) =>
                        (places = {
                          ...places,
                          [n.slug]: { ...p, country: e.currentTarget.value },
                        })}
                    />
                  </div>
                  <div class="space-y-1">
                    <Label for={`${uid}-${n.slug}-city`}>City (optional)</Label>
                    <Input
                      id={`${uid}-${n.slug}-city`}
                      class="w-48"
                      value={p.city}
                      oninput={(e) =>
                        (places = { ...places, [n.slug]: { ...p, city: e.currentTarget.value } })}
                    />
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onclick={() => saveHunt(n, n.hunt.enabled)}
                  >
                    Save the place
                  </Button>
                </div>
                <p class="text-muted-foreground">
                  Found names are timed from probes there: a node relays every check of a name to
                  its cover site, so a cover site near the node is less visible.
                </p>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
      {#if h.families.length > 0}
        <p class="font-medium">Found for name lists</p>
        <ul class="space-y-1">
          {#each h.families as f (f.slug)}
            <li>
              <Link href={edgesPaths.family(f.slug)} class="underline underline-offset-4">
                {f.label}
              </Link>: {f.candidates.total} found, {f.candidates.ready} usable.
            </li>
          {/each}
        </ul>
      {/if}
    </CardContent>
  </Card>

  <Card class="mt-6">
    <CardHeader class="flex flex-row flex-wrap items-center justify-between gap-2">
      <CardTitle class="text-base">The top-sites search</CardTitle>
      {#if sweeping(h.sweep)}
        <Button variant="outline" size="sm" disabled={busy} onclick={() => run(cancelSweep)}>
          Stop the search
        </Button>
      {:else}
        <Button
          variant="outline"
          size="sm"
          disabled={busy || !h.config.enabled}
          onclick={() => (sweepOpen = true)}
        >
          Search the top sites
        </Button>
      {/if}
    </CardHeader>
    <CardContent class="space-y-1 text-sm">
      <p>{sweepWords(h.sweep)}</p>
      <p class="text-muted-foreground">{sweepCostWords(h.config)}</p>
    </CardContent>
  </Card>

  <NetworksCard />

  <Card class="mt-6">
    <CardHeader>
      <CardTitle class="text-base">Import</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      <label class="flex items-center gap-2">
        <input type="checkbox" bind:checked={seedMode} />
        <span>This is a seed file (JSON from a study)</span>
      </label>
      {#if !seedMode}
        <label class="flex flex-wrap items-center gap-2">
          <span>Into</span>
          <select bind:value={importScope} class={SELECT} aria-label="Where the names go">
            <option value="" disabled>a network or a name list</option>
            {#each h.networks as n (n.slug)}
              <option value={`network:${n.slug}`}>Network {n.label}</option>
            {/each}
            {#each families.data?.families ?? [] as f (f.slug)}
              <option value={`family:${f.slug}`}>Name list {f.label}</option>
            {/each}
          </select>
        </label>
      {/if}
      <textarea
        bind:value={importText}
        rows="6"
        spellcheck="false"
        autocapitalize="off"
        aria-label={seedMode ? 'Seed file' : 'One host name per line'}
        placeholder={seedMode ? '{"networks": [...]}' : 'www.example.com'}
        class="border-input focus-visible:ring-ring/50 w-full rounded-md border bg-transparent px-3 py-2 font-mono text-sm outline-none focus-visible:ring-3"
      ></textarea>
      <p class="text-muted-foreground">
        Names are only found names: each is checked here, and again by its list when you add it.
      </p>
      <Button
        size="sm"
        disabled={busy || importText.trim() === '' || (!seedMode && !importScope)}
        onclick={doImport}
      >
        Import
      </Button>
      {#if result && (result.proposals.networks.length > 0 || result.proposals.families.length > 0)}
        <div class="space-y-2 rounded-md border p-3" aria-live="polite">
          <p class="font-medium">The seed describes these, which FCP does not have yet:</p>
          {#each result.proposals.networks as n (n.slug)}
            <div class="flex flex-wrap items-center justify-between gap-2">
              <span>Network {n.label} ({n.asns.map((a) => `AS${a}`).join(', ')})</span>
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onclick={() =>
                  run(() => createNetwork({ slug: n.slug, label: n.label, asns: n.asns }))}
              >
                Add it
              </Button>
            </div>
          {/each}
          {#each result.proposals.families as f (f.slug)}
            <div class="flex flex-wrap items-center justify-between gap-2">
              <span>
                Name list {f.label}, cover site <span class="font-mono">{f.targetAddress}</span>, on
                {f.network}
              </span>
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onclick={() =>
                  run(() =>
                    createFamily({
                      slug: f.slug,
                      label: f.label,
                      targetAddress: f.targetAddress,
                      targetPort: f.targetPort,
                      requireH2: f.requireH2,
                      network: f.network,
                    }),
                  )}
              >
                Make it
              </Button>
            </div>
          {/each}
          <p class="text-muted-foreground">
            Then import the seed again: its names go to the name lists that exist by then.
          </p>
        </div>
      {/if}
    </CardContent>
  </Card>

  <CountryChecksCard />

  <ConfirmDialog
    bind:open={sweepOpen}
    title="Search the top sites?"
    body={`${sweepCostWords(h.config)} Lookups go to ordinary DNS; nothing is sent to the sites themselves.`}
    confirmLabel="Start the search"
    onConfirm={() => {
      sweepOpen = false;
      void run(startSweep);
    }}
  />
{/if}
