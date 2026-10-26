<script lang="ts">
  /**
   * Find names (`/admin/edges/find-names`; docs/edges.md "Finding names"): the
   * switch, the top-sites sweep, which networks are searched and where their
   * nodes are, imports (a pasted list or a seed file), and where candidates
   * were found. Sources are passive only: no address range is ever scanned.
   * Nothing found is added by itself.
   *
   * All wording lives in ./lib/huntWords.ts (pure, unit-tested).
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
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import { huntImportWords, parsePlace, sweepWords } from './lib/huntWords';
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
    if (done !== null) toast.success('Saved.');
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
  title="Find names"
  description="Real sites that live on one of your networks, near your nodes, to use as server names. They come from public sources only: a top-sites list looked up in DNS, the certificate a family's target shows, certificate logs, and lists you paste. No address range is ever scanned, and nothing found is used until you add it to a family."
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
      <label for={`${uid}-enabled`} class="font-medium">Find names</label>
      <p id={`${uid}-enabled-help`} class="text-muted-foreground">
        Off, nothing is looked up, checked or measured. Names found before stay here.
      </p>
    </div>
  </div>

  <Card>
    <CardHeader class="flex flex-row flex-wrap items-center justify-between gap-2">
      <CardTitle class="text-base">The top-sites sweep</CardTitle>
      {#if sweeping(h.sweep)}
        <Button variant="outline" size="sm" disabled={busy} onclick={() => run(cancelSweep)}>
          Stop the sweep
        </Button>
      {:else}
        <Button size="sm" disabled={busy || !h.config.enabled} onclick={() => run(startSweep)}>
          Start a sweep now
        </Button>
      {/if}
    </CardHeader>
    <CardContent class="space-y-1 text-sm">
      <p>{sweepWords(h.sweep)}</p>
      <p class="text-muted-foreground">
        The {h.config.depth.toLocaleString('en-US')} most visited sites are looked up in DNS, about
        {h.config.lookupsPerSecond} a second, every {h.config.sweepEveryDays} days. A name is kept when
        an address of it is on a network you search below.
      </p>
    </CardContent>
  </Card>

  <Card class="mt-6">
    <CardHeader>
      <CardTitle class="text-base">Networks</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      {#if h.networks.length === 0}
        <p class="text-muted-foreground">
          No network yet. Add one under <Link
            href={edgesPaths.names()}
            class="underline underline-offset-4">Server names</Link
          >.
        </p>
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
                    {n.candidates.total === 1 ? 'name' : 'names'} found, {n.candidates.ready} would qualify.
                    {n.ranges.v4 + n.ranges.v6 === 0 ? ' It has no address ranges yet.' : ''}
                  </p>
                </div>
                <label class="flex items-center gap-2">
                  <Switch
                    disabled={busy}
                    bind:checked={() => n.hunt.enabled, (v) => void saveHunt(n, v)}
                  />
                  <span>Search it</span>
                </label>
                <Link href={edgesPaths.findNetwork(n.slug)} class="underline underline-offset-4">
                  Open
                </Link>
              </div>
              <div class="flex flex-wrap items-end gap-2">
                <div class="space-y-1">
                  <Label for={`${uid}-${n.slug}-cc`}>Its nodes are in (country code)</Label>
                  <Input
                    id={`${uid}-${n.slug}-cc`}
                    class="w-24"
                    value={p.country}
                    placeholder="US"
                    oninput={(e) =>
                      (places = { ...places, [n.slug]: { ...p, country: e.currentTarget.value } })}
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
                Timing is measured from probes there to each site: the node relays every check of a
                name to its family's target, so a target near the node is less visible.
              </p>
            </li>
          {/each}
        </ul>
      {/if}
      {#if h.families.length > 0}
        <p class="font-medium">Found for a family</p>
        <ul class="space-y-1">
          {#each h.families as f (f.slug)}
            <li>
              <Link href={edgesPaths.family(f.slug)} class="underline underline-offset-4">
                {f.label}
              </Link>: {f.candidates.total} found, {f.candidates.ready} would qualify.
            </li>
          {/each}
        </ul>
      {/if}
    </CardContent>
  </Card>

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
            <option value="" disabled>a network or a family</option>
            {#each h.networks as n (n.slug)}
              <option value={`network:${n.slug}`}>Network {n.label}</option>
            {/each}
            {#each families.data?.families ?? [] as f (f.slug)}
              <option value={`family:${f.slug}`}>Family {f.label}</option>
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
        Names are only candidates: each is checked here, and again by its family when you add it.
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
                Family {f.label}, target <span class="font-mono">{f.targetAddress}</span>, on
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
            Then import the seed again: its names go to the families that exist by then.
          </p>
        </div>
      {/if}
    </CardContent>
  </Card>
{/if}
