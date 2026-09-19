<script lang="ts">
  /**
   * One family (`/admin/edges/names/:slug`): its names and what each one's last
   * check said, the operator's per-country judgement, and the inbounds it is
   * bound to with their rollouts (BindingCard).
   *
   * All wording lives in ./lib/words.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import { fetchServerSummary, fetchServerTree } from '@client/lib/serversApi';
  import {
    actOnNames,
    bindFamily,
    familyQuery,
    importNames,
    invalidateSni,
    judgeNames,
    removeFamily,
    updateFamily,
    type NameAction,
  } from '@client/lib/sniApi';
  import { router } from '@client/stores/router.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import BindingCard from './BindingCard.svelte';
  import {
    FILTER_LABEL,
    NAME_FILTERS,
    importWords,
    matchesFilter,
    nameWords,
    sniErrorWords,
    suspectWords,
    type Dot,
    type NameFilter,
  } from './lib/words';

  let { slug }: { slug: string } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const family = familyQuery(() => slug);
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  const DOT: Record<Dot, string> = {
    green: 'bg-emerald-500',
    amber: 'bg-amber-500',
    red: 'bg-destructive',
    grey: 'bg-muted-foreground/50',
  };
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

  // --- names -------------------------------------------------------------------------------------
  let filter = $state<NameFilter>('all');
  let picked = $state<string[]>([]);
  let shown = $derived((family.data?.names ?? []).filter((n) => matchesFilter(n, filter)));
  let allPicked = $derived(shown.length > 0 && shown.every((n) => picked.includes(n.name)));
  const toggle = (name: string, on: boolean) =>
    (picked = on ? [...picked, name] : picked.filter((n) => n !== name));
  const toggleAll = (on: boolean) => (picked = on ? shown.map((n) => n.name) : []);

  let burnOpen = $state(false);
  async function act(action: NameAction) {
    const names = [...picked];
    if ((await run(() => actOnNames(slug, action, names))) !== null) picked = [];
  }

  let country = $state('');
  async function judge(state: 'proven' | 'blocked' | 'unknown') {
    if (!country) return;
    const names = [...picked];
    if ((await run(() => judgeNames(slug, names, country, state))) !== null) picked = [];
  }

  let importText = $state('');
  let importResult = $state<string[]>([]);
  async function doImport() {
    const r = await run(() => importNames(slug, importText));
    if (!r) return;
    importResult = importWords(r);
    importText = '';
  }

  // --- the family itself -----------------------------------------------------------------------
  let removeOpen = $state(false);
  const setEnabled = (enabled: boolean) => run(() => updateFamily(slug, { enabled }));
  async function remove() {
    removeOpen = false;
    if ((await run(() => removeFamily(slug))) !== null) router.navigate(edgesPaths.names());
  }

  // --- binding to an inbound -------------------------------------------------------------------
  let bindOpen = $state(false);
  let backends = $state<{ slug: string; name: string }[]>([]);
  let backendSlug = $state('');
  let inbounds = $state<{ tag: string; target: string | null }[]>([]);
  let inboundTag = $state('');

  async function startBind() {
    bindOpen = true;
    const s = await run(fetchServerSummary);
    backends = (s?.instances ?? [])
      .filter((i) => i.observable)
      .map(({ slug, name }) => ({ slug, name }));
    backendSlug = backends[0]?.slug ?? '';
    await loadInbounds();
  }
  async function loadInbounds() {
    inbounds = [];
    inboundTag = '';
    if (!backendSlug) return;
    const tree = await run(() => fetchServerTree(backendSlug));
    inbounds = (tree?.profiles ?? [])
      .flatMap((p) => p.inbounds)
      .filter((i) => i.security === 'reality')
      .map((i) => ({ tag: i.tag, target: i.realityTarget }));
    inboundTag = inbounds[0]?.tag ?? '';
  }
  async function bind() {
    if ((await run(() => bindFamily(slug, backendSlug, inboundTag))) !== null) bindOpen = false;
  }
</script>

<p class="mb-2 text-sm">
  <Link href={edgesPaths.names()} class="text-muted-foreground underline underline-offset-4">
    Server names
  </Link>
</p>

{#if family.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if family.isError}
  <p class="text-destructive text-sm">{sniErrorWords(codeOf(family.error))}</p>
{:else if family.data}
  {@const f = family.data.family}
  <SectionHeader
    title={f.label}
    description={`Names served by ${f.target.address}:${f.target.port}${f.requireH2 ? ', over HTTP/2 only' : ''}.`}
  >
    {#snippet actions()}
      <Button variant="ghost" size="sm" disabled={busy} onclick={() => (removeOpen = true)}>
        Remove
      </Button>
    {/snippet}
  </SectionHeader>

  <div class="mb-6 flex items-start gap-3 text-sm">
    <Switch
      id={`${uid}-enabled`}
      class="mt-0.5"
      disabled={busy}
      aria-describedby={`${uid}-enabled-help`}
      bind:checked={() => f.enabled, (v) => void setEnabled(v)}
    />
    <div>
      <label for={`${uid}-enabled`} class="font-medium">Use this family</label>
      <p id={`${uid}-enabled-help`} class="text-muted-foreground">
        Off, nothing new is written for it. The names members already have keep working.
      </p>
    </div>
  </div>

  <Card>
    <CardHeader class="flex flex-row flex-wrap items-center justify-between gap-2">
      <CardTitle class="text-base">Where it is used</CardTitle>
      <Button variant="outline" size="sm" disabled={busy} onclick={startBind}>
        Bind to an inbound
      </Button>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      {#if bindOpen}
        <form
          class="bg-muted/30 flex flex-wrap items-end gap-3 rounded-md border p-3"
          onsubmit={(e) => {
            e.preventDefault();
            void bind();
          }}
        >
          <label>
            <span class="text-muted-foreground mb-1 block">Server</span>
            <select bind:value={backendSlug} onchange={loadInbounds} class={SELECT}>
              {#each backends as b (b.slug)}
                <option value={b.slug}>{b.name}</option>
              {/each}
            </select>
          </label>
          <label>
            <span class="text-muted-foreground mb-1 block">REALITY inbound</span>
            <select bind:value={inboundTag} class={SELECT}>
              {#each inbounds as i (i.tag)}
                <option value={i.tag}>{i.tag}{i.target ? ` (${i.target})` : ''}</option>
              {/each}
            </select>
          </label>
          <Button type="submit" size="sm" disabled={busy || !inboundTag}>Bind</Button>
          <Button type="button" variant="ghost" size="sm" onclick={() => (bindOpen = false)}>
            Cancel
          </Button>
          <p class="text-muted-foreground basis-full">
            The inbound's target site has to be this family's target. Binding writes nothing: the
            names already on the inbound are remembered as having been there.
          </p>
        </form>
      {/if}
      {#if family.data.bindings.length === 0}
        <p class="text-muted-foreground">Not bound to any inbound yet.</p>
      {/if}
      {#each family.data.bindings as b (b.id)}
        <BindingCard binding={b} />
      {/each}
    </CardContent>
  </Card>

  <Card class="mt-6">
    <CardHeader>
      <CardTitle class="text-base">Names</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      <div class="flex flex-wrap gap-2" role="group" aria-label="Show">
        {#each NAME_FILTERS as id (id)}
          <Button
            variant={filter === id ? 'default' : 'outline'}
            size="sm"
            aria-pressed={filter === id}
            onclick={() => {
              filter = id;
              picked = [];
            }}
          >
            {FILTER_LABEL[id]}
          </Button>
        {/each}
      </div>

      {#if picked.length > 0}
        <div class="bg-muted/30 flex flex-wrap items-center gap-2 rounded-md border p-2">
          <span class="px-1">{picked.length} picked</span>
          <Button variant="outline" size="sm" disabled={busy} onclick={() => act('recheck')}>
            Check again
          </Button>
          <Button variant="outline" size="sm" disabled={busy} onclick={() => act('retire')}>
            Retire
          </Button>
          <Button variant="outline" size="sm" disabled={busy} onclick={() => act('reactivate')}>
            Bring back
          </Button>
          <Button variant="outline" size="sm" disabled={busy} onclick={() => (burnOpen = true)}>
            Burn
          </Button>
          <span class="ms-auto flex flex-wrap items-center gap-2">
            <label class="flex items-center gap-2">
              <span class="text-muted-foreground">In</span>
              <select bind:value={country} class={SELECT} aria-label="Country">
                <option value="" disabled>country</option>
                {#each family.data.curatedCountries as c (c)}
                  <option value={c}>{c}</option>
                {/each}
              </select>
            </label>
            <Button
              variant="outline"
              size="sm"
              disabled={busy || !country}
              onclick={() => judge('proven')}
            >
              Works there
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={busy || !country}
              onclick={() => judge('blocked')}
            >
              Blocked there
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={busy || !country}
              onclick={() => judge('unknown')}
            >
              Not known
            </Button>
          </span>
        </div>
      {/if}

      {#if shown.length === 0}
        <p class="text-muted-foreground">Nothing to show here.</p>
      {:else}
        <div class="flex items-center gap-2 border-b pb-2">
          <Checkbox
            id={`${uid}-all`}
            checked={allPicked}
            onCheckedChange={(v) => toggleAll(v === true)}
          />
          <Label for={`${uid}-all`} class="font-normal">All {shown.length} shown</Label>
        </div>
        <ul class="divide-y">
          {#each shown as n (n.name)}
            {@const w = nameWords(n)}
            <li class="flex items-start gap-3 py-2">
              <Checkbox
                id={`${uid}-${n.name}`}
                class="mt-0.5"
                checked={picked.includes(n.name)}
                onCheckedChange={(v) => toggle(n.name, v === true)}
              />
              <span
                class={`mt-1.5 inline-block size-2.5 shrink-0 rounded-full ${DOT[w.dot]}`}
                aria-hidden="true"
              ></span>
              <span class="min-w-0 flex-1">
                <Label for={`${uid}-${n.name}`} class="block font-medium break-all">{n.name}</Label>
                <span class="text-muted-foreground block">{w.sentence}</span>
                {#if n.suspectIn.length > 0}
                  <span class="block text-amber-700 dark:text-amber-400">
                    {suspectWords(n.suspectIn)}
                  </span>
                {/if}
                {#if n.provenIn.length > 0 || n.blockedIn.length > 0}
                  <span class="block">
                    {#if n.provenIn.length > 0}Works in {n.provenIn.join(', ')}.{/if}
                    {#if n.blockedIn.length > 0}
                      <span class="text-destructive">Blocked in {n.blockedIn.join(', ')}.</span>
                    {/if}
                  </span>
                {/if}
              </span>
            </li>
          {/each}
        </ul>
      {/if}
    </CardContent>
  </Card>

  <Card class="mt-6">
    <CardHeader>
      <CardTitle class="text-base">Add names</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      <Label for={`${uid}-import`}>One host name per line</Label>
      <textarea
        id={`${uid}-import`}
        bind:value={importText}
        rows="6"
        spellcheck="false"
        autocapitalize="off"
        class="border-input focus-visible:ring-ring/50 w-full rounded-md border bg-transparent px-3 py-2 font-mono text-sm outline-none focus-visible:ring-3"
      ></textarea>
      <p class="text-muted-foreground">
        Only add names the target site really serves, with a valid certificate. Each one is checked
        before it can be used, and a name belongs to one family only.
      </p>
      <Button size="sm" disabled={busy || importText.trim() === ''} onclick={doImport}>Add</Button>
      {#if importResult.length > 0}
        <ul aria-live="polite">
          {#each importResult as line (line)}
            <li>{line}</li>
          {/each}
        </ul>
      {/if}
    </CardContent>
  </Card>
{/if}

<ConfirmDialog
  bind:open={burnOpen}
  title={`Burn ${picked.length} ${picked.length === 1 ? 'name' : 'names'}?`}
  body="A burned name stops being given to members at once, on every node, even when it is a node's last name. It can never be used again, in this family or any other."
  typed="burn"
  confirmLabel="Burn"
  danger
  onConfirm={() => {
    burnOpen = false;
    void act('burn');
  }}
/>
<ConfirmDialog
  bind:open={removeOpen}
  title="Remove this family?"
  body="A family an inbound still uses is not removed. Unbind it first."
  confirmLabel="Remove"
  danger
  onConfirm={remove}
/>
