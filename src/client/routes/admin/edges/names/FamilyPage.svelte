<script lang="ts">
  /**
   * One name list (`/admin/edges/names/:slug`; docs/edges.md "The page"): the
   * ports it is used on, each with its status and next step (FamilyPort), then
   * ONE list of its names and the names found for it, each with one state on
   * the way to members (lib/listWords.ts): Suggested, Being checked, Waiting
   * to be sent, Waiting for a test, In use; Failing, Retired, Burned,
   * Ignored, Not usable. Three filters. What was measured is under Details.
   *
   * Picked names can be checked again, retired (confirmed: it states the name
   * drain, `edge.sniDrainMinutes`), brought back, burned (typed), or marked
   * for a curated country. Adding names by hand and the list's settings sit
   * below, folded away.
   *
   * Wording lives in ./lib/listWords.ts, ./lib/transportWords.ts and
   * ./lib/words.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Collapsible from '@client/components/ui/collapsible';
  import { Label } from '@client/components/ui/label';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import { fetchServerSummary, fetchServerTree } from '@client/lib/serversApi';
  import { edgeConfigQuery } from '@client/lib/edgesApi';
  import {
    actOnCandidates,
    actOnNames,
    addCandidates,
    applyVantage,
    bindFamily,
    checkNamesFrom,
    familyFindsQuery,
    familyQuery,
    importNames,
    invalidateSni,
    judgeNames,
    lookUpCt,
    networksQuery,
    readTargetCert,
    removeFamily,
    sniConfigQuery,
    updateFamily,
    type NameAction,
  } from '@client/lib/sniApi';
  import { router } from '@client/stores/router.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import { drainLength } from '../simple/drainWords';
  import StatusDot from '../simple/StatusDot.svelte';
  import AddSuggestionsDialog from './AddSuggestionsDialog.svelte';
  import FamilyPort from './FamilyPort.svelte';
  import { countryWords, extraWords, nearWords, scoreWords, sourcesWords } from './lib/huntWords';
  import {
    LIST_FILTERS,
    LIST_FILTER_LABEL,
    checksWantWords,
    STATE_LABEL,
    listRows,
    listSwitchLine,
    matchesListFilter,
    nameActionWords,
    type ListFilter,
  } from './lib/listWords';
  import { addedWords, lookedWords } from './lib/transportWords';
  import {
    CHECK_WORDS,
    ago,
    sniErrorWords,
    suspectWords,
    vantageAppliedWords,
    vantageLine,
    vantageRequestedWords,
    vantageSuggestionWords,
  } from './lib/words';

  let { slug }: { slug: string } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const family = familyQuery(() => slug);
  const config = sniConfigQuery();
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

  // --- the one list ------------------------------------------------------------------------------
  let filter = $state<ListFilter>('needs_you');
  // Suggestions and finds being checked; everything found only under All.
  const suggestions = familyFindsQuery(
    () => slug,
    () => 'new',
  );
  const everything = familyFindsQuery(
    () => slug,
    () => 'all',
    () => filter === 'all',
  );
  let found = $derived(
    (filter === 'all' ? everything.data?.candidates : suggestions.data?.candidates) ?? [],
  );
  let rows = $derived(
    listRows(family.data?.names ?? [], found, (family.data?.bindings.length ?? 0) > 0),
  );
  let counts = $derived(
    Object.fromEntries(
      LIST_FILTERS.map((f) => [f, rows.filter((r) => matchesListFilter(r, f)).length]),
    ) as Record<ListFilter, number>,
  );
  let shown = $derived(rows.filter((r) => matchesListFilter(r, filter)));
  let suggestionCount = $derived(rows.filter((r) => r.state === 'suggested').length);

  // Picking is for the list's own names (the finds have their own buttons).
  let picked = $state<string[]>([]);
  let pickable = $derived(shown.filter((r) => r.row.kind === 'name').map((r) => r.name));
  let allPicked = $derived(pickable.length > 0 && pickable.every((n) => picked.includes(n)));
  const toggle = (name: string, on: boolean) =>
    (picked = on ? [...picked, name] : picked.filter((n) => n !== name));

  let burnOpen = $state(false);
  let retireOpen = $state(false);
  const edgeConfig = edgeConfigQuery();
  let nameDrain = $derived(
    edgeConfig.data ? drainLength(edgeConfig.data.config.sniDrainMinutes) : 'the name drain time',
  );
  async function act(action: NameAction) {
    const names = [...picked];
    const r = await run(() => actOnNames(slug, action, names));
    if (r === null) return;
    picked = [];
    const words = nameActionWords(action, r as Parameters<typeof nameActionWords>[1]);
    if (words.includes('busy')) toast.warning(words);
    else toast.success(words);
  }

  // --- a found name: add it, ignore it, or take it back ---------------------------------------
  async function addOne(name: string) {
    const r = await run(() => addCandidates(slug, [name]));
    if (r) toast.success(addedWords(r, (family.data?.bindings.length ?? 0) > 0));
  }
  const findAction = (id: string, action: 'ignore' | 'unignore' | 'recheck') =>
    run(() => actOnCandidates(action, [id], action === 'ignore' ? 'name' : undefined));

  let addOpen = $state(false);
  async function lookForMore() {
    const f = family.data?.family;
    if (!f) return;
    const r = await run(async () => {
      const cert = await readTargetCert(slug);
      const host = f.target.address;
      const literal = /^[\d.]+$/.test(host) || host.includes(':');
      const ct = literal ? null : await lookUpCt([host], { family: slug });
      return { cert, ct };
    });
    if (!r) return;
    if (r.cert.ok) toast.success(lookedWords(r.cert, r.ct));
    else toast.error(CHECK_WORDS[r.cert.code ?? ''] ?? 'The cover site could not be read.');
  }

  // --- a curated country: marks, and checks from inside it -------------------------------------
  let country = $state('');
  async function judge(state: 'proven' | 'blocked' | 'unknown') {
    if (!country) return;
    const names = [...picked];
    if ((await run(() => judgeNames(slug, names, country, state))) !== null) picked = [];
  }
  let canCheck = $derived(
    !!family.data?.vantage.enabled && (family.data?.vantage.countries ?? []).includes(country),
  );
  async function checkNow() {
    if (!country) return;
    const r = await run(() => checkNamesFrom(slug, [...picked], country));
    if (r) toast.success(vantageRequestedWords(r));
  }
  async function applyChecks(names: string[], where: string) {
    const r = await run(() => applyVantage(slug, names, where));
    if (r) toast.success(vantageAppliedWords(r));
  }

  // --- adding by hand ---------------------------------------------------------------------------
  let importText = $state('');
  async function doImport() {
    const r = await run(() => importNames(slug, importText));
    if (!r) return;
    toast.success(addedWords(r, (family.data?.bindings.length ?? 0) > 0));
    importText = '';
  }

  // --- the list itself -------------------------------------------------------------------------
  let removeOpen = $state(false);
  const setEnabled = (enabled: boolean) => run(() => updateFamily(slug, { enabled }));
  const setRequireH2 = (requireH2: boolean) => run(() => updateFamily(slug, { requireH2 }));
  const networks = networksQuery();
  const setNetwork = (network: string | null) => run(() => updateFamily(slug, { network }));
  async function remove() {
    removeOpen = false;
    if ((await run(() => removeFamily(slug))) !== null) router.navigate(edgesPaths.names());
  }

  // --- using it on a port by hand (the node page's "Manage" is the usual way) ------------------
  let bindOpen = $state(false);
  let backends = $state<{ slug: string; name: string }[]>([]);
  let backendSlug = $state('');
  let transports = $state<{ tag: string; uuid: string; target: string | null; names: string[] }[]>(
    [],
  );
  let transportUuid = $state('');
  let takeNames = $state(true);
  let chosen = $derived(transports.find((t) => t.uuid === transportUuid) ?? null);
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
    transports = [];
    transportUuid = '';
    if (!backendSlug) return;
    const tree = await run(() => fetchServerTree(backendSlug));
    transports = (tree?.profiles ?? [])
      .flatMap((p) => p.transports)
      .filter((i) => i.security === 'reality')
      .map((i) => ({
        tag: i.tag,
        uuid: i.transportUuid,
        target: i.realityTarget,
        names: i.serverNames ?? [],
      }));
    transportUuid = transports[0]?.uuid ?? '';
  }
  async function bind() {
    const t = chosen;
    if (!t) return;
    const done = await run(() =>
      bindFamily(slug, backendSlug, t.tag, { transportUuid: t.uuid, takeNames }),
    );
    if (done === null) return;
    bindOpen = false;
    if (done.imported) toast.message(addedWords(done.imported));
  }
</script>

{#snippet details(title: string)}
  <Collapsible.Trigger
    class="group text-muted-foreground hover:text-foreground flex min-h-11 items-center gap-1 text-xs sm:min-h-0"
  >
    <ChevronRight
      class="size-3.5 transition-transform group-data-[state=open]:rotate-90"
      aria-hidden="true"
    />
    {title}
  </Collapsible.Trigger>
{/snippet}

<p class="mb-2 text-sm">
  <Link href={edgesPaths.names()} class="text-muted-foreground underline underline-offset-4">
    Server names
  </Link>
</p>

{#if family.isPending}
  <div class="space-y-3"><Skeleton class="h-6 w-72" /><Skeleton class="h-32 w-full" /></div>
{:else if family.isError}
  <p class="text-destructive text-sm">{sniErrorWords(codeOf(family.error))}</p>
{:else if family.data}
  {@const f = family.data.family}
  <SectionHeader
    title={f.label}
    description={`Names the cover site ${f.target.address}:${f.target.port} serves${f.requireH2 ? ', over HTTP/2' : ''}${f.network ? `, on ${f.network.label}` : ''}.`}
  />

  <section class="space-y-3" aria-labelledby={`${uid}-ports`}>
    <h2 id={`${uid}-ports`} class="text-base font-semibold">Where it is used</h2>
    {#if !f.enabled}
      <p class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
        {listSwitchLine(false)} Turn it on under Settings below.
      </p>
    {/if}
    {#each family.data.bindings as b (b.id)}
      <FamilyPort binding={b} />
    {:else}
      <p class="text-muted-foreground text-sm">
        Not used by any port yet. Open a node under Servers and choose "Manage these names with FCP"
        on its REALITY transport, or use it on a port under Settings below.
      </p>
    {/each}
  </section>

  <Card class="mt-6">
    <CardHeader class="flex flex-row flex-wrap items-center justify-between gap-2">
      <CardTitle class="text-base">Names</CardTitle>
      <div class="flex flex-wrap gap-2">
        <!-- A port using the list offers it as its next step already. -->
        {#if suggestionCount > 0 && family.data.bindings.length === 0}
          <Button size="sm" disabled={busy} onclick={() => (addOpen = true)}>
            Add suggestions ({suggestionCount})
          </Button>
        {/if}
        <Button
          variant="outline"
          size="sm"
          disabled={busy || !config.data?.hunt?.enabled}
          title={config.data?.hunt?.enabled ? undefined : 'Finding names is off'}
          onclick={lookForMore}
        >
          Look for more names
        </Button>
      </div>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      <div class="flex flex-wrap gap-2" role="group" aria-label="Show">
        {#each LIST_FILTERS as id (id)}
          <Button
            variant={filter === id ? 'default' : 'outline'}
            size="sm"
            aria-pressed={filter === id}
            onclick={() => {
              filter = id;
              picked = [];
            }}
          >
            {LIST_FILTER_LABEL[id]}{id === 'all' && !everything.data ? '' : ` ${counts[id]}`}
          </Button>
        {/each}
      </div>

      {#if picked.length > 0}
        <div class="bg-muted/30 space-y-2 rounded-md border p-2">
          <div class="flex flex-wrap items-center gap-2">
            <span class="px-1">{picked.length} picked</span>
            <Button variant="outline" size="sm" disabled={busy} onclick={() => act('recheck')}>
              Check again
            </Button>
            <Button variant="outline" size="sm" disabled={busy} onclick={() => (retireOpen = true)}>
              Retire
            </Button>
            <Button variant="outline" size="sm" disabled={busy} onclick={() => act('reactivate')}>
              Bring back
            </Button>
            <Button variant="outline" size="sm" disabled={busy} onclick={() => (burnOpen = true)}>
              Burn
            </Button>
          </div>
          {#if family.data.curatedCountries.length > 0}
            <Collapsible.Root>
              {@render details('For a country')}
              <Collapsible.Content class="mt-2 flex flex-wrap items-center gap-2">
                <select bind:value={country} class={SELECT} aria-label="Country">
                  <option value="" disabled>country</option>
                  {#each family.data.curatedCountries as c (c)}
                    <option value={c}>{c}</option>
                  {/each}
                </select>
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
                {#if family.data.vantage.enabled}
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={busy || !canCheck || picked.length > 6}
                    title={canCheck ? undefined : 'Pick a country turned on for checks'}
                    onclick={checkNow}
                  >
                    Check from there now
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={busy || !country}
                    onclick={() => applyChecks([...picked], country)}
                  >
                    Apply what the checks suggest
                  </Button>
                {/if}
              </Collapsible.Content>
            </Collapsible.Root>
          {/if}
        </div>
      {/if}

      {#if (filter === 'all' ? everything : suggestions).isError}
        <p class="text-destructive">
          The names found for this list could not be read: {sniErrorWords(
            codeOf((filter === 'all' ? everything : suggestions).error),
          )}
        </p>
      {/if}
      {#if filter === 'all' && everything.isPending}
        <Skeleton class="h-24 w-full" />
      {:else if shown.length === 0 && !(filter === 'all' ? everything : suggestions).isError}
        <p class="text-muted-foreground">
          {filter === 'needs_you'
            ? 'Nothing to do here.'
            : filter === 'in_use'
              ? 'No name of this list is in use yet.'
              : 'No names yet.'}
        </p>
      {:else}
        {#if pickable.length > 0}
          <div class="flex items-center gap-2 border-b pb-2">
            <Checkbox
              id={`${uid}-all`}
              checked={allPicked}
              onCheckedChange={(v) => (picked = v === true ? [...pickable] : [])}
            />
            <Label for={`${uid}-all`} class="font-normal">
              Pick the {pickable.length === 1 ? 'name' : `${pickable.length} names`} shown
            </Label>
          </div>
        {/if}
        <ul class="divide-y" aria-label="Names">
          {#each shown as r (r.key)}
            <li class="flex items-start gap-3 py-2">
              {#if r.row.kind === 'name'}
                {@const n = r.row.name}
                <Checkbox
                  class="mt-0.5"
                  checked={picked.includes(r.name)}
                  onCheckedChange={(v) => toggle(r.name, v === true)}
                  aria-label={`Pick ${r.name}`}
                />
                <div class="min-w-0 flex-1">
                  <p class="flex flex-wrap items-center gap-2">
                    <StatusDot dot={r.dot} />
                    <span class="font-mono break-words">{r.name}</span>
                    <span class="text-muted-foreground text-xs">{STATE_LABEL[r.state]}</span>
                  </p>
                  <p class="text-muted-foreground">{r.sentence}</p>
                  {#if n.suspectIn.length > 0}
                    <p class="text-amber-700 dark:text-amber-400">{suspectWords(n.suspectIn)}</p>
                  {/if}
                  {#if checksWantWords(n)}
                    <p class="text-amber-700 dark:text-amber-400">{checksWantWords(n)}</p>
                  {/if}
                  {#if n.provenIn.length > 0 || n.blockedIn.length > 0}
                    <p>
                      {#if n.provenIn.length > 0}Works in {n.provenIn.join(', ')}.{/if}
                      {#if n.blockedIn.length > 0}
                        <span class="text-destructive">Blocked in {n.blockedIn.join(', ')}.</span>
                      {/if}
                    </p>
                  {/if}
                  <Collapsible.Root>
                    {@render details('Details')}
                    <Collapsible.Content class="text-muted-foreground mt-1 space-y-1 text-xs">
                      <p>
                        {n.qualification === 'ok'
                          ? `The cover site serves it${n.tlsVersion === 'TLSv1.3' ? ' over TLS 1.3' : ''}${n.alpn === 'h2' ? ' and HTTP/2' : ''}. Checked ${ago(n.checkedAt)}.`
                          : n.qualification === 'pending'
                            ? 'Waiting for its first check against the cover site.'
                            : `Not served by the cover site at its last check, ${ago(n.checkedAt)}.`}
                      </p>
                      {#if n.probeMarkedIn.length > 0}
                        <p>Marked by the checks from inside {n.probeMarkedIn.join(', ')}.</p>
                      {/if}
                      {#each n.vantage as v (v.country)}
                        {@const said = vantageSuggestionWords(v)}
                        <p>
                          {vantageLine(v)}
                          {#if said}{said}{/if}
                          {#if v.decision === 'suggest' || v.decision === 'conflict'}
                            <Button
                              variant="link"
                              size="sm"
                              class="h-auto p-0 align-baseline text-xs"
                              disabled={busy}
                              onclick={() => applyChecks([n.name], v.country)}
                            >
                              {v.decision === 'conflict' ? 'Use the checks instead' : 'Apply'}
                            </Button>
                          {/if}
                        </p>
                      {/each}
                    </Collapsible.Content>
                  </Collapsible.Root>
                </div>
              {:else}
                {@const c = r.row.found}
                {@const extra = extraWords(c)}
                {@const places = countryWords(c)}
                <span class="w-4 shrink-0" aria-hidden="true"></span>
                <div class="min-w-0 flex-1">
                  <p class="flex flex-wrap items-center gap-2">
                    <StatusDot dot={r.dot} />
                    <span class="font-mono break-words">{r.name}</span>
                    <span class="text-muted-foreground text-xs">{STATE_LABEL[r.state]}</span>
                  </p>
                  <p class="text-muted-foreground">{r.sentence}</p>
                  <Collapsible.Root>
                    {@render details('Details')}
                    <Collapsible.Content class="text-muted-foreground mt-1 space-y-0.5 text-xs">
                      {#if extra}<p>{extra}</p>{/if}
                      <p>{nearWords(c, true)}</p>
                      {#if places.length > 0}<p>{places.join(' · ')}</p>{/if}
                      <p>Found in: {sourcesWords(c)}.</p>
                      <p>{scoreWords(c)}</p>
                    </Collapsible.Content>
                  </Collapsible.Root>
                </div>
                <div class="flex shrink-0 flex-wrap gap-2">
                  {#if r.state === 'suggested'}
                    <Button size="sm" disabled={busy} onclick={() => addOne(c.name)}>Add</Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={busy}
                      onclick={() => findAction(c.id, 'ignore')}
                    >
                      Ignore
                    </Button>
                  {:else if r.state === 'ignored'}
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={busy}
                      onclick={() => findAction(c.id, 'unignore')}
                    >
                      Stop ignoring
                    </Button>
                  {:else if r.state === 'not_usable'}
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={busy}
                      onclick={() => findAction(c.id, 'recheck')}
                    >
                      Check again
                    </Button>
                  {/if}
                </div>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </CardContent>
  </Card>

  <Collapsible.Root class="mt-6 rounded-lg border p-4 text-sm">
    <Collapsible.Trigger
      class="group flex min-h-11 w-full items-center gap-2 font-medium sm:min-h-0"
    >
      <ChevronRight
        class="size-4 transition-transform group-data-[state=open]:rotate-90"
        aria-hidden="true"
      />
      Add names by hand
    </Collapsible.Trigger>
    <Collapsible.Content class="mt-3 space-y-3">
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
        Each name is checked against the cover site before it can be used.
      </p>
      <Button size="sm" disabled={busy || importText.trim() === ''} onclick={doImport}>Add</Button>
    </Collapsible.Content>
  </Collapsible.Root>

  <Collapsible.Root class="mt-3 rounded-lg border p-4 text-sm">
    <Collapsible.Trigger
      class="group flex min-h-11 w-full items-center gap-2 font-medium sm:min-h-0"
    >
      <ChevronRight
        class="size-4 transition-transform group-data-[state=open]:rotate-90"
        aria-hidden="true"
      />
      Settings
    </Collapsible.Trigger>
    <Collapsible.Content class="mt-3 space-y-5">
      <div class="flex items-start gap-3">
        <Switch
          id={`${uid}-enabled`}
          class="mt-0.5"
          disabled={busy}
          aria-describedby={`${uid}-enabled-help`}
          bind:checked={() => f.enabled, (v) => void setEnabled(v)}
        />
        <div>
          <label for={`${uid}-enabled`} class="font-medium">Use this list</label>
          <p id={`${uid}-enabled-help`} class="text-muted-foreground">
            {listSwitchLine(f.enabled)}
          </p>
        </div>
      </div>

      <div class="space-y-1">
        <label class="flex flex-wrap items-center gap-2">
          <span class="font-medium">Network</span>
          <select
            class={SELECT}
            value={f.network?.slug ?? ''}
            disabled={busy || f.bindings > 0}
            aria-describedby={`${uid}-network-help`}
            onchange={(e) => void setNetwork(e.currentTarget.value || null)}
          >
            <option value="">Anywhere</option>
            {#each networks.data?.networks ?? [] as n (n.slug)}
              <option value={n.slug}>{n.label}</option>
            {/each}
          </select>
        </label>
        <p id={`${uid}-network-help`} class="text-muted-foreground">
          {f.bindings > 0
            ? 'A port uses this list. Stop managing its names on that port to change the network.'
            : 'On a network, the cover site and every name must live inside it (every name is checked again when it changes), and a port using the list gets addresses from it only.'}
        </p>
      </div>

      <label class="flex items-start gap-2">
        <Checkbox
          class="mt-0.5"
          checked={f.requireH2}
          disabled={busy}
          onCheckedChange={(v) => void setRequireH2(v === true)}
        />
        <span>
          Only use names the cover site serves over HTTP/2
          <span class="text-muted-foreground block">Changing it checks every name again.</span>
        </span>
      </label>

      <div class="space-y-2">
        <p class="font-medium">Use it on a port</p>
        {#if !bindOpen}
          <p class="text-muted-foreground">
            The node page's "Manage these names with FCP" is the usual way. Here you can pick any
            REALITY port with the same cover site.
          </p>
          <Button variant="outline" size="sm" disabled={busy} onclick={startBind}>
            Pick a port
          </Button>
        {:else}
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
              <span class="text-muted-foreground mb-1 block">REALITY port</span>
              <select bind:value={transportUuid} class={SELECT}>
                {#each transports as i (i.uuid)}
                  <option value={i.uuid}>{i.tag}{i.target ? ` (${i.target})` : ''}</option>
                {/each}
              </select>
            </label>
            <Button type="submit" size="sm" disabled={busy || !chosen}>Use it there</Button>
            <Button type="button" variant="ghost" size="sm" onclick={() => (bindOpen = false)}>
              Cancel
            </Button>
            {#if backendSlug && !busy && transports.length === 0}
              <p class="basis-full rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2">
                No REALITY port has been read from this server yet. Refresh it under Servers, then
                come back here.
              </p>
            {/if}
            {#if chosen && chosen.names.length > 0}
              <div class="flex basis-full items-start gap-2">
                <Checkbox id={`${uid}-take`} bind:checked={takeNames} />
                <Label for={`${uid}-take`} class="leading-snug font-normal">
                  Take the {chosen.names.length === 1 ? 'name' : `${chosen.names.length} names`} it lists
                  now into this list. They are then checked against the cover site and stay on the port.
                </Label>
              </div>
            {/if}
            <p class="text-muted-foreground basis-full">
              The port's cover site has to be this list's. Nothing is sent to the node yet.
            </p>
          </form>
        {/if}
      </div>

      <div class="border-t pt-4">
        <Button variant="outline" size="sm" disabled={busy} onclick={() => (removeOpen = true)}>
          Remove this list
        </Button>
      </div>
    </Collapsible.Content>
  </Collapsible.Root>

  <AddSuggestionsDialog
    bind:open={addOpen}
    family={slug}
    label={f.label}
    onPort={family.data.bindings.length > 0}
  />
{/if}

<ConfirmDialog
  bind:open={retireOpen}
  title={`Retire ${picked.length} ${picked.length === 1 ? 'name' : 'names'}?`}
  body={`New subscriptions stop presenting ${picked.length === 1 ? 'it' : 'them'} at once, on every origin that presents ${picked.length === 1 ? 'it' : 'them'}. Each node keeps accepting ${picked.length === 1 ? 'it' : 'them'} for ${nameDrain}, so members who already hold ${picked.length === 1 ? 'it' : 'one'} stay connected until their app refreshes. An origin keeps its last active name, and an origin that is busy (replacing an address, removing protection, paused) is skipped. Bring ${picked.length === 1 ? 'it' : 'them'} back any time.`}
  confirmLabel="Retire"
  danger
  onConfirm={() => {
    retireOpen = false;
    void act('retire');
  }}
/>
<ConfirmDialog
  bind:open={burnOpen}
  title={`Burn ${picked.length} ${picked.length === 1 ? 'name' : 'names'}?`}
  body="A burned name leaves every member's list at once and can never be used again."
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
  title="Remove this list?"
  body="Stop managing its names on every port first."
  confirmLabel="Remove"
  danger
  onConfirm={remove}
/>
