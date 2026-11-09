<script lang="ts">
  /**
   * Servers -> Nodes (`/admin/servers/nodes`): every node of every backend in
   * ONE table, with how members reach it (lib/nodesTable.ts builds the rows,
   * components/NodesTable.svelte draws them). It replaced both the old
   * per-backend Nodes list and the Edges home's fronted rows, and with
   * "Technical columns" on it is also the old All origins page.
   *
   * Header: search, filter chips (All, Action needed, Fronted, Direct,
   * Retiring, Added by hand; with technical columns also the All origins
   * filters and layers), the Backend chip (only with more than one backend),
   * the Technical columns switch, Refresh and Add (Front a node, Add a node by
   * hand, Add an origin by hand). Adopting a node that already serves members
   * is on its row.
   *
   * Above the table each backend says its status and what needs you
   * (components/BackendStatus.svelte); below it come its set-up-once parts
   * (components/BackendDetails.svelte: Backend setup, Mode groups, Recent
   * changes), then the two panel switches in the footer.
   *
   * URL state (lib/nodesTable.ts and lib/routes.ts `NodesParams`): `?backend=`,
   * `?show=`, `?layer=`, `?columns=technical`, `?add=origin` (Add an origin by
   * hand), `?front=1[&backend=&node=]` (the protect sheet, preset to a node),
   * `?run=<id>` (a fronting run's progress in that sheet).
   *
   * Everything shown is non-secret by construction (docs/servers.md). Wording:
   * ./lib/words.ts and ./lib/nodesTable.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import { Button, buttonVariants } from '@client/components/ui/button';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import Link from '@client/components/Link.svelte';
  import { EDGE_PROVIDER_META } from '@client/lib/edgeProviderMeta';
  import {
    attentionQuery,
    edgeSummaryQuery,
    invalidateOverview,
    providersQuery,
  } from '@client/lib/edgesApi';
  import { invalidateSni } from '@client/lib/sniApi';
  import {
    intentsListsQuery,
    invalidateServers,
    opsListsQuery,
    patchServerConfig,
    refreshServer,
    serverKeys,
    serverSummaryQuery,
    serverTreesQuery,
    setupsQuery,
  } from '@client/lib/serversApi';
  import { searchParam, setSearchParams } from '@client/lib/urlState.svelte';
  import { router } from '@client/stores/router.svelte';
  import AdminListState from '../AdminListState.svelte';
  import SectionHeader from '../edges/components/SectionHeader.svelte';
  import ConfirmDialog from '../edges/components/ConfirmDialog.svelte';
  import NewRelayDialog from '../edges/forms/NewRelayDialog.svelte';
  import { edgesPaths } from '../edges/lib/routes';
  import OriginsTechnical from '../edges/overview/OriginsTechnical.svelte';
  import { statusIndex } from '../edges/overview/derive';
  import { originRowActions } from '../edges/overview/originRowActions.svelte';
  import ProtectSheet from '../edges/simple/ProtectSheet.svelte';
  import AddNodeDialog from './components/AddNodeDialog.svelte';
  import AdoptNodeDialog from './components/AdoptNodeDialog.svelte';
  import BackendDetails from './components/BackendDetails.svelte';
  import BackendStatus from './components/BackendStatus.svelte';
  import NodesTable from './components/NodesTable.svelte';
  import SetupSheet from './components/SetupSheet.svelte';
  import { codeOf } from './lib/run';
  import {
    FILTER_LABELS,
    LAYERS,
    LAYER_LABELS,
    NODE_FILTERS,
    TECH_FILTERS,
    buildNodeRows,
    filterCounts,
    filterNodeRows,
    parseLayer,
    parseShow,
    type BackendInput,
    type NodeFilter,
    type NodeRow,
  } from './lib/nodesTable';
  import { backendOf, serversPaths } from './lib/routes';
  import { intentRestarting, needsYou, nodesBeingChanged, serverErrorWords } from './lib/words';

  const qc = useQueryClient();
  const summary = serverSummaryQuery();
  const edgeSummary = edgeSummaryQuery();
  const attention = attentionQuery();
  const providers = providersQuery();

  // --- URL state
  const showParam = searchParam('show', 'all');
  const layerParam = searchParam('layer', 'all');
  const columnsParam = searchParam('columns');
  const addParam = searchParam('add');
  const frontParam = searchParam('front');
  const runParam = searchParam('run');
  const nodeParam = searchParam('node');
  const backendParam = searchParam('backend');
  const technical = $derived(columnsParam.value === 'technical');
  const show = $derived(parseShow(showParam.value, technical));
  const layer = $derived(parseLayer(layerParam.value, technical));
  let query = $state('');

  // --- the backends
  const instances = $derived(summary.data?.instances ?? []);
  const multi = $derived(instances.length > 1);
  const backend = $derived(backendOf(router.search, instances));
  const observable = $derived(instances.filter((i) => i.observable));
  const slugs = $derived(observable.map((i) => i.slug));
  // The backends the page shows (the Backend chip keeps one).
  const shownBackends = $derived(
    backend ? observable.filter((i) => i.slug === backend) : observable,
  );
  const trees = serverTreesQuery(() => slugs);
  const intentLists = intentsListsQuery(() => slugs);
  const setups = setupsQuery(() => slugs);
  const opsLists = opsListsQuery(() => slugs);
  const observeOn = $derived(summary.data?.config['manage.observe'] ?? false);
  const manageOn = $derived(summary.data?.config['manage.enabled'] ?? false);
  const anyWritable = $derived(observable.some((i) => i.writable));
  const at = (slug: string) => slugs.indexOf(slug);
  const treeOf = (slug: string) => trees[at(slug)]?.data ?? null;
  const setupOf = (slug: string) => setups[at(slug)]?.data ?? null;
  const instanceOf = (slug: string) => instances.find((i) => i.slug === slug) ?? null;
  const canWriteOn = (slug: string) => {
    const i = instanceOf(slug);
    return manageOn && !!i?.writable && !!i?.setUp;
  };

  // --- the rows
  const backendInputs = $derived<BackendInput[]>(
    observable.flatMap((instance, idx) => {
      const tree = trees[idx]?.data;
      if (!tree) return [];
      const intents = intentLists[idx]?.data?.intents ?? [];
      const applying = nodesBeingChanged(opsLists[idx]?.data?.ops ?? []);
      const now = Date.now();
      return [
        {
          instance: { id: instance.id, slug: instance.slug, name: instance.name },
          nodes: tree.nodes,
          intents,
          attentionNodes: new Set(needsYou(tree).flatMap((r) => (r.nodeUuid ? [r.nodeUuid] : []))),
          restarting: (node, intent) =>
            applying.has(node.nodeUuid) || (!!intent && intentRestarting(intent, now)),
        },
      ];
    }),
  );
  const statuses = $derived(statusIndex(attention.data?.origins));
  const allRows = $derived(
    buildNodeRows({
      backends: backendInputs,
      origins: edgeSummary.data?.relays ?? [],
      statuses,
    }),
  );
  const backendRows = $derived(filterNodeRows(allRows, { show: 'all', backend }));
  const counts = $derived(filterCounts(backendRows));
  const rows = $derived(filterNodeRows(allRows, { show, layer, query, backend }));
  const loading = $derived(
    summary.isPending || edgeSummary.isPending || trees.some((t) => t.isPending),
  );
  const chips = $derived<NodeFilter[]>(
    technical ? [...NODE_FILTERS, ...TECH_FILTERS] : [...NODE_FILTERS],
  );

  // --- dialogs and sheets
  let addFor = $state<string | null>(null);
  let addOpen = $state(false);
  let adopt = $state<{ slug: string; node: { nodeUuid: string; name: string } } | null>(null);
  let adoptOpen = $state(false);
  let setupFor = $state<string | null>(null);
  let setupOpen = $state(false);
  let originOpen = $state(false);
  $effect(() => {
    if (addParam.value === 'origin') originOpen = true;
  });
  $effect(() => {
    if (!originOpen && addParam.value) addParam.value = null;
  });
  const sheetOpen = $derived(frontParam.value === '1' || runParam.value !== '');
  function openFront() {
    setSearchParams({ front: '1', run: null, node: null });
  }
  function openRun(id: string) {
    setSearchParams({ run: id, front: null, node: null });
  }
  function closeSheet() {
    setSearchParams({ front: null, run: null, node: null });
    invalidateOverview(qc);
  }
  function openSetup(slug: string) {
    setupFor = slug;
    setupOpen = true;
  }
  function openAdd(slug: string) {
    addFor = slug;
    addOpen = true;
  }
  const canAdopt = (row: NodeRow) =>
    !!row.backend && canWriteOn(row.backend.slug) && setupOf(row.backend.slug)?.state === 'ready';
  function startAdopt(row: NodeRow) {
    if (!row.backend || !row.nodeUuid) return;
    adopt = { slug: row.backend.slug, node: { nodeUuid: row.nodeUuid, name: row.name } };
    adoptOpen = true;
  }
  // The backends a node can be added to by hand (changes on, set up, the tree read).
  const addTargets = $derived(shownBackends.filter((i) => canWriteOn(i.slug) && !!treeOf(i.slug)));

  // A setup run finishes in the background, and only the setup query polls
  // while it runs: when one stops, everything else (the summary's "set up"
  // flag, the trees' groups and transports) is re-read at once.
  let setupsWereRunning = false;
  $effect(() => {
    const running = setups.some((s) => s.data?.running ?? false);
    if (setupsWereRunning && !running) invalidateServers(qc);
    setupsWereRunning = running;
  });
  // Closing the sheet re-reads too, whatever the run did meanwhile.
  let sheetWasOpen = false;
  $effect(() => {
    if (sheetWasOpen && !setupOpen) invalidateServers(qc);
    sheetWasOpen = setupOpen;
  });

  // Every DNS account can hold origin names in one of its zones (the setup
  // sheet lists them); switched-on accounts first.
  const originAccounts = $derived(
    (providers.data?.accounts ?? [])
      .filter((a) => EDGE_PROVIDER_META[a.provider].providesDns)
      .sort((a, b) => Number(b.enabled) - Number(a.enabled))
      .map((a) => ({ id: a.id, name: a.name, enabled: a.enabled, locations: a.locations })),
  );

  const originActions = originRowActions(qc);

  // --- refresh and the panel switches
  let refreshing = $state(false);
  let saving = $state(false);
  async function refresh() {
    if (refreshing || shownBackends.length === 0) return;
    refreshing = true;
    try {
      await Promise.all(
        shownBackends.map(async (i) =>
          qc.setQueryData(serverKeys.tree(i.slug), await refreshServer(i.slug)),
        ),
      );
      void qc.invalidateQueries({ queryKey: serverKeys.summary });
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      refreshing = false;
    }
  }
  async function setConfig(key: 'manage.enabled' | 'manage.observe', on: boolean) {
    saving = true;
    try {
      await patchServerConfig({ [key]: on });
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      saving = false;
      invalidateServers(qc);
      // A send to the backend is held back by this switch: say so at once.
      invalidateSni(qc);
    }
  }

  const CHIP =
    'rounded-md border px-2 py-1 text-xs outline-none focus-visible:ring-3 focus-visible:ring-ring/50';
  const chipClass = (on: boolean) => [
    CHIP,
    on ? 'bg-primary text-primary-foreground border-transparent' : '',
  ];
</script>

<SectionHeader title="Nodes">
  {#snippet actions()}
    <Button
      variant="outline"
      size="sm"
      onclick={refresh}
      disabled={refreshing || shownBackends.length === 0}
    >
      <RefreshCw class={refreshing ? 'size-4 animate-spin' : 'size-4'} aria-hidden="true" />
      Refresh
    </Button>
    <DropdownMenu.Root>
      <DropdownMenu.Trigger class={buttonVariants({ size: 'sm' })}>
        <Plus class="size-4" aria-hidden="true" />
        Add
        <ChevronDown class="size-4" aria-hidden="true" />
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="end">
        <DropdownMenu.Item onSelect={openFront}>Front a node</DropdownMenu.Item>
        {#each addTargets as i (i.slug)}
          <DropdownMenu.Item onSelect={() => openAdd(i.slug)}>
            {multi ? `Add a node by hand to ${i.name}` : 'Add a node by hand'}
          </DropdownMenu.Item>
        {/each}
        <DropdownMenu.Item onSelect={() => (originOpen = true)}>
          Add an origin by hand
        </DropdownMenu.Item>
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  {/snippet}
</SectionHeader>

<div class="space-y-8">
  {#if summary.isError}
    <p class="text-destructive text-sm">{serverErrorWords(codeOf(summary.error))}</p>
  {:else if summary.data && instances.length === 0}
    <div class="rounded-lg border border-dashed p-8 text-center">
      <p class="text-muted-foreground text-sm">No backend server is set up yet.</p>
      <Link
        href={serversPaths.backends()}
        class="text-primary mt-2 inline-block text-sm underline underline-offset-4"
      >
        Add one
      </Link>
    </div>
  {/if}

  {#each shownBackends as i (i.slug)}
    <BackendStatus
      slug={i.slug}
      name={i.name}
      showName={multi}
      canWrite={canWriteOn(i.slug)}
      {manageOn}
      setUp={i.setUp}
      {observeOn}
      onSetUp={() => openSetup(i.slug)}
    />
  {/each}
  {#each instances.filter((i) => !i.observable && (!backend || i.slug === backend)) as i (i.slug)}
    <p class="text-muted-foreground text-sm">
      {i.name}: this kind of server has nothing to show here.
    </p>
  {/each}

  {#if technical}
    <OriginsTechnical part="top" activeFilter={show} onFilter={(f) => (showParam.value = f)} />
  {/if}

  <section aria-label="Nodes" class="space-y-3">
    <div class="flex flex-wrap items-center gap-x-4 gap-y-2">
      <div class="w-full max-w-sm">
        <Label for="node-filter" class="sr-only">Find a node</Label>
        <Input
          id="node-filter"
          type="search"
          placeholder="Find a node by its name or machine name"
          bind:value={query}
        />
      </div>
      {#if multi}
        <DropdownMenu.Root>
          <DropdownMenu.Trigger class={buttonVariants({ variant: 'outline', size: 'sm' })}>
            Backend: {backend ? (instanceOf(backend)?.name ?? backend) : 'all'}
            <ChevronDown class="size-4" aria-hidden="true" />
          </DropdownMenu.Trigger>
          <DropdownMenu.Content align="start">
            <DropdownMenu.Item onSelect={() => (backendParam.value = null)}>
              All backends
            </DropdownMenu.Item>
            {#each instances as i (i.slug)}
              <DropdownMenu.Item onSelect={() => (backendParam.value = i.slug)}>
                {i.name}
              </DropdownMenu.Item>
            {/each}
          </DropdownMenu.Content>
        </DropdownMenu.Root>
      {/if}
      <div class="flex items-center gap-2">
        <Switch
          id="technical-columns"
          checked={technical}
          onCheckedChange={(v) => (columnsParam.value = v ? 'technical' : null)}
        />
        <Label for="technical-columns" class="text-sm font-normal">Technical columns</Label>
      </div>
    </div>
    <div class="flex flex-wrap items-center gap-1" role="group" aria-label="Filter nodes">
      {#each chips as f (f)}
        <button
          type="button"
          class={chipClass(show === f)}
          aria-pressed={show === f}
          onclick={() => (showParam.value = f)}
        >
          {FILTER_LABELS[f]} <span class="tabular-nums opacity-70">{counts[f]}</span>
        </button>
      {/each}
      {#if technical}
        <span class="bg-border mx-1 h-4 w-px" aria-hidden="true"></span>
        {#each LAYERS as l (l)}
          <button
            type="button"
            class={chipClass(layer === l)}
            aria-pressed={layer === l}
            onclick={() => (layerParam.value = l)}
          >
            {LAYER_LABELS[l]}
          </button>
        {/each}
      {/if}
    </div>

    {#if loading}
      <Skeleton class="h-32" />
    {:else if edgeSummary.isError}
      <AdminListState error={edgeSummary.error} onRetry={() => void edgeSummary.refetch()} />
    {:else if allRows.length === 0}
      <div class="rounded-lg border border-dashed p-8 text-center">
        <p class="text-muted-foreground mx-auto max-w-prose text-sm">
          Nodes appear here once the node role enrolls them. For a machine the role does not run,
          use Add, then Add a node by hand.
        </p>
      </div>
    {:else if rows.length === 0}
      <div class="text-muted-foreground rounded-lg border border-dashed p-6 text-center text-sm">
        No node matches.
        <Button
          variant="link"
          size="sm"
          onclick={() => {
            query = '';
            setSearchParams({ show: null, layer: null });
          }}
        >
          Show all nodes
        </Button>
      </div>
    {:else}
      <NodesTable
        {rows}
        {technical}
        showBackend={multi}
        {canAdopt}
        onAdopt={startAdopt}
        onOpenRun={openRun}
        busySlug={originActions.busySlug}
        onProvision={(row) => originActions.askProvision(row)}
        onProbe={(row) => originActions.probe(row)}
      />
    {/if}
  </section>

  {#if technical}
    <OriginsTechnical part="bottom" activeFilter={show} onFilter={(f) => (showParam.value = f)} />
  {/if}

  {#each shownBackends as i (i.slug)}
    <BackendDetails
      slug={i.slug}
      name={i.name}
      showName={multi}
      canWrite={canWriteOn(i.slug)}
      canChangeSetup={manageOn && i.writable}
      onChangeSetup={() => openSetup(i.slug)}
    />
  {/each}

  {#if observable.length > 0}
    <footer
      class="text-muted-foreground flex flex-wrap items-center gap-x-8 gap-y-3 border-t pt-4 text-sm"
    >
      <div class="flex items-center gap-3">
        <Switch
          id="servers-observe"
          checked={observeOn}
          disabled={saving}
          onCheckedChange={(v) => void setConfig('manage.observe', v)}
        />
        <Label for="servers-observe" class="font-normal">
          Panels are read every ten minutes{observeOn ? '' : ': off'}
        </Label>
      </div>
      {#if anyWritable}
        <div class="flex items-center gap-3">
          <Switch
            id="servers-manage"
            checked={manageOn}
            disabled={saving}
            onCheckedChange={(v) => void setConfig('manage.enabled', v)}
          />
          <Label for="servers-manage" class="font-normal">
            Changes from here are {manageOn ? 'on' : 'off'}
          </Label>
        </div>
      {/if}
    </footer>
  {/if}
</div>

{#if addFor && treeOf(addFor) && canWriteOn(addFor)}
  <AddNodeDialog bind:open={addOpen} slug={addFor} tree={treeOf(addFor)!} />
{/if}
{#if adopt && treeOf(adopt.slug)}
  <AdoptNodeDialog
    bind:open={adoptOpen}
    slug={adopt.slug}
    node={adopt.node}
    modes={setupOf(adopt.slug)?.modes ?? []}
    tree={treeOf(adopt.slug)!}
  />
{/if}
{#if setupFor}
  <SetupSheet
    bind:open={setupOpen}
    slug={setupFor}
    setup={setupOf(setupFor)}
    accounts={originAccounts}
  />
{/if}

<NewRelayDialog
  bind:open={originOpen}
  kinds={['manual', 'backend-server']}
  onCreated={(slug) => router.navigate(edgesPaths.relay(slug))}
/>

<ConfirmDialog
  bind:open={originActions.provisionOpen}
  title="Provision a new edge?"
  body="Creates a billable resource at the provider and counts against today's account budget. The run opens in the origin's technical details."
  confirmLabel="Provision"
  onConfirm={() => originActions.confirmProvision()}
>
  {#if originActions.provisionRow}
    <p class="text-muted-foreground">Origin {originActions.provisionRow.relay.slug}</p>
  {/if}
</ConfirmDialog>

<!-- The node always comes first; the account step adds one when there is none. -->
{#if sheetOpen}
  <ProtectSheet
    open={sheetOpen}
    runId={runParam.value || null}
    server={frontParam.value === '1' ? backendParam.value || null : null}
    node={nodeParam.value || null}
    onRunCreated={(id) => openRun(id)}
    onClose={closeSheet}
  />
{/if}
