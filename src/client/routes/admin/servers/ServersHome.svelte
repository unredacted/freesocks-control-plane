<script lang="ts">
  /**
   * Servers home (`/admin/servers[?instance=<slug>]`): one status sentence,
   * what needs you, one row per node, the quiet leftovers, squads, recent
   * changes, and the two switches in the footer. A node's details and every
   * action on it live on its own page (NodePage).
   *
   * Everything shown is non-secret by construction (docs/servers.md). All
   * wording lives in ./lib/words.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Button } from '@client/components/ui/button';
  import { Label } from '@client/components/ui/label';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import Link from '@client/components/Link.svelte';
  import { providersQuery } from '@client/lib/edgesApi';
  import {
    acknowledgeForeignEdit,
    intentsQuery,
    invalidateServers,
    patchServerConfig,
    refreshServer,
    serverKeys,
    serverSummaryQuery,
    serverTreeQuery,
    setupQuery,
  } from '@client/lib/serversApi';
  import { router } from '@client/stores/router.svelte';
  import SectionHeader from '../edges/components/SectionHeader.svelte';
  import StatusDot from '../edges/simple/StatusDot.svelte';
  import OpsList from './components/OpsList.svelte';
  import SetupSheet from './components/SetupSheet.svelte';
  import SquadsCard from './components/SquadsCard.svelte';
  import { codeOf } from './lib/run';
  import { pickInstance, serversPaths } from './lib/routes';
  import {
    PURPOSE_WORDS,
    ago,
    countryLabel,
    fleetSentence,
    needsYou,
    nodeWords,
    quietNotes,
    serverErrorWords,
    setupWords,
    stageWords,
  } from './lib/words';

  const qc = useQueryClient();
  const summary = serverSummaryQuery();
  let slug = $derived(pickInstance(router.search, summary.data?.instances ?? []));
  const tree = serverTreeQuery(() => slug);
  // The bootstrap contract: the panel's setup and its enrolled nodes.
  const setup = setupQuery(() => slug);
  const intents = intentsQuery(() => slug);
  const providers = providersQuery();
  let setupOpen = $state(false);
  let setupRow = $derived(setup.data ? setupWords(setup.data) : null);
  let originAccounts = $derived(
    (providers.data?.accounts ?? [])
      .filter((a) => a.provider === 'cloudflare' && typeof a.settings.zoneName === 'string')
      .map((a) => ({ id: a.id, name: a.name, zoneName: String(a.settings.zoneName) })),
  );
  const intentOf = (node: { nodeUuid: string; name: string }) =>
    intents.data?.intents.find((i) => i.nodeUuid === node.nodeUuid || i.name === node.name) ?? null;

  let instance = $derived(summary.data?.instances.find((i) => i.slug === slug) ?? null);
  let observeOn = $derived(summary.data?.config['manage.observe'] ?? false);
  let manageOn = $derived(summary.data?.config['manage.enabled'] ?? false);
  let canWrite = $derived(manageOn && !!instance?.writable && !!instance?.handoffCurrent);
  let refreshing = $state(false);
  let saving = $state(false);

  const ROW =
    'bg-card hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-start outline-none focus-visible:ring-3';

  async function refresh() {
    if (!slug || refreshing) return;
    refreshing = true;
    try {
      qc.setQueryData(serverKeys.tree(slug), await refreshServer(slug));
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
    }
  }

  async function seen(profileUuid: string) {
    if (!slug) return;
    try {
      await acknowledgeForeignEdit(slug, profileUuid);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      invalidateServers(qc);
    }
  }
</script>

<SectionHeader title="Servers">
  {#snippet actions()}
    <Button
      variant="outline"
      size="sm"
      onclick={refresh}
      disabled={!slug || refreshing || instance?.observable === false}
    >
      <RefreshCw class={refreshing ? 'size-4 animate-spin' : 'size-4'} aria-hidden="true" />
      Refresh
    </Button>
  {/snippet}
</SectionHeader>

<div class="space-y-8">
  {#if (summary.data?.instances.length ?? 0) > 1}
    <nav class="-mt-2 flex flex-wrap gap-2" aria-label="Backend servers">
      {#each summary.data?.instances ?? [] as i (i.slug)}
        <Button
          variant={i.slug === slug ? 'default' : 'outline'}
          size="sm"
          onclick={() => router.navigate(serversPaths.home({ instance: i.slug }))}
          aria-current={i.slug === slug ? 'page' : undefined}
        >
          {i.name}
        </Button>
      {/each}
    </nav>
  {/if}

  {#if summary.isPending || (slug && tree.isPending)}
    <Skeleton class="h-6 w-64" />
  {:else if summary.isError}
    <p class="text-destructive text-sm">{serverErrorWords(codeOf(summary.error))}</p>
  {:else if (summary.data?.instances.length ?? 0) === 0}
    <div class="rounded-lg border border-dashed p-8 text-center">
      <p class="text-muted-foreground text-sm">No backend server is set up yet.</p>
      <Link
        href="/admin/backend-servers"
        class="text-primary mt-2 inline-block text-sm underline underline-offset-4"
      >
        Add one
      </Link>
    </div>
  {:else if instance && !instance.observable}
    <p class="text-muted-foreground text-sm">This kind of server has nothing to show here.</p>
  {:else if tree.isError}
    <p class="text-destructive text-sm">{serverErrorWords(codeOf(tree.error))}</p>
  {:else if tree.data}
    {@const t = tree.data}
    {@const headline = fleetSentence(t.nodes)}
    {@const attention = needsYou(t)}
    {@const notes = quietNotes(t)}

    <div>
      <p class="flex items-center gap-2 text-lg font-medium" role="status">
        <StatusDot dot={t.state.ok === false ? 'red' : headline.dot} class="size-3" />
        {t.state.ok === false ? 'The panel could not be read.' : headline.text}
      </p>
      <p class="text-muted-foreground mt-1 text-sm">
        {#if t.state.observedAt}
          Read {ago(Date.now() - Date.parse(t.state.observedAt))}{observeOn
            ? ''
            : '. Regular reading is off'}.
        {:else}
          Not read yet.
        {/if}
      </p>
    </div>

    {#if attention.length > 0 || (manageOn && setupRow) || (manageOn && instance && !instance.handoffCurrent && !setupRow)}
      <section aria-labelledby="needs-you">
        <h2 id="needs-you" class="mb-3 text-base font-semibold">Needs you</h2>
        <ul class="space-y-2">
          {#if manageOn && setupRow}
            <li
              class="flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-sm"
            >
              <span class="min-w-0 flex-1">{setupRow}</span>
              <Button variant="outline" size="sm" onclick={() => (setupOpen = true)}>
                {setup.data?.state === 'needs_takeover' ? 'Take over' : 'Set up'}
              </Button>
            </li>
          {:else if manageOn && instance && !instance.handoffCurrent}
            <li class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-sm">
              Changes are allowed, but this panel is not set up yet, so they are refused. Set it up
              first.
            </li>
          {/if}
          {#each attention as row (row.key)}
            <li
              class="flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-sm"
            >
              <span class="min-w-0 flex-1">{row.text}</span>
              {#if row.key.startsWith('edit:') && canWrite}
                <Button variant="outline" size="sm" onclick={() => seen(row.key.slice(5))}>
                  Seen it
                </Button>
              {:else if row.nodeUuid && slug}
                <Link
                  href={serversPaths.node(row.nodeUuid, { instance: slug })}
                  class="text-primary text-sm underline underline-offset-4"
                >
                  Open
                </Link>
              {/if}
            </li>
          {/each}
        </ul>
      </section>
    {/if}

    <section aria-label="Nodes">
      {#if t.nodes.length === 0}
        <p class="text-muted-foreground text-sm">
          A node appears here once the node role has registered it with the panel.
        </p>
      {:else}
        <ul class="space-y-2">
          {#each t.nodes as node (node.nodeUuid)}
            {@const w = nodeWords(node)}
            {@const country = countryLabel(node.countryCode)}
            {@const intent = intentOf(node)}
            {@const st = intent ? stageWords(intent) : null}
            <li>
              <Link
                href={serversPaths.node(node.nodeUuid, { instance: slug ?? undefined })}
                class={ROW}
              >
                <StatusDot dot={st && st.dot !== 'green' ? st.dot : w.dot} />
                <span class="min-w-0 flex-1">
                  <span class="flex flex-wrap items-baseline gap-x-2">
                    <span class="font-medium">{node.name}</span>
                    {#if intent}
                      <span class="text-muted-foreground text-xs"
                        >{PURPOSE_WORDS[intent.purpose]}</span
                      >
                    {/if}
                    {#if country}<span class="text-muted-foreground text-xs">{country}</span>{/if}
                  </span>
                  <span class="text-muted-foreground block text-sm">
                    {st && st.dot !== 'green' ? st.sentence : w.sentence}
                  </span>
                </span>
                <ChevronRight
                  class="text-muted-foreground size-4 shrink-0 rtl:rotate-180"
                  aria-hidden="true"
                />
              </Link>
            </li>
          {/each}
        </ul>
      {/if}
      {#if notes.length > 0}
        <ul class="text-muted-foreground mt-3 space-y-1 text-sm" aria-label="Notes">
          {#each notes as n (n)}
            <li>{n}</li>
          {/each}
        </ul>
      {/if}
    </section>

    {#if slug}
      <SquadsCard {slug} tree={t} {canWrite} />
      <SetupSheet
        bind:open={setupOpen}
        {slug}
        setup={setup.data ?? null}
        accounts={originAccounts}
      />
    {/if}
    {#if slug && manageOn && instance?.writable}
      <OpsList {slug} />
    {/if}
  {/if}

  {#if instance?.observable}
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
      {#if instance.writable}
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
