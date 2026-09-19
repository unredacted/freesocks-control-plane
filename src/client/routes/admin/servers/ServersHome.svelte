<script lang="ts">
  /**
   * Admin -> Servers (`/admin/servers[?instance=<slug>]`): what already exists
   * on one panel, node by node. For each node: the config profile it runs, the
   * inbounds it serves, the Hosts members are given for each inbound and the
   * squads that grant it. READ-ONLY: nothing on this page changes a panel.
   *
   * Everything shown is non-secret by construction (docs/servers.md): server
   * names, targets and the PUBLIC key of a REALITY inbound, never the private
   * key, the short ids or the clients.
   *
   * All wording and status logic lives in ./lib/words.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Switch } from '@client/components/ui/switch';
  import { ApiCallError } from '@client/lib/api';
  import {
    invalidateServers,
    patchServerConfig,
    refreshServer,
    serverKeys,
    serverSummaryQuery,
    serverTreeQuery,
  } from '@client/lib/serversApi';
  import { router } from '@client/stores/router.svelte';
  import SectionHeader from '../edges/components/SectionHeader.svelte';
  import { pickInstance, serversPaths } from './lib/routes';
  import {
    inboundSummary,
    nodeWords,
    notices,
    observedWords,
    serverErrorWords,
    serverNamesLabel,
    type Dot,
  } from './lib/words';

  const qc = useQueryClient();
  const summary = serverSummaryQuery();
  let slug = $derived(pickInstance(router.search, summary.data?.instances ?? []));
  const tree = serverTreeQuery(() => slug);

  let instance = $derived(summary.data?.instances.find((i) => i.slug === slug) ?? null);
  let observeOn = $derived(summary.data?.config['manage.observe'] ?? false);
  let refreshing = $state(false);
  let saving = $state(false);
  let open = $state<Record<string, boolean>>({});

  const DOT: Record<Dot, string> = {
    green: 'bg-emerald-500',
    amber: 'bg-amber-500',
    red: 'bg-destructive',
    grey: 'bg-muted-foreground/50',
  };

  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  async function refresh() {
    if (!slug || refreshing) return;
    refreshing = true;
    try {
      qc.setQueryData(serverKeys.tree(slug), await refreshServer(slug));
      void qc.invalidateQueries({ queryKey: serverKeys.summary });
      toast.success('Read the panel again.');
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      refreshing = false;
    }
  }

  async function setObserve(on: boolean) {
    saving = true;
    try {
      await patchServerConfig({ 'manage.observe': on });
      invalidateServers(qc);
      toast.success(on ? 'Panels are now read every ten minutes.' : 'Regular reading is off.');
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      saving = false;
    }
  }
</script>

<SectionHeader
  title="Servers"
  description="What is on a panel right now: its nodes, what each one serves, and what members are given. Nothing here changes a panel."
>
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

{#if summary.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if summary.isError}
  <p class="text-destructive text-sm">{serverErrorWords(codeOf(summary.error))}</p>
{:else if (summary.data?.instances.length ?? 0) === 0}
  <Card>
    <CardContent class="text-muted-foreground py-8 text-center text-sm">
      No backend server is set up yet. Add one under Backend servers first.
    </CardContent>
  </Card>
{:else}
  {#if (summary.data?.instances.length ?? 0) > 1}
    <nav class="mb-4 flex flex-wrap gap-2" aria-label="Backend servers">
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

  {#if instance && !instance.observable}
    <Card>
      <CardContent class="text-muted-foreground py-8 text-center text-sm">
        This kind of server has nothing to show here.
      </CardContent>
    </Card>
  {:else if tree.isPending}
    <p class="text-muted-foreground text-sm">Loading…</p>
  {:else if tree.isError}
    <p class="text-destructive text-sm">{serverErrorWords(codeOf(tree.error))}</p>
  {:else if tree.data}
    {@const t = tree.data}
    <p class="text-muted-foreground mb-4 text-sm" aria-live="polite">
      {observedWords(t.state, observeOn, Date.now())}
    </p>

    {#each notices(t) as n (n.text)}
      <p
        class={n.tone === 'warn'
          ? 'border-amber-500/40 bg-amber-500/10 mb-2 rounded-md border px-3 py-2 text-sm'
          : 'bg-muted/50 mb-2 rounded-md border px-3 py-2 text-sm'}
      >
        {n.text}
      </p>
    {/each}

    {#if t.nodes.length === 0 && t.state.ok}
      <Card>
        <CardContent class="text-muted-foreground py-8 text-center text-sm">
          This panel has no nodes yet.
        </CardContent>
      </Card>
    {/if}

    <ul class="space-y-3" aria-label="Nodes">
      {#each t.nodes as node (node.nodeUuid)}
        {@const w = nodeWords(node)}
        {@const isOpen = open[node.nodeUuid] ?? t.nodes.length === 1}
        <li class="rounded-lg border">
          <button
            type="button"
            class="hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 w-full items-center gap-3 rounded-lg px-4 py-3 text-start outline-none focus-visible:ring-3 focus-visible:ring-inset"
            aria-expanded={isOpen}
            onclick={() => (open[node.nodeUuid] = !isOpen)}
          >
            <span
              class={`inline-block size-2.5 shrink-0 rounded-full ${DOT[w.dot]}`}
              aria-hidden="true"
            ></span>
            <span class="min-w-0 flex-1">
              <span class="block truncate font-medium">{node.name}</span>
              <span class="text-muted-foreground block text-sm">{w.sentence}</span>
            </span>
            <span class="text-muted-foreground hidden text-sm sm:block">
              {node.address ?? ''}{node.countryCode ? ` · ${node.countryCode}` : ''}
            </span>
            <ChevronDown
              class={isOpen ? 'size-4 shrink-0 rotate-180' : 'size-4 shrink-0'}
              aria-hidden="true"
            />
          </button>

          {#if isOpen}
            <div class="space-y-4 border-t px-4 py-4 text-sm">
              <dl class="grid gap-x-6 gap-y-1 sm:grid-cols-2">
                <div class="flex gap-2">
                  <dt class="text-muted-foreground">Address</dt>
                  <dd class="break-all">{node.address ?? 'Not set'}</dd>
                </div>
                <div class="flex gap-2">
                  <dt class="text-muted-foreground">Config profile</dt>
                  <dd>{node.profile?.name ?? 'None'}</dd>
                </div>
              </dl>

              {#each node.inbounds as inbound (inbound.inboundUuid)}
                {@const names = serverNamesLabel(inbound)}
                <section class="bg-muted/30 rounded-md border p-3" aria-label={inbound.tag}>
                  <h3 class="font-medium break-all">{inbound.tag}</h3>
                  <p class="text-muted-foreground">{inboundSummary(inbound)}</p>

                  {#if names}
                    <details class="mt-2">
                      <summary class="cursor-pointer">{names}</summary>
                      <ul class="mt-1 columns-1 gap-x-6 sm:columns-2">
                        {#each inbound.serverNames ?? [] as name (name)}
                          <li class="break-all">{name}</li>
                        {/each}
                      </ul>
                      {#if inbound.realityTarget}
                        <p class="text-muted-foreground mt-1">
                          Target site: <span class="break-all">{inbound.realityTarget}</span>
                        </p>
                      {/if}
                    </details>
                  {/if}

                  <div class="mt-3 grid gap-3 sm:grid-cols-2">
                    <div>
                      <h4 class="text-muted-foreground text-xs font-medium uppercase">
                        Addresses members get
                      </h4>
                      {#if inbound.hosts.length === 0}
                        <p class="text-muted-foreground">None</p>
                      {:else}
                        <ul>
                          {#each inbound.hosts as host (host.hostUuid)}
                            <li class={host.isDisabled ? 'text-muted-foreground line-through' : ''}>
                              <span class="break-all">{host.remark}</span>
                              <span class="text-muted-foreground break-all">
                                {host.address}:{host.port}{host.sni ? ` · ${host.sni}` : ''}
                              </span>
                            </li>
                          {/each}
                        </ul>
                      {/if}
                    </div>
                    <div>
                      <h4 class="text-muted-foreground text-xs font-medium uppercase">Squads</h4>
                      {#if inbound.squads.length === 0}
                        <p class="text-muted-foreground">None</p>
                      {:else}
                        <p>{inbound.squads.map((s) => s.name).join(', ')}</p>
                      {/if}
                    </div>
                  </div>
                </section>
              {/each}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  <Card class="mt-6">
    <CardHeader>
      <CardTitle class="text-base">Regular reading</CardTitle>
    </CardHeader>
    <CardContent class="flex items-start gap-3 text-sm">
      <Switch
        id="servers-observe"
        class="mt-0.5"
        disabled={saving}
        aria-describedby="servers-observe-help"
        bind:checked={() => observeOn, (v) => void setObserve(v)}
      />
      <div>
        <label for="servers-observe" class="font-medium">Read every panel every ten minutes</label>
        <p id="servers-observe-help" class="text-muted-foreground">
          Off, a panel is only read when you press Refresh. Reading never changes a panel, and no
          key, password or member detail is copied out of it.
        </p>
      </div>
    </CardContent>
  </Card>
{/if}
