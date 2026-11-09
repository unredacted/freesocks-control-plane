<script lang="ts">
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import { apiClient } from '@client/lib/api';
  import { apiErrorMessage } from '@client/lib/errors';
  import { adminConnectionModesQuery, adminNodeStatsQuery, queryKeys } from '@client/lib/queries';
  import {
    fetchServerTree,
    invalidateServers,
    serverKeys,
    serverSummaryQuery,
    validatePlacements,
  } from '@client/lib/serversApi';
  import { createMutation, createQueries, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { RemnawavePlacementUpdateResponse } from '@shared/contracts/admin';
  import SectionHeader from '../edges/components/SectionHeader.svelte';
  import {
    UUID_RE,
    indexModeGroups,
    parseGroupList,
    poolSpread,
    readPoolLines,
    type GroupRef,
    type PoolCheck,
  } from './lib/modePools';
  import { serversPaths } from './lib/routes';

  /**
   * Settings -> Mode pools (`/admin/servers/settings/mode-pools`, formerly the
   * Remnawave page; the namespaced /api/v1/admin/remnawave/* surface): each
   * connection mode binds a POOL of Remnawave mode group UUIDs, and issuance
   * homes a new key to the least-loaded node of that pool (per-node load from
   * the backend, refreshed by the healthcheck cron). Mode group UUIDs are
   * write-only, so a bound pool is described by what the client does know
   * (lib/modePools.ts): each backend's pool check says where its groups are
   * (and which grant no transport), a typed uuid is named from the mode groups
   * every backend reports, and so is each row of the live node-load view.
   * Every group name links to its backend's row on Settings -> Backends.
   * English-only (admin CMS convention).
   */
  const nodeStats = adminNodeStatsQuery();
  const qc = useQueryClient();

  // Every backend whose panel FCP reads: its mode groups (names by uuid) and its
  // check of the pools against them. Same cache keys as the Nodes page.
  const backends = serverSummaryQuery();
  const readable = $derived((backends.data?.instances ?? []).filter((i) => i.observable));
  const trees = createQueries(() => ({
    queries: readable.map((i) => ({
      queryKey: serverKeys.tree(i.slug),
      queryFn: () => fetchServerTree(i.slug),
      staleTime: 30_000,
    })),
  }));
  const checks = createQueries(() => ({
    queries: readable.map((i) => ({
      queryKey: serverKeys.placements(i.slug),
      queryFn: () => validatePlacements(i.slug),
      staleTime: 30_000,
    })),
  }));
  let groupIndex = $derived(indexModeGroups(trees.flatMap((q) => (q.data ? [q.data] : []))));
  let allGroups = $derived(
    [...groupIndex.values()]
      .flat()
      .sort((a, b) => a.backendName.localeCompare(b.backendName) || a.name.localeCompare(b.name)),
  );
  let poolChecks = $derived(
    readable.flatMap((i, n): PoolCheck[] => {
      const d = checks[n]?.data;
      return d ? [{ slug: i.slug, name: i.name, modes: d.modes }] : [];
    }),
  );
  const backendHref = (slug: string) => serversPaths.backends({ backend: slug });
  const groupsOf = (uuid: string): readonly GroupRef[] => groupIndex.get(uuid.toLowerCase()) ?? [];

  // Pools are bound per LEAF mode and grouped by family for legibility. Fully
  // data-driven off the admin catalog, so a new mode needs no edit here.
  // Note this reads the ADMIN catalog, not publicConfig: publicConfig omits
  // disabled modes, and an operator must still be able to bind a pool to a mode
  // before turning it on.
  const modeCatalog = adminConnectionModesQuery();
  // Only modes that DECLARE the remnawave backend can be bound here; an orphan
  // bucket keeps modes whose family row is gone manageable (the old grouping
  // hid them entirely, so their pool could never be bound or cleared).
  let adminModes = $derived(
    (modeCatalog.data?.modes ?? []).filter((m) => (m.backends as string[]).includes('remnawave')),
  );
  let adminFamilies = $derived(modeCatalog.data?.families ?? []);
  let modeGroups = $derived(
    (() => {
      const grouped = adminFamilies
        .map((f) => ({
          family: f as (typeof adminFamilies)[number] | null,
          children: adminModes.filter((m) => m.family === f.id),
        }))
        .filter((g) => g.children.length > 0);
      const known = new Set(adminFamilies.map((f) => f.id));
      const orphans = adminModes.filter((m) => !m.family || !known.has(m.family));
      return orphans.length ? [...grouped, { family: null, children: orphans }] : grouped;
    })(),
  );

  // Per-leaf textarea contents, keyed by mode id.
  let draft = $state<Record<string, string>>({});
  // Inline validation error (bad UUID lines) — a typo'd mode group UUID used to save
  // silently and only surface later as a dead/offline pool.
  let draftError = $state<string | null>(null);

  // Per-mode bound-pool SIZES (never the UUIDs): the catalog's per-backend
  // placement summaries, with the node-stats counts as an older-server fallback.
  let boundCounts = $derived(
    Object.fromEntries(
      (nodeStats.data?.placements ?? []).map((p) => [p.modeId, p.boundCount]),
    ) as Record<string, number>,
  );
  function remnawaveSummary(m: (typeof adminModes)[number]): { bound: boolean; count: number } {
    const viaCatalog = m.placements.find((p) => p.backendId === 'remnawave');
    if (viaCatalog) return { bound: viaCatalog.bound, count: viaCatalog.boundCount };
    return { bound: m.bound, count: boundCounts[m.id] ?? 0 };
  }

  const save = createMutation(() => ({
    mutationFn: async () => {
      const modes: Record<string, { groupUuids: string[] }> = {};
      const invalid: string[] = [];
      // Only send a mode when the admin typed something - blank keeps the current
      // binding (keep-secret-on-blank). An explicit line clears/sets the pool.
      for (const m of adminModes) {
        const text = draft[m.id] ?? '';
        if (!text.trim()) continue;
        const uuids = parseGroupList(text);
        invalid.push(...uuids.filter((s) => !UUID_RE.test(s)));
        modes[m.id] = { groupUuids: uuids };
      }
      if (invalid.length > 0) {
        throw new Error(`Not a mode group UUID: ${invalid.join(', ')}`);
      }
      return apiClient.patch(
        '/api/v1/admin/backends/remnawave/mode-placements',
        { modes },
        RemnawavePlacementUpdateResponse,
      );
    },
    onSuccess: () => {
      draft = {};
      draftError = null;
      void qc.invalidateQueries({ queryKey: queryKeys.adminConnectionModes });
      void qc.invalidateQueries({ queryKey: queryKeys.config }); // refresh `available`
      void qc.invalidateQueries({ queryKey: queryKeys.adminNodeStats }); // refresh bound counts
      invalidateServers(qc); // each backend's pool check
      toast.success('Node placement saved');
    },
    onError: (err) => {
      draftError = apiErrorMessage(err);
      toast.error('Could not save node placement', { description: apiErrorMessage(err) });
    },
  }));
</script>

<SectionHeader
  title="Mode pools"
  description="Which mode groups each connection mode issues new keys into. A new key goes to the least-loaded node of its mode's pool."
/>

<div class="space-y-6">
  <Card>
    <CardHeader>
      <CardTitle class="text-base">Node placement pools</CardTitle>
      <CardDescription>
        Give each connection mode a pool of Remnawave mode group UUIDs, one per line and one group
        per node. Two or more make a load-balanced pool. The UUIDs are write-only. Leave a field
        blank to keep its current pool. The node role's backend bootstrap sets these for you. The
        modes themselves are under
        <Link href="/admin/connection-modes" class="underline underline-offset-2"
          >Connection modes</Link
        >.
      </CardDescription>
    </CardHeader>
    <CardContent class="space-y-5 text-sm">
      {#each modeGroups as g, gi (g.family?.id ?? '__orphans__')}
        <div
          class="space-y-4"
          class:border-t={gi > 0}
          class:border-border={gi > 0}
          class:pt-4={gi > 0}
        >
          <p class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {g.family ? (g.family.label ?? g.family.id) : 'No family (orphaned modes)'}
          </p>
          {#each g.children as m (m.id)}
            {@const summary = remnawaveSummary(m)}
            {@const bound = summary.bound}
            {@const spread = poolSpread(m.id, poolChecks)}
            <div class="space-y-2">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <span class="font-medium">
                  {m.label ?? m.id}
                  <span class="font-mono text-xs text-muted-foreground">({m.id})</span>
                </span>
                <span class="flex items-center gap-1.5">
                  {#if !m.enabled}
                    <!-- A pool can be bound BEFORE the mode is switched on; say so
                         rather than letting "bound" read as "live to members". -->
                    <span
                      class="rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-600 dark:text-amber-400"
                    >
                      Disabled
                    </span>
                  {/if}
                  <span
                    class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide {bound
                      ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                      : 'bg-muted text-muted-foreground'}"
                  >
                    {#if bound}
                      {summary.count > 0
                        ? `${summary.count} mode group${summary.count === 1 ? '' : 's'} bound`
                        : 'Pool bound'}
                    {:else}
                      Not set
                    {/if}
                  </span>
                </span>
              </div>
              {#if bound && spread.size > 0}
                <p class="text-muted-foreground text-xs">
                  {#each spread.found as f, fi (f.slug)}
                    {fi > 0 ? ', ' : ''}{f.count} on
                    <Link href={backendHref(f.slug)} class="underline underline-offset-2"
                      >{f.name}</Link
                    >
                  {/each}{#if spread.missing > 0}
                    <span class="text-amber-600 dark:text-amber-400"
                      >{spread.found.length > 0 ? ', ' : ''}{spread.missing} on no backend FCP reads</span
                    >
                  {/if}.
                  {#each spread.withoutTransports as w (`${w.slug}:${w.group}`)}
                    <span class="text-amber-600 dark:text-amber-400">
                      {w.group} on {w.name} grants no transport.
                    </span>
                  {/each}
                </p>
              {/if}
              <textarea
                rows="2"
                aria-label={`Mode group pool for ${m.label ?? m.id}`}
                class="border-input focus-visible:border-ring focus-visible:ring-ring/50 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1 font-mono text-base outline-none transition-colors focus-visible:ring-3 md:text-sm placeholder:text-muted-foreground"
                placeholder={bound ? 'Bound - leave blank to keep' : 'one group uuid per line'}
                value={draft[m.id] ?? ''}
                oninput={(e) =>
                  (draft = { ...draft, [m.id]: (e.target as HTMLTextAreaElement).value })}
              ></textarea>
              {#if (draft[m.id] ?? '').trim()}
                <ul
                  class="space-y-0.5 text-xs"
                  aria-label={`What the pool for ${m.label ?? m.id} names`}
                >
                  {#each readPoolLines(draft[m.id] ?? '', groupIndex) as line (line.text)}
                    <li class="flex flex-wrap items-baseline gap-x-2">
                      <span class="font-mono text-muted-foreground break-all">{line.text}</span>
                      {#if line.kind === 'group'}
                        {#each line.groups as g (g.backendSlug)}
                          <span>
                            <span class="font-medium">{g.name}</span> on
                            <Link
                              href={backendHref(g.backendSlug)}
                              class="underline underline-offset-2">{g.backendName}</Link
                            >
                          </span>
                        {/each}
                      {:else if line.kind === 'unknown'}
                        <span class="text-amber-600 dark:text-amber-400"
                          >Not a mode group on any backend FCP reads.</span
                        >
                      {:else}
                        <span class="text-destructive">Not a mode group UUID.</span>
                      {/if}
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
          {/each}
        </div>
      {/each}
      {#if draftError}
        <p
          class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive"
        >
          {draftError}
        </p>
      {/if}
      {#if allGroups.length > 0}
        <details class="rounded-lg border">
          <summary class="cursor-pointer px-3 py-2 font-medium">
            Mode groups on your backends ({allGroups.length})
          </summary>
          <ul class="divide-y border-t">
            {#each allGroups as g (`${g.backendSlug}:${g.uuid}`)}
              <li class="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-2">
                <span class="font-medium">{g.name}</span>
                <span class="font-mono text-xs text-muted-foreground break-all">{g.uuid}</span>
                <Link href={backendHref(g.backendSlug)} class="text-xs underline underline-offset-2"
                  >{g.backendName}</Link
                >
              </li>
            {/each}
          </ul>
        </details>
      {/if}
      <div class="flex justify-end">
        <Button onclick={() => save.mutate()} disabled={save.isPending}>
          {save.isPending ? 'Saving…' : 'Save node placement'}
        </Button>
      </div>
    </CardContent>
  </Card>

  <Card>
    <CardHeader>
      <CardTitle class="text-base">Node load</CardTitle>
      <CardDescription>
        Users online per mode group and its node, refreshed about every 10 minutes. New keys go to
        the least-loaded online node with fresh stats in their mode's pool.
      </CardDescription>
    </CardHeader>
    <CardContent class="text-sm">
      {#if nodeStats.data && nodeStats.data.nodes.length > 0}
        <div class="space-y-1">
          {#each nodeStats.data.nodes as sq (sq.placement)}
            {@const known = groupsOf(sq.placement)}
            <div class="flex items-center justify-between gap-2">
              <span class="min-w-0 truncate">
                <span class="font-medium">{sq.label ?? known[0]?.name ?? 'unnamed'}</span>
                <span class="ml-1 font-mono text-xs text-muted-foreground">{sq.placement}</span>
                {#each known as g (g.backendSlug)}
                  <Link
                    href={backendHref(g.backendSlug)}
                    class="ml-1 text-xs underline underline-offset-2">{g.backendName}</Link
                  >
                {/each}
                {#if !sq.online}
                  <span class="ml-1 text-xs text-amber-600 dark:text-amber-400">· offline</span>
                {/if}
              </span>
              <span class="shrink-0 tabular-nums text-muted-foreground">
                {sq.usersOnline}
                {sq.usersOnline === 1 ? 'user' : 'users'}
              </span>
            </div>
          {/each}
        </div>
      {:else}
        <p class="text-muted-foreground">
          No node stats yet. They appear after the first health check on a bound pool.
        </p>
      {/if}
    </CardContent>
  </Card>
</div>
