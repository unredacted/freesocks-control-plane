<script lang="ts">
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { apiClient } from '@client/lib/api';
  import { apiErrorMessage } from '@client/lib/errors';
  import { adminConnectionModesQuery, adminNodeStatsQuery, queryKeys } from '@client/lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { RemnawavePlacementUpdateResponse } from '@shared/contracts/admin';
  import SectionHeader from '../edges/components/SectionHeader.svelte';

  /**
   * Servers -> Mode pools (`/admin/servers/pools`, formerly the Remnawave
   * page; the namespaced /api/v1/admin/remnawave/* surface): each connection
   * mode binds a POOL of Remnawave mode group UUIDs, and issuance homes a new
   * key to the least-loaded node of that pool (per-node load from the backend,
   * refreshed by the healthcheck cron). Mode group UUIDs are write-only; the
   * live node-load view below is read-only. English-only (admin CMS convention).
   */
  const nodeStats = adminNodeStatsQuery();
  const qc = useQueryClient();

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

  // One UUID per line (commas also accepted); trims + dedupes.
  function parseGroupList(text: string): string[] {
    const out: string[] = [];
    for (const raw of text.split(/[\n,]/)) {
      const s = raw.trim();
      if (s && !out.includes(s)) out.push(s);
    }
    return out;
  }

  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
        blank to keep its current pool. The node role's backend bootstrap sets these for you.
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
              <textarea
                rows="2"
                aria-label={`Mode group pool for ${m.label ?? m.id}`}
                class="border-input focus-visible:border-ring focus-visible:ring-ring/50 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1 font-mono text-base outline-none transition-colors focus-visible:ring-3 md:text-sm placeholder:text-muted-foreground"
                placeholder={bound ? 'Bound - leave blank to keep' : 'one group uuid per line'}
                value={draft[m.id] ?? ''}
                oninput={(e) =>
                  (draft = { ...draft, [m.id]: (e.target as HTMLTextAreaElement).value })}
              ></textarea>
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
            <div class="flex items-center justify-between gap-2">
              <span class="truncate">
                <span class="font-medium">{sq.label ?? 'unnamed'}</span>
                <span class="ml-1 font-mono text-xs text-muted-foreground">{sq.placement}</span>
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
