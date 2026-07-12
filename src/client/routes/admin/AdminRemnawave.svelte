<script lang="ts">
  import AdminLayout from './AdminLayout.svelte';
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminNodeStatsQuery, configQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { z } from 'zod';
  import { toast } from 'svelte-sonner';
  import { RemnawaveLoggingReport } from '../../../shared/contracts/admin';

  /**
   * Remnawave-specific admin config (the namespaced /api/v1/admin/remnawave/*
   * surface). Node placement lives here, OFF the generic settings page: each
   * connection mode binds a POOL of Remnawave internal-squad UUIDs, and issuance
   * homes a new key to the least-loaded node of that pool (per-node load from the
   * panel, refreshed by the healthcheck cron). Squad UUIDs are write-only; the
   * live node-load view below is read-only. English-only (admin CMS convention).
   */
  const config = configQuery();
  const nodeStats = adminNodeStatsQuery();
  const qc = useQueryClient();

  // The two shipped modes. (The generic catalog is data-driven; the pool editor
  // stays keyed to the known modes - a novel mode would add a row here.)
  let cpAvailable = $derived({
    evade: config.data?.connectionModes?.find((m) => m.id === 'evade')?.available ?? false,
    privacy: config.data?.connectionModes?.find((m) => m.id === 'privacy')?.available ?? false,
  });

  let draft = $state<{ evade: string; privacy: string }>({ evade: '', privacy: '' });

  // One UUID per line (commas also accepted); trims + dedupes.
  function parseSquadList(text: string): string[] {
    const out: string[] = [];
    for (const raw of text.split(/[\n,]/)) {
      const s = raw.trim();
      if (s && !out.includes(s)) out.push(s);
    }
    return out;
  }

  const save = createMutation(() => ({
    mutationFn: async () => {
      const modes: Record<string, { squadUuids: string[] }> = {};
      // Only send a mode when the admin typed something - blank keeps the current
      // binding (keep-secret-on-blank). An explicit line clears/sets the pool.
      const evade = parseSquadList(draft.evade);
      const privacy = parseSquadList(draft.privacy);
      if (draft.evade.trim()) modes.evade = { squadUuids: evade };
      if (draft.privacy.trim()) modes.privacy = { squadUuids: privacy };
      return apiClient.patch(
        '/api/v1/admin/remnawave/mode-placements',
        { modes },
        z.object({ bound: z.array(z.string()) }),
      );
    },
    onSuccess: () => {
      draft = { evade: '', privacy: '' };
      void qc.invalidateQueries({ queryKey: queryKeys.config }); // refresh `available`
      void qc.invalidateQueries({ queryKey: queryKeys.adminNodeStats });
      toast.success('Node placement saved');
    },
    onError: (err) => {
      toast.error('Could not save node placement', { description: apiErrorMessage(err) });
    },
  }));

  // Node logging privacy: enforce the no-client-IP-logging Xray posture on the
  // Remnawave config profiles (docs/privacy.md §5). Check = dry-run (read-only);
  // Apply writes the log/policy block (and restarts the affected nodes).
  let logReport = $state<z.infer<typeof RemnawaveLoggingReport> | null>(null);
  let armApply = $state(false);
  const checkLogging = createMutation(() => ({
    mutationFn: () =>
      apiClient.get('/api/v1/admin/remnawave/logging-status', RemnawaveLoggingReport),
    onSuccess: (r) => (logReport = r),
    onError: (err) =>
      toast.error('Could not read logging status', { description: apiErrorMessage(err) }),
  }));
  const applyLogging = createMutation(() => ({
    mutationFn: () =>
      apiClient.post('/api/v1/admin/remnawave/harden-logging', {}, RemnawaveLoggingReport),
    onSuccess: (r) => {
      logReport = r;
      const changed = r.instances.reduce(
        (n, i) => n + i.profiles.filter((p) => p.changed).length,
        0,
      );
      toast.success(
        changed > 0 ? `Disabled IP logging on ${changed} profile(s)` : 'Logging already hardened',
      );
    },
    onError: (err) =>
      toast.error('Could not update logging', { description: apiErrorMessage(err) }),
  }));
</script>

<AdminLayout>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-display font-bold">Remnawave</h1>
      <p class="text-sm text-muted-foreground mt-1">
        Backend-specific node placement for the Remnawave (Xray) backend.
      </p>
    </div>

    <Card>
      <CardHeader>
        <CardTitle class="text-base">Node placement pools</CardTitle>
        <CardDescription>
          Bind each connection mode to a POOL of Remnawave internal-squad UUIDs - one squad per node
          (create them on the panel, e.g. via the Ansible role). At issuance FCP homes a new key to
          the least-loaded node of the chosen mode's pool. Squad UUIDs are write-only; one per line,
          2+ = a load-balanced pool. Leave a field blank to keep the current binding. The Ansible
          panel-bootstrap sets these automatically.
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-5 text-sm">
        {#each [{ id: 'evade', label: 'Stay connected (evade)' }, { id: 'privacy', label: 'Maximize privacy (privacy)' }] as m (m.id)}
          <div
            class="space-y-2"
            class:border-t={m.id === 'privacy'}
            class:border-border={m.id === 'privacy'}
            class:pt-4={m.id === 'privacy'}
          >
            <div class="flex items-center justify-between gap-2">
              <span class="font-medium">{m.label}</span>
              <span
                class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide {cpAvailable[
                  m.id as 'evade' | 'privacy'
                ]
                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                  : 'bg-muted text-muted-foreground'}"
              >
                {cpAvailable[m.id as 'evade' | 'privacy'] ? 'Pool bound' : 'Not set'}
              </span>
            </div>
            <textarea
              rows="2"
              class="border-input focus-visible:border-ring focus-visible:ring-ring/50 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1 font-mono text-base outline-none transition-colors focus-visible:ring-3 md:text-sm placeholder:text-muted-foreground"
              placeholder={cpAvailable[m.id as 'evade' | 'privacy']
                ? 'Bound - leave blank to keep'
                : 'squad-uuid per line'}
              value={draft[m.id as 'evade' | 'privacy']}
              oninput={(e) =>
                (draft = { ...draft, [m.id]: (e.target as HTMLTextAreaElement).value })}
            ></textarea>
          </div>
        {/each}
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
          Users online per placement (squad → node), refreshed by the backend-healthcheck cron (~10
          min). Issuance picks the least-loaded fresh + online placement of a mode's pool.
        </CardDescription>
      </CardHeader>
      <CardContent class="text-sm">
        {#if nodeStats.data && nodeStats.data.length > 0}
          <div class="space-y-1">
            {#each nodeStats.data as sq (sq.placement)}
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
            No node stats yet - they populate after the first healthcheck cycle once a pool is
            bound.
          </p>
        {/if}
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle class="text-base">Node logging privacy</CardTitle>
        <CardDescription>
          Enforce the no-client-IP-logging posture on every Remnawave config profile: sets the Xray
          <code>log</code> to no access/error log and turns off the per-user online-IP tracker (<code
            >statsUserOnline</code
          >), preserving inbounds, Reality keys, and routing (a safe read-modify-write). See
          docs/privacy.md §5. Applying restarts the affected nodes (a brief reconnect).
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-4 text-sm">
        <div class="flex flex-wrap gap-2">
          <Button
            variant="outline"
            onclick={() => checkLogging.mutate()}
            disabled={checkLogging.isPending || applyLogging.isPending}
          >
            {checkLogging.isPending ? 'Checking…' : 'Check current logging'}
          </Button>
          <Button
            variant={armApply ? 'destructive' : 'default'}
            disabled={applyLogging.isPending}
            onclick={() => {
              if (armApply) {
                armApply = false;
                applyLogging.mutate();
              } else {
                armApply = true;
              }
            }}
          >
            {applyLogging.isPending
              ? 'Applying…'
              : armApply
                ? 'Confirm - restarts nodes'
                : 'Disable IP logging on all nodes'}
          </Button>
        </div>
        {#if logReport}
          {#if logReport.instances.length === 0}
            <p class="text-muted-foreground">No active Remnawave instances to configure.</p>
          {/if}
          {#each logReport.instances as inst (inst.serverId)}
            <div class="space-y-1">
              <div class="font-medium">{inst.name}</div>
              {#if !inst.ok}
                <p class="text-xs text-destructive">Couldn't reach this panel: {inst.error}</p>
              {:else if inst.profiles.length === 0}
                <p class="text-xs text-muted-foreground">No config profiles.</p>
              {:else}
                {#each inst.profiles as p (p.uuid)}
                  <div class="flex items-center justify-between gap-2">
                    <span class="truncate">{p.name}</span>
                    {#if p.error}
                      <span
                        class="shrink-0 rounded-full bg-muted px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground"
                        title={p.error}>skipped</span
                      >
                    {:else if p.hardened}
                      <span
                        class="shrink-0 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-600 dark:text-emerald-400"
                      >
                        {p.changed ? 'hardened now' : 'no logging'}
                      </span>
                    {:else}
                      <span
                        class="shrink-0 rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-600 dark:text-amber-400"
                        >logs IPs</span
                      >
                    {/if}
                  </div>
                {/each}
              {/if}
            </div>
          {/each}
        {/if}
      </CardContent>
    </Card>
  </div>
</AdminLayout>
