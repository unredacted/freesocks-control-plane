<script lang="ts">
  /**
   * Node logging privacy: enforce the no-client-IP-logging Xray posture on
   * every Remnawave config profile (docs/privacy.md §5). Check is a dry run
   * (read-only); Apply writes the log/policy block and restarts the affected
   * nodes. The hourly `logging-privacy` cron does the same as Apply on its own;
   * the newest check (whoever ran it) is shown as one line. Lives on Servers ->
   * Backends.
   */
  import type { z } from 'zod';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
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
  import { adminLoggingLastCheckQuery, queryKeys } from '@client/lib/queries';
  import { RemnawaveLoggingReport, type RemnawaveLoggingLastCheck } from '@shared/contracts/admin';
  import { ago } from '../lib/words';

  const qc = useQueryClient();
  const lastCheck = adminLoggingLastCheckQuery();
  const refreshLastCheck = () =>
    void qc.invalidateQueries({ queryKey: queryKeys.adminLoggingLastCheck });

  // Keeps "12 minutes ago" moving while the page stays open.
  let now = $state(Date.now());
  $effect(() => {
    const timer = setInterval(() => (now = Date.now()), 60_000);
    return () => clearInterval(timer);
  });

  const count = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

  /** "Last checked 12 minutes ago (automatic): 4 profiles, no logging." */
  function lastCheckLine(c: RemnawaveLoggingLastCheck, at: number): string {
    const who = c.source === 'automatic' ? 'automatic' : 'by an admin';
    const head = `Last checked ${ago(Math.max(0, at - c.at))} (${who})`;
    if (c.panels === 0) return `${head}: no Remnawave panels to check.`;
    const notes: string[] = [];
    if (c.profilesTurnedOff > 0)
      notes.push(`turned logging off on ${count(c.profilesTurnedOff, 'profile', 'profiles')}`);
    const stillLogging = c.profilesLogging - c.profilesTurnedOff;
    if (stillLogging > 0)
      notes.push(`${count(stillLogging, 'profile is', 'profiles are')} logging`);
    if (c.panelsUnreadable > 0)
      notes.push(`${count(c.panelsUnreadable, 'panel', 'panels')} could not be read`);
    if (c.panelsBusy > 0)
      notes.push(
        `${count(c.panelsBusy, 'panel was', 'panels were')} only read while a server change runs there`,
      );
    if (c.profilesSkipped > 0)
      notes.push(`${count(c.profilesSkipped, 'profile', 'profiles')} could not be checked`);
    if (notes.length === 0)
      return `${head}: ${count(c.profiles, 'profile', 'profiles')}, no logging.`;
    return `${head}: ${notes.join(', ')}.`;
  }

  let logReport = $state<z.infer<typeof RemnawaveLoggingReport> | null>(null);
  let armApply = $state(false);
  const checkLogging = createMutation(() => ({
    mutationFn: () =>
      apiClient.get('/api/v1/admin/remnawave/logging-status', RemnawaveLoggingReport),
    onSuccess: (r) => {
      logReport = r;
      refreshLastCheck();
    },
    onError: (err) =>
      toast.error('Could not read logging status', { description: apiErrorMessage(err) }),
  }));
  const applyLogging = createMutation(() => ({
    mutationFn: () =>
      apiClient.post('/api/v1/admin/remnawave/harden-logging', {}, RemnawaveLoggingReport),
    onSuccess: (r) => {
      logReport = r;
      refreshLastCheck();
      const changed = r.instances.reduce(
        (n, i) => n + i.profiles.filter((p) => p.changed).length,
        0,
      );
      toast.success(
        changed > 0 ? `Disabled IP logging on ${changed} profile(s)` : 'Logging already hardened',
      );
    },
    onError: (err) => {
      refreshLastCheck();
      toast.error('Could not update logging', { description: apiErrorMessage(err) });
    },
  }));
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Node logging privacy</CardTitle>
    <CardDescription>
      Keeps client IPs out of node logs on every Remnawave config profile. It turns off the Xray
      <code>log</code> access and error logs and the per-user online-IP tracker,
      <code>statsUserOnline</code>. Transports, REALITY keys and routing are kept. See
      docs/privacy.md §5. Applying briefly restarts the affected nodes. FCP checks every hour and
      turns logging off on its own wherever it finds it.
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-4 text-sm">
    {#if lastCheck.data}
      <p class="text-muted-foreground">
        {lastCheck.data.lastCheck
          ? lastCheckLine(lastCheck.data.lastCheck, now)
          : 'Not checked yet. The first automatic check runs within the hour.'}
      </p>
    {:else if lastCheck.isError}
      <p class="text-muted-foreground">Could not load the last check.</p>
    {/if}
    <div class="flex flex-wrap gap-2">
      <Button
        variant="outline"
        onclick={() => {
          // A fresh check disarms a pending apply — the admin should re-arm
          // against the NEW report, not fire on a stale one.
          armApply = false;
          checkLogging.mutate();
        }}
        disabled={checkLogging.isPending || applyLogging.isPending}
      >
        {checkLogging.isPending ? 'Checking…' : 'Check current logging'}
      </Button>
      <Button
        variant={armApply ? 'destructive' : 'default'}
        disabled={applyLogging.isPending || checkLogging.isPending}
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
