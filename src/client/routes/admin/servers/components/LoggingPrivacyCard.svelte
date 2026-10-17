<script lang="ts">
  /**
   * Node logging privacy: enforce the no-client-IP-logging Xray posture on
   * every Remnawave config profile (docs/privacy.md §5). Check is a dry run
   * (read-only); Apply writes the log/policy block and restarts the affected
   * nodes. Lives on Servers -> Backends.
   */
  import type { z } from 'zod';
  import { createMutation } from '@tanstack/svelte-query';
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
  import { RemnawaveLoggingReport } from '@shared/contracts/admin';

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

<Card>
  <CardHeader>
    <CardTitle class="text-base">Node logging privacy</CardTitle>
    <CardDescription>
      Enforce the no-client-IP-logging posture on every Remnawave config profile: sets the Xray
      <code>log</code> to no access/error log and turns off the per-user online-IP tracker (<code
        >statsUserOnline</code
      >), preserving transports, Reality keys, and routing (a safe read-modify-write). See
      docs/privacy.md §5. Applying restarts the affected nodes (a brief reconnect).
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-4 text-sm">
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
