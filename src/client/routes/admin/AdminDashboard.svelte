<script lang="ts">
  /**
   * Operator landing dashboard (`/admin`). Consumes the shared
   * GET /api/v1/admin/status snapshot (the same endpoint the Ansible role
   * health-gates on): a backend-healthcheck-freshness strip, member counts by
   * status, total issued keys, and a per-backend health/key panel. Read-only
   * and non-secret - there is never a backend `config` in this payload.
   */
  import AdminLayout from './AdminLayout.svelte';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AdminListState from './AdminListState.svelte';
  import { adminStatusQuery } from '../../lib/queries';
  import { formatDateTime } from '../../lib/i18n/format';
  import { formatBytes } from '../../lib/utils';
  import CheckCircle from '@lucide/svelte/icons/check-circle';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';

  const status = adminStatusQuery();

  function backendTone(b: { healthy: boolean; isActive: boolean }) {
    if (!b.isActive) return { label: 'Inactive', tone: 'bg-muted text-muted-foreground' };
    return b.healthy
      ? { label: 'Healthy', tone: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400' }
      : { label: 'Stale', tone: 'bg-amber-500/15 text-amber-600 dark:text-amber-400' };
  }

  // --- Scheduled-jobs (cron) freshness -------------------------------------
  type CronState = 'ok' | 'stale' | 'pending';
  const cronOrder: Record<CronState, number> = { stale: 0, pending: 1, ok: 2 };

  function cronTone(state: CronState) {
    if (state === 'stale')
      return { label: 'Stale', tone: 'bg-amber-500/15 text-amber-600 dark:text-amber-400' };
    if (state === 'pending') return { label: 'Pending', tone: 'bg-muted text-muted-foreground' };
    return { label: 'OK', tone: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400' };
  }

  /** Humanize a cron cadence (all jobs are 10m / 15m / 1h / 6h / daily). */
  function fmtEvery(ms: number): string {
    if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
    if (ms < 86_400_000) return `${Math.round(ms / 3_600_000)}h`;
    return 'daily';
  }

  /** Relative "last ran" from an age in seconds. */
  function ago(seconds: number | null): string {
    if (seconds == null) return 'never';
    if (seconds < 90) return `${seconds}s ago`;
    if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
    if (seconds < 129600) return `${Math.round(seconds / 3600)}h ago`;
    return `${Math.round(seconds / 86400)}d ago`;
  }

  /** Sort attention-first: stale, then pending, then ok (stable within a group). */
  function cronsSorted<T extends { state: CronState }>(crons: readonly T[]): T[] {
    return [...crons].sort((a, b) => cronOrder[a.state] - cronOrder[b.state]);
  }
</script>

{#snippet stat(label: string, value: number)}
  <Card>
    <CardContent class="py-4">
      <div class="text-2xl font-bold tabular-nums">{value}</div>
      <div class="mt-0.5 text-xs text-muted-foreground">{label}</div>
    </CardContent>
  </Card>
{/snippet}

<AdminLayout>
  <h1 class="text-2xl font-bold mb-6">Dashboard</h1>

  {#if status.isPending}
    <div class="space-y-4">
      <Skeleton class="h-16 w-full" />
      <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {#each Array(4) as _, i (i)}<Skeleton class="h-24 w-full" />{/each}
      </div>
      <Skeleton class="h-40 w-full" />
    </div>
  {:else if status.isError}
    <AdminListState error={status.error} onRetry={() => void status.refetch()} />
  {:else if status.data}
    {@const s = status.data}

    <!-- Backend-healthcheck freshness: the operator's "is routing alive?" signal. -->
    <div
      class="mb-6 flex items-center gap-2.5 rounded-xl border px-4 py-3 text-sm {s.healthcheck.ok
        ? 'border-emerald-500/40 bg-emerald-500/10'
        : 'border-amber-500/40 bg-amber-500/10'}"
    >
      {#if s.healthcheck.ok}
        <CheckCircle class="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
        <span>
          Backend healthcheck is current - last successful probe
          {s.healthcheck.staleSeconds != null ? `${s.healthcheck.staleSeconds}s ago` : 'recently'}.
        </span>
      {:else}
        <TriangleAlert class="size-4 shrink-0 text-amber-600 dark:text-amber-400" />
        <span>
          No recent backend healthcheck{s.healthcheck.lastOkAt
            ? ` (last OK ${formatDateTime(s.healthcheck.lastOkAt)})`
            : ''}. The backend-healthcheck cron or the backends may be down.
        </span>
      {/if}
    </div>

    <!-- Backend push-drift: users whose tier/status never reached the panel. Only
         shown when there's drift; links to the drift-filtered users list. -->
    {#if s.backendDrift > 0}
      <a
        href="/admin/users?drift=true"
        class="mb-6 flex items-center gap-2.5 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-700 hover:bg-amber-500/15 dark:text-amber-300"
      >
        <TriangleAlert class="size-4 shrink-0 text-amber-600 dark:text-amber-400" />
        <span>
          {s.backendDrift}
          {s.backendDrift === 1 ? 'user has' : 'users have'} unresolved backend drift - the panel may
          be out of sync with their entitlement. Review and Resync →
        </span>
      </a>
    {/if}

    <!-- Cron liveness: a loud strip when any scheduled job is overdue past its
         cadence (the scheduler or a job may be wedged). Detail is in the card below. -->
    {#if s.cronsStale > 0}
      <div
        class="mb-6 flex items-center gap-2.5 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-700 dark:text-amber-300"
      >
        <TriangleAlert class="size-4 shrink-0 text-amber-600 dark:text-amber-400" />
        <span>
          {s.cronsStale}
          {s.cronsStale === 1 ? 'scheduled job is' : 'scheduled jobs are'} overdue past their cadence
          - the cron system or a job may be wedged. See Scheduled jobs below.
        </span>
      </div>
    {/if}

    <div class="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {@render stat('Active members', s.users.active)}
      {@render stat('Expiring (grace)', s.users.grace)}
      {@render stat('Disabled', s.users.disabled)}
      {@render stat('Active keys', s.totals.keys)}
    </div>

    <Card>
      <CardHeader>
        <CardTitle class="text-lg">
          Backends - {s.totals.healthyBackends}/{s.totals.activeBackends} healthy
        </CardTitle>
      </CardHeader>
      <CardContent>
        {#if s.backends.length === 0}
          <p class="text-sm text-muted-foreground">No backend servers registered yet.</p>
        {:else}
          <ul class="divide-y divide-border text-sm">
            {#each s.backends as b (b.slug)}
              {@const t = backendTone(b)}
              <li class="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5">
                <code class="font-mono text-foreground">{b.slug}</code>
                <span class="text-xs text-muted-foreground">{b.backend}</span>
                <span class="rounded px-1.5 py-0.5 text-[11px] font-medium {t.tone}">{t.label}</span
                >
                <span class="ms-auto text-xs text-muted-foreground">
                  {b.keyCount} keys{b.lastHealthRttMs != null
                    ? ` · ${b.lastHealthRttMs}ms`
                    : ''}{b.lastHealthOkAt ? ` · ok ${formatDateTime(b.lastHealthOkAt)}` : ''}
                </span>
                {#if b.fleetStats}
                  <!-- Fleet observability (cached by the healthcheck cron). The panel
                       version surfaces contract-version drift at a glance. -->
                  <span class="w-full text-xs text-muted-foreground tabular-nums">
                    {b.fleetStats.onlineNow} online · {b.fleetStats.nodesOnline}/{b.fleetStats
                      .nodesTotal} nodes · {b.fleetStats.distinctCountries} countries · {formatBytes(
                      b.fleetStats.monthTrafficBytes,
                    )} this month · v{b.fleetStats.panelVersion}
                  </span>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </CardContent>
    </Card>

    <!-- PoP enrollment readiness (the POP_REQUIRED flip). Enforcement rejects only
         cookie-only (unbound) sessions, so it is safe to enable once none remain. -->
    <Card class="mt-6">
      <CardHeader>
        <CardTitle class="text-lg">Session protection (proof-of-possession)</CardTitle>
      </CardHeader>
      <CardContent class="space-y-2 text-sm">
        <p class="text-muted-foreground">
          {s.pop.bound}/{s.pop.activeSessions} active sessions are key-bound - a captured cookie alone
          cannot be replayed.
        </p>
        {#if s.pop.required}
          <div
            class="flex items-center gap-2.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-emerald-700 dark:text-emerald-300"
          >
            <CheckCircle class="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
            <span>Enforced - cookie-only sessions are rejected (POP_REQUIRED is on).</span>
          </div>
        {:else if s.pop.readyToEnable}
          <div
            class="flex items-center gap-2.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-emerald-700 dark:text-emerald-300"
          >
            <CheckCircle class="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
            <span
              >Safe to enable - no cookie-only sessions remain. Set <code class="font-mono"
                >POP_REQUIRED=true</code
              > to enforce.</span
            >
          </div>
        {:else}
          <div
            class="flex items-center gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-amber-700 dark:text-amber-300"
          >
            <TriangleAlert class="size-4 shrink-0 text-amber-600 dark:text-amber-400" />
            <span>
              {s.pop.unbound} cookie-only {s.pop.unbound === 1 ? 'session' : 'sessions'} ({s.pop
                .unboundMember} member · {s.pop.unboundAdmin} admin) would be logged out if POP_REQUIRED
              were enabled. Wait for these to expire or re-login before enforcing.
            </span>
          </div>
        {/if}
      </CardContent>
    </Card>

    <!-- Scheduled-jobs liveness (W4-B4): per-cron heartbeat freshness vs cadence.
         Stamped at each job's run start, so this tracks whether the scheduler is
         firing the job - independent of the job's own success. -->
    <Card class="mt-6">
      <CardHeader>
        <CardTitle class="text-lg">
          Scheduled jobs - {s.crons.filter((c) => c.state === 'ok').length}/{s.crons.length} healthy
        </CardTitle>
      </CardHeader>
      <CardContent>
        {#if s.crons.length === 0}
          <p class="text-sm text-muted-foreground">No cron heartbeats recorded yet.</p>
        {:else}
          <ul class="grid gap-x-6 gap-y-2 sm:grid-cols-2">
            {#each cronsSorted(s.crons) as c (c.name)}
              {@const t = cronTone(c.state)}
              <li class="flex items-start gap-2 py-0.5">
                <span class="mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium {t.tone}"
                  >{t.label}</span
                >
                <div class="min-w-0">
                  <div>
                    <code class="font-mono text-xs text-foreground">{c.name}</code>
                    <span class="ms-1 text-xs text-muted-foreground"
                      >every {fmtEvery(c.everyMs)}</span
                    >
                  </div>
                  <div class="text-xs text-muted-foreground">
                    {c.description} · {c.state === 'pending'
                      ? 'not yet observed'
                      : `ran ${ago(c.ageSeconds)}`}
                  </div>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
      </CardContent>
    </Card>

    <p class="mt-4 text-xs text-muted-foreground">Updated {formatDateTime(s.generatedAt)}.</p>
  {/if}
</AdminLayout>
