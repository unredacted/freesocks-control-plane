<script lang="ts">
  /**
   * Operator landing dashboard (`/admin`). Consumes the shared
   * GET /api/v1/admin/status snapshot (the same endpoint the Ansible role
   * health-gates on): a backend-healthcheck-freshness strip, member counts by
   * status, total issued keys, and a per-backend health/key panel. Read-only
   * and non-secret — there is never a backend `config` in this payload.
   */
  import AdminLayout from './AdminLayout.svelte';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AdminListState from './AdminListState.svelte';
  import { adminStatusQuery } from '../../lib/queries';
  import { formatDateTime } from '../../lib/i18n/format';
  import CheckCircle from '@lucide/svelte/icons/check-circle';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';

  const status = adminStatusQuery();

  function backendTone(b: { healthy: boolean; isActive: boolean }) {
    if (!b.isActive) return { label: 'Inactive', tone: 'bg-muted text-muted-foreground' };
    return b.healthy
      ? { label: 'Healthy', tone: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400' }
      : { label: 'Stale', tone: 'bg-amber-500/15 text-amber-600 dark:text-amber-400' };
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
          Backend healthcheck is current — last successful probe
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

    <div class="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {@render stat('Active members', s.users.active)}
      {@render stat('Expiring (grace)', s.users.grace)}
      {@render stat('Disabled', s.users.disabled)}
      {@render stat('Active keys', s.totals.keys)}
    </div>

    <Card>
      <CardHeader>
        <CardTitle class="text-lg">
          Backends — {s.totals.healthyBackends}/{s.totals.activeBackends} healthy
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
              </li>
            {/each}
          </ul>
        {/if}
      </CardContent>
    </Card>

    <p class="mt-4 text-xs text-muted-foreground">Updated {formatDateTime(s.generatedAt)}.</p>
  {/if}
</AdminLayout>
