<script lang="ts">
  /**
   * Mirror sync (Admin -> Storage): for every mirror a member asked for (one
   * row per copy: a member's mirror on one provider), whether the object holds
   * what FCP would serve right now. Counts come from a maintained counter; the
   * attention line from bounded reads of copies that stayed stale, failing or
   * not uploaded past the bound (or in sync but unchecked too long). The table
   * pages the ledger by state. Hash prefixes only, never an object path or a
   * URL (each is a capability).
   */
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { z } from 'zod';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import CheckCircle from '@lucide/svelte/icons/check-circle';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminMirrorSyncQuery, queryKeys } from '../../lib/queries';
  import type { MirrorCopyAdmin, MirrorCopyState } from '../../../shared/contracts/admin';
  import AdminListState from './AdminListState.svelte';

  let filter = $state<MirrorCopyState | null>(null);
  const sync = adminMirrorSyncQuery(() => filter);
  const qc = useQueryClient();

  const summary = $derived(sync.data?.pages[0]?.summary ?? null);
  const rows = $derived((sync.data?.pages ?? []).flatMap((p) => p.page));

  const STATE_WORDS: Record<MirrorCopyState, { label: string; tone: string }> = {
    in_sync: {
      label: 'In sync',
      tone: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400',
    },
    stale: { label: 'Stale', tone: 'bg-amber-500/15 text-amber-600 dark:text-amber-400' },
    failing: { label: 'Failing', tone: 'bg-destructive/15 text-destructive' },
    never: { label: 'Not uploaded', tone: 'bg-muted text-muted-foreground' },
  };

  const REASON_WORDS: Record<string, string> = {
    content_changed: 'what FCP serves changed',
    invalidated: 'the key moved (a switch)',
    country_changed: "the member's country changed",
    reissued: 'the key was re-issued',
    policy_moved: 'the delivery policy moved during the upload',
    overwritten: 'an older upload overwrote it',
    object_mismatch: 'the public URL served another body',
    missing: 'the public URL served nothing',
    unchecked: 'not checked yet',
    fetch_failed: 'the backend body could not be fetched',
    upload_failed: 'the upload failed',
    provider_missing: 'its provider is gone',
    url_unreadable: 'the public URL does not serve it, even after a rewrite',
    url_stale: 'the public URL serves an old body, even after a rewrite',
  };

  const VERIFY_WORDS: Record<NonNullable<MirrorCopyAdmin['verify']>, string> = {
    match: 'matches',
    mismatch: 'another body',
    missing: 'nothing served',
    unreachable: 'unreachable',
  };

  function ago(at: number | null): string {
    if (at == null) return 'never';
    const s = Math.max(0, Math.round((Date.now() - at) / 1000));
    if (s < 90) return `${s}s ago`;
    if (s < 5400) return `${Math.round(s / 60)}m ago`;
    if (s < 129600) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  }

  const hours = (ms: number) => `${Math.round(ms / 3_600_000)} h`;
  const n = (c: { count: number; capped: boolean }) => `${c.count}${c.capped ? '+' : ''}`;

  const recheck = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.post('/api/v1/admin/mirror-sync/recheck', { id }, z.object({ ok: z.boolean() })),
    onSuccess: () => {
      toast.success('Re-check started', {
        description: 'The copy is rendered, rewritten and read back. Refresh in a few seconds.',
      });
      setTimeout(() => void qc.invalidateQueries({ queryKey: queryKeys.adminMirrorSync }), 5_000);
    },
    onError: (err) =>
      toast.error('Could not start a re-check', { description: apiErrorMessage(err) }),
  }));

  const FILTERS: { value: MirrorCopyState | null; label: string }[] = [
    { value: null, label: 'All' },
    { value: 'stale', label: 'Stale' },
    { value: 'failing', label: 'Failing' },
    { value: 'never', label: 'Not uploaded' },
    { value: 'in_sync', label: 'In sync' },
  ];
</script>

<Card class="mb-6">
  <CardHeader>
    <CardTitle class="text-lg">Mirror sync</CardTitle>
    <p class="text-sm text-muted-foreground">
      Every mirror a member asked for, per provider: does the object hold what FCP would serve right
      now? Checked by every refresh and read back through the member's link every few hours.
    </p>
  </CardHeader>
  <CardContent class="space-y-4">
    {#if sync.isPending}
      <Skeleton class="h-24 w-full" />
    {:else if sync.isError}
      <AdminListState error={sync.error} onRetry={() => void sync.refetch()} />
    {:else if summary}
      <div class="grid gap-3 grid-cols-2 sm:grid-cols-4">
        {#each [['In sync', summary.counts.inSync], ['Stale', summary.counts.stale], ['Failing', summary.counts.failing], ['Not uploaded', summary.counts.never]] as [label, value] (label)}
          <div class="rounded-lg border px-3 py-2">
            <div class="text-xl font-bold tabular-nums">{value}</div>
            <div class="text-xs text-muted-foreground">{label}</div>
          </div>
        {/each}
      </div>

      {#if summary.attention}
        <div
          class="flex items-start gap-2.5 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-300"
          role="status"
        >
          <TriangleAlert class="mt-0.5 size-4 shrink-0" />
          <div class="space-y-0.5">
            <p class="font-medium">Some mirrors are out of sync for too long.</p>
            {#if summary.overdue.stale.count > 0}
              <p>
                {n(summary.overdue.stale)} stale for over {hours(summary.attentionAfterMs)} (oldest {ago(
                  summary.overdue.stale.oldest,
                )}).
              </p>
            {/if}
            {#if summary.overdue.failing.count > 0}
              <p>
                {n(summary.overdue.failing)} failing for over {hours(summary.attentionAfterMs)} (oldest
                {ago(summary.overdue.failing.oldest)}).
              </p>
            {/if}
            {#if summary.overdue.never.count > 0}
              <p>
                {n(summary.overdue.never)} not uploaded for over {hours(summary.attentionAfterMs)}.
              </p>
            {/if}
            {#if summary.overdue.unchecked.count > 0}
              <p>
                {n(summary.overdue.unchecked)} in sync but not checked for over {hours(
                  summary.checkOverdueMs,
                )}: the refresh is not reaching them.
              </p>
            {/if}
          </div>
        </div>
      {:else if summary.counts.total > 0}
        <div
          class="flex items-center gap-2.5 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-700 dark:text-emerald-300"
        >
          <CheckCircle class="size-4 shrink-0" />
          <span
            >No mirror has been out of sync for longer than {hours(summary.attentionAfterMs)}.</span
          >
        </div>
      {/if}
      {#if summary.pass.running}
        <p class="text-xs text-muted-foreground">
          A full refresh pass is running (last progress {ago(summary.pass.at)}): copies it has not
          reached yet show their previous check.
        </p>
      {/if}

      <div class="flex flex-wrap gap-1.5" role="tablist" aria-label="Filter mirrors by state">
        {#each FILTERS as f (f.label)}
          <Button
            size="sm"
            variant={filter === f.value ? 'default' : 'outline'}
            role="tab"
            aria-selected={filter === f.value}
            onclick={() => (filter = f.value)}
          >
            {f.label}
          </Button>
        {/each}
      </div>

      {#if rows.length === 0}
        <p class="text-sm text-muted-foreground border border-dashed rounded-lg p-4 text-center">
          {filter ? 'No mirror in this state.' : 'No member has asked for a mirror yet.'}
        </p>
      {:else}
        <div class="space-y-2">
          {#each rows as r (r.id)}
            {@const st = STATE_WORDS[r.state]}
            <div class="rounded-lg border px-3 py-2 text-sm">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="text-xs px-2 py-0.5 rounded font-medium {st.tone}">{st.label}</span>
                  <span class="font-medium">{r.provider}</span>
                  {#if r.stub}
                    <span class="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground"
                      >unavailable stub</span
                    >
                  {/if}
                  <span class="text-xs text-muted-foreground font-mono"
                    >key {r.subscriptionId.slice(-8)}</span
                  >
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={recheck.isPending}
                  onclick={() => recheck.mutate(r.id)}
                >
                  Re-check
                </Button>
              </div>
              <div class="mt-1 text-xs text-muted-foreground space-y-0.5">
                <p>
                  {st.label} since {ago(r.since)}{r.reason
                    ? `: ${REASON_WORDS[r.reason] ?? r.reason}`
                    : ''}.
                </p>
                <p>
                  Last synced {ago(r.syncedAt)} · last check {ago(r.checkedAt)} · last upload {ago(
                    r.uploadedAt,
                  )} · public link read {ago(r.verifiedAt)}{r.verify
                    ? ` (${VERIFY_WORDS[r.verify]})`
                    : ''}
                </p>
                <p class="font-mono">
                  object {r.objectHash ?? 'unknown'} · served {r.servedHash ??
                    'unknown'}{r.servedEpoch != null ? ` · epoch ${r.servedEpoch}` : ''}
                </p>
                {#if r.failures > 0 || r.lastError}
                  <p class={r.failures > 0 ? 'text-destructive' : ''}>
                    {r.failures > 0 ? `${r.failures} failed attempt(s) in a row. ` : ''}{r.lastError
                      ? `Last failure: ${REASON_WORDS[r.lastError] ?? r.lastError}, ${ago(r.lastErrorAt)}.`
                      : ''}
                  </p>
                {/if}
              </div>
            </div>
          {/each}
        </div>
        {#if sync.hasNextPage}
          <Button
            size="sm"
            variant="outline"
            disabled={sync.isFetchingNextPage}
            onclick={() => void sync.fetchNextPage()}
          >
            {sync.isFetchingNextPage ? 'Loading…' : 'Show more'}
          </Button>
        {/if}
      {/if}
    {/if}
  </CardContent>
</Card>
