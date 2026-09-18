<script lang="ts">
  /**
   * One rotation (provision / publish / replace) in a side sheet: phase in words,
   * progress, steps, the event log, the audit trail, and Cancel while the run can
   * still be cancelled. Polls every 2 s until the rotation is terminal
   * (`rotationQuery`), then invalidates the relay once so the page behind it
   * catches up.
   *
   * Open by setting `rotationId` (pages keep it in `?rotation=`); `onClose` must clear it.
   *
   * Props:
   *   rotationId: string | null
   *   relaySlug: string                     for invalidateRelay(qc, slug) on terminal / cancel
   *   relayId: string                       cancel is a relay-level call
   *   onClose: () => void
   *   onOpenEdge?: (edgeId: string) => void makes the rotation's edge a button (e.g. swap to the edge drawer)
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import * as Sheet from '@client/components/ui/sheet';
  import { Button } from '@client/components/ui/button';
  import { Progress } from '@client/components/ui/progress';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Badge } from '@client/components/ui/badge';
  import { assertEdgeOk } from '../lib/edgeErrors';
  import {
    cancelRelayRotation,
    edgeKeys,
    invalidateRelay,
    rotationQuery,
  } from '@client/lib/edgesApi';
  import { codeLabel, humanizeCode, isCancellablePhase, phaseLabel } from '@client/lib/edgeCodes';
  import AdminListState from '../../AdminListState.svelte';
  import StatusBadge from './StatusBadge.svelte';
  import KeyValue from './KeyValue.svelte';
  import CodeNote from './CodeNote.svelte';
  import ConfirmDialog from './ConfirmDialog.svelte';
  import Timeline from './Timeline.svelte';
  import { providerLabel } from '../lib/format';
  import { ROTATION_KIND_LABELS, ROTATION_TRIGGER_LABELS, stepStateTone } from '../lib/rotation';
  import { durationLabel, relativeTime, shortId } from '../lib/time';
  import type { KeyValueRow } from '../lib/types';

  interface Props {
    rotationId: string | null;
    relaySlug: string;
    relayId: string;
    onClose: () => void;
    onOpenEdge?: (edgeId: string) => void;
  }
  let { rotationId, relaySlug, relayId, onClose, onOpenEdge }: Props = $props();

  const qc = useQueryClient();
  const rotation = rotationQuery(() => rotationId);
  const r = $derived(rotation.data ?? null);

  // Invalidate the relay ONCE per rotation, when it is first seen terminal.
  let settledFor: string | null = null;
  $effect(() => {
    if (r && r.terminal && settledFor !== r.id) {
      settledFor = r.id;
      invalidateRelay(qc, relaySlug);
    }
  });

  const cancellable = $derived(!!r && !r.terminal && isCancellablePhase(r.phase));
  let confirmCancel = $state(false);
  const cancel = createMutation(() => ({
    mutationFn: async () => assertEdgeOk(await cancelRelayRotation(relayId)),
    onSuccess: () => {
      toast.success('Cancel requested. The run stops at the next safe point.');
      if (rotationId) void qc.invalidateQueries({ queryKey: edgeKeys.rotation(rotationId) });
      invalidateRelay(qc, relaySlug);
    },
  }));

  const when = (iso: string | null | undefined): string =>
    iso ? `${relativeTime(iso)} (${new Date(iso).toLocaleString()})` : '';

  const summaryRows = $derived.by((): KeyValueRow[] => {
    if (!r) return [];
    const ended = r.finishedAt ? new Date(r.finishedAt).getTime() : Date.now();
    return [
      {
        label: 'Kind',
        value: ROTATION_KIND_LABELS[r.kind] + (r.burn ? ', burning the old edge' : ''),
      },
      { label: 'Started by', value: ROTATION_TRIGGER_LABELS[r.trigger] },
      { label: 'Started', value: when(r.startedAt) },
      {
        label: r.terminal ? 'Took' : 'Running for',
        value: durationLabel(ended - new Date(r.startedAt).getTime()),
      },
      { label: 'Provisioned', value: when(r.provisionedAt) },
      { label: 'Hosts switched', value: when(r.flippedAt) },
      { label: 'Finished', value: when(r.finishedAt) },
      { label: 'Forced', value: r.force ? 'Yes, limits were overridden' : '' },
      { label: 'Hosts in the plan', value: r.hostPlanSize > 0 ? r.hostPlanSize : '' },
      { label: 'Switch attempts', value: r.flipAttempts > 0 ? r.flipAttempts : '' },
      { label: 'Rollback attempts', value: r.rollbackAttempts > 0 ? r.rollbackAttempts : '' },
      { label: 'Rotation id', value: r.id, mono: true, copy: true },
    ];
  });

  const LEVEL_TONE = { info: 'muted', warn: 'warning', error: 'danger' } as const;
  const LEVEL_WORD = { info: 'Info', warn: 'Warning', error: 'Error' } as const;
  // Newest first: the operator watches the top of the list while it polls.
  const events = $derived(r ? [...r.events].reverse() : []);
</script>

<Sheet.Root
  open={rotationId !== null}
  onOpenChange={(o) => {
    if (!o) onClose();
  }}
>
  <Sheet.Content side="right" class="gap-0 sm:max-w-xl">
    <Sheet.Header class="border-b">
      <Sheet.Title>
        {r
          ? `${ROTATION_KIND_LABELS[r.kind]} on relay ${relaySlug}`
          : `Rotation on relay ${relaySlug}`}
      </Sheet.Title>
      <Sheet.Description>
        {#if r && !r.terminal}
          Running. This view updates every two seconds.
        {:else if r}
          Finished {relativeTime(r.finishedAt ?? r.updatedAt)}.
        {:else}
          Progress, events and the audit trail of one run.
        {/if}
      </Sheet.Description>
      {#if r}
        <div class="flex flex-wrap items-center gap-1.5 pt-1">
          <StatusBadge kind="phase" value={r.phase} />
          {#if r.cancelRequested && !r.terminal}
            <Badge variant="warning">Cancel requested</Badge>
          {/if}
        </div>
      {/if}
    </Sheet.Header>

    <div class="flex-1 space-y-6 overflow-y-auto p-4">
      {#if rotation.isPending}
        <div class="space-y-3" role="status">
          <span class="sr-only">Loading the rotation</span>
          <Skeleton class="h-5 w-1/2" />
          <Skeleton class="h-3 w-full" />
          <Skeleton class="h-24 w-full" />
        </div>
      {:else if rotation.isError}
        <AdminListState error={rotation.error} onRetry={() => rotation.refetch()} />
      {:else if r}
        <div aria-live="polite">
          <div class="mb-1 flex justify-between text-xs">
            <span id="rotation-progress-label">
              {phaseLabel(r.phase)}, step {r.progress.done} of {r.progress.total}
            </span>
            <span class="text-muted-foreground">{Math.round(r.progress.percent)}%</span>
          </div>
          <Progress value={r.progress.percent} aria-labelledby="rotation-progress-label" />
        </div>

        {#if r.terminal && r.phase !== 'done' && (r.reason || r.outcome)}
          <CodeNote
            issue={{ code: r.reason ?? r.outcome ?? r.phase }}
            tone={r.phase === 'failed' || r.phase === 'quarantined' ? 'blocker' : 'warning'}
          />
        {/if}

        <KeyValue title="Run" rows={summaryRows} hideEmpty />

        {#if r.edge}
          {@const e = r.edge}
          <section class="space-y-2">
            <h3 class="text-sm font-semibold">Edge</h3>
            <div class="flex flex-wrap items-center gap-1.5 text-sm">
              <span>{providerLabel(e.provider)} edge</span>
              <span class="font-mono text-xs">
                {e.addresses.hostname ?? e.addresses.v4 ?? e.addresses.v6 ?? shortId(e.id)}
              </span>
              <StatusBadge kind="status" value={e.status} />
              <StatusBadge kind="health" value={e.health} />
              {#if onOpenEdge}
                <Button size="xs" variant="outline" onclick={() => onOpenEdge(e.id)}
                  >Open edge</Button
                >
              {/if}
            </div>
          </section>
        {/if}

        {#if r.steps.length > 0}
          <section class="space-y-2">
            <h3 class="text-sm font-semibold">Provider steps</h3>
            <ol class="divide-border divide-y rounded-md border text-sm">
              {#each r.steps as s (s.stepId)}
                <li class="flex flex-wrap items-center justify-between gap-2 px-2.5 py-1.5">
                  <span>
                    {humanizeCode(s.kind)}
                    {#if s.attempt && s.attempt > 1}
                      <span class="text-muted-foreground text-xs">attempt {s.attempt}</span>
                    {/if}
                  </span>
                  <Badge variant={stepStateTone(s.state)}>{humanizeCode(s.state)}</Badge>
                </li>
              {/each}
            </ol>
          </section>
        {/if}

        <section class="space-y-2">
          <h3 class="text-sm font-semibold">Events</h3>
          {#if events.length === 0}
            <p class="text-muted-foreground text-sm">
              No events yet. They appear as the run advances.
            </p>
          {:else}
            <ol class="space-y-1.5 text-sm" aria-label="Rotation events, newest first">
              {#each events as ev, i (`${ev.at}:${ev.code}:${i}`)}
                <li class="flex gap-2">
                  <Badge variant={LEVEL_TONE[ev.level]} class="mt-0.5">{LEVEL_WORD[ev.level]}</Badge
                  >
                  <span class="min-w-0 flex-1">
                    <span>{codeLabel(ev.code.replace(/^edge\./, ''))}</span>
                    {#if ev.detail}
                      <span class="text-muted-foreground break-words">: {ev.detail}</span>
                    {/if}
                    <time
                      class="text-muted-foreground block text-xs"
                      datetime={ev.at}
                      title={new Date(ev.at).toLocaleString()}
                    >
                      {relativeTime(ev.at)}
                    </time>
                  </span>
                </li>
              {/each}
            </ol>
          {/if}
        </section>

        <section class="space-y-2">
          <h3 class="text-sm font-semibold">Audit trail</h3>
          <Timeline
            entries={r.audit}
            max={15}
            label="Rotation audit trail"
            emptyText="No audit rows are tagged with this rotation yet."
          />
        </section>
      {/if}
    </div>

    {#if r && !r.terminal}
      <Sheet.Footer>
        <p class="text-muted-foreground me-auto text-xs sm:self-center">
          {cancellable
            ? 'Cancelling stops the run at the next safe point and rolls back anything already published.'
            : 'This phase cannot be cancelled. It finishes or rolls back on its own.'}
        </p>
        <Button
          variant="destructive"
          disabled={!cancellable || r.cancelRequested || cancel.isPending}
          onclick={() => (confirmCancel = true)}
        >
          {r.cancelRequested ? 'Cancel requested' : 'Cancel rotation'}
        </Button>
      </Sheet.Footer>
    {/if}
  </Sheet.Content>
</Sheet.Root>

<ConfirmDialog
  bind:open={confirmCancel}
  title="Cancel this rotation?"
  body="The run stops at the next safe point. An edge that was already created is kept as a standby or destroyed, and a Host switch that already happened is rolled back."
  confirmLabel="Cancel rotation"
  cancelLabel="Keep running"
  danger
  onConfirm={() => cancel.mutateAsync()}
/>
