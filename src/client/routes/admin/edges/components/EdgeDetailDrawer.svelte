<script lang="ts">
  /**
   * One edge in a side sheet: identity, addresses, publication, readiness,
   * qualification, provider resources, reachability, recent probes and the live
   * provider snapshot ("Refresh live" pulls a new one; "Show raw" reveals the
   * recorded provider payload, hidden by default).
   *
   * Open by setting `edgeId` (pages keep it in `?edge=` through searchParam, a
   * search-only change that does not remount the page); `onClose` must clear it.
   *
   * Props:
   *   edgeId: string | null
   *   onClose: () => void
   *   actions?: Snippet<[EdgeAdmin]>        footer buttons for the loaded edge (publish, replace, ...)
   */
  import type { Snippet } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import type { EdgeAdmin } from '@shared/contracts/edges';
  import * as Sheet from '@client/components/ui/sheet';
  import { Button } from '@client/components/ui/button';
  import { Progress } from '@client/components/ui/progress';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Badge } from '@client/components/ui/badge';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import {
    edgeDetailQuery,
    edgeKeys,
    edgeLiveQuery,
    invalidateEdge,
    refreshEdgeLive,
  } from '@client/lib/edgesApi';
  import { codeLabel, humanizeCode, readinessTone, READINESS_LABELS } from '@client/lib/edgeCodes';
  import { countryName } from '@client/lib/countries';
  import AdminListState from '../../AdminListState.svelte';
  import StatusBadge from './StatusBadge.svelte';
  import LayerBadge from './LayerBadge.svelte';
  import KeyValue from './KeyValue.svelte';
  import CodeNote from './CodeNote.svelte';
  import { formatBytes, providerLabel } from '../lib/format';
  import { relativeTime, shortId } from '../lib/time';
  import type { KeyValueRow } from '../lib/types';

  interface Props {
    edgeId: string | null;
    onClose: () => void;
    actions?: Snippet<[EdgeAdmin]>;
  }
  let { edgeId, onClose, actions }: Props = $props();

  const qc = useQueryClient();
  const detail = edgeDetailQuery(() => edgeId);
  const liveQ = edgeLiveQuery(() => edgeId);

  let showRaw = $state(false);
  $effect(() => {
    void edgeId;
    showRaw = false;
  });

  const edge = $derived(detail.data?.edge ?? null);
  const live = $derived(liveQ.data?.live ?? detail.data?.live ?? null);

  const refresh = createMutation(() => ({
    mutationFn: (id: string) => refreshEdgeLive(id),
    onSuccess: (data, id) => {
      qc.setQueryData(edgeKeys.edgeLive(id), data);
      invalidateEdge(qc, id);
      toast.success(data.live ? 'Live snapshot refreshed' : 'The provider returned no snapshot');
    },
    onError: (e) => toast.error(edgeErrorMessage(e)),
  }));

  const when = (iso: string | null | undefined): string =>
    iso ? `${relativeTime(iso)} (${new Date(iso).toLocaleString()})` : '';

  const building = $derived(
    !!edge && ['planning', 'provisioning', 'verifying', 'destroying'].includes(edge.status),
  );

  const identityRows = $derived.by((): KeyValueRow[] => {
    if (!edge) return [];
    return [
      { label: 'Name', value: edge.name, mono: true, copy: true },
      { label: 'Provider', value: providerLabel(edge.provider) },
      {
        label: 'Managed by FCP',
        value: edge.managed,
        hint: edge.managed ? undefined : 'Imported: FCP never deletes it at the provider.',
      },
      { label: 'Pool slot', value: edge.poolIndex === null ? '' : `Slot ${edge.poolIndex + 1}` },
      { label: 'IPv4', value: edge.addresses.v4, mono: true, copy: true },
      { label: 'IPv6', value: edge.addresses.v6, mono: true, copy: true },
      { label: 'Hostname', value: edge.addresses.hostname, mono: true, copy: true },
      { label: 'Edge id', value: edge.id, mono: true, copy: true },
    ];
  });
  const timeRows = $derived.by((): KeyValueRow[] => {
    if (!edge) return [];
    return [
      { label: 'Created', value: when(edge.createdAt) },
      { label: 'Status changed', value: when(edge.statusChangedAt) },
      { label: 'Published', value: when(edge.publishedAt) },
      { label: 'Last health check', value: when(edge.lastHealthAt) },
      { label: 'Draining until', value: when(edge.drainUntil) },
      { label: 'Burned', value: when(edge.burnedAt) },
      { label: 'Destroyed', value: when(edge.destroyedAt) },
      { label: 'Destroy attempts', value: edge.destroyAttempts > 0 ? edge.destroyAttempts : '' },
    ];
  });
  const liveRows = $derived.by((): KeyValueRow[] => {
    if (!live) return [];
    const s = live.summary;
    return [
      { label: 'Provider status', value: s.status ? humanizeCode(s.status) : '' },
      {
        label: 'Operating status',
        value: s.operatingStatus ? humanizeCode(s.operatingStatus) : '',
      },
      { label: 'Size', value: s.flavor },
      { label: 'Region', value: s.region },
      { label: 'IPv4', value: s.addresses.v4, mono: true, copy: true },
      { label: 'IPv6', value: s.addresses.v6, mono: true, copy: true },
      { label: 'Hostname', value: s.addresses.hostname, mono: true, copy: true },
      { label: 'Connections', value: s.stats?.connections },
      { label: 'Traffic in', value: formatBytes(s.stats?.bytesIn) },
      { label: 'Traffic out', value: formatBytes(s.stats?.bytesOut) },
    ];
  });
  const rawText = $derived.by(() => {
    if (!live) return '';
    try {
      return JSON.stringify(live.raw, null, 2) ?? '';
    } catch {
      return String(live.raw);
    }
  });

  const VERDICT_TONE = {
    reachable: 'success',
    unreachable: 'danger',
    mixed: 'warning',
    unknown: 'muted',
  } as const;
  const DELETE_STATE_WORDS = {
    present: 'Present',
    delete_requested: 'Delete requested',
    confirmed_gone: 'Gone',
  } as const;
</script>

<Sheet.Root
  open={edgeId !== null}
  onOpenChange={(o) => {
    if (!o) onClose();
  }}
>
  <Sheet.Content side="right" class="gap-0 sm:max-w-xl">
    <Sheet.Header class="border-b">
      <Sheet.Title>{edge ? `Edge ${edge.name}` : 'Edge'}</Sheet.Title>
      <Sheet.Description>
        {edge
          ? `${providerLabel(edge.provider)} edge, status changed ${relativeTime(edge.statusChangedAt)}.`
          : 'Identity, publication and the live provider snapshot of one edge.'}
      </Sheet.Description>
      {#if edge}
        <div class="flex flex-wrap items-center gap-1.5 pt-1">
          <LayerBadge layer={edge.layer} />
          <StatusBadge kind="status" value={edge.status} />
          <StatusBadge kind="publication" value={edge.publication} />
          <StatusBadge kind="health" value={edge.health} />
        </div>
      {/if}
    </Sheet.Header>

    <div class="flex-1 space-y-6 overflow-y-auto p-4">
      {#if detail.isPending}
        <div class="space-y-3" role="status">
          <span class="sr-only">Loading the edge</span>
          <Skeleton class="h-5 w-1/2" />
          <Skeleton class="h-24 w-full" />
          <Skeleton class="h-24 w-full" />
        </div>
      {:else if detail.isError}
        <AdminListState error={detail.error} onRetry={() => detail.refetch()} />
      {:else if edge}
        {#if building}
          <div>
            <div class="mb-1 flex justify-between text-xs">
              <span id="edge-progress-label"
                >Steps {edge.progress.done} of {edge.progress.total}</span
              >
              <span class="text-muted-foreground">{Math.round(edge.progress.percent)}%</span>
            </div>
            <Progress value={edge.progress.percent} aria-labelledby="edge-progress-label" />
          </div>
        {/if}
        {#if edge.failure}
          <CodeNote
            issue={{
              code: edge.failure.code ?? 'provision_failed',
              detail: `Failed at step ${humanizeCode(edge.failure.step)}${edge.failure.status ? `, provider status ${edge.failure.status}` : ''}`,
            }}
            tone="blocker"
          />
        {/if}

        <KeyValue title="Identity" rows={identityRows} hideEmpty />
        <KeyValue title="Times" rows={timeRows} hideEmpty />

        {#if edge.readiness}
          <section class="space-y-2">
            <h3 class="text-sm font-semibold">Front readiness</h3>
            <div class="flex flex-wrap gap-1.5 text-sm">
              {#each [['DNS', edge.readiness.dns], ['Certificate', edge.readiness.certificate], ['Front', edge.readiness.front]] as [name, state] (name)}
                <Badge variant={readinessTone(state ?? 'unknown')}>
                  {name}: {READINESS_LABELS[state ?? 'unknown'] ?? humanizeCode(state ?? 'unknown')}
                </Badge>
              {/each}
            </div>
            <p class="text-muted-foreground text-xs">
              Checked {relativeTime(edge.readiness.checkedAt)}.
            </p>
          </section>
        {/if}

        {#if edge.frontQualification}
          {@const fq = edge.frontQualification}
          <section class="space-y-2">
            <h3 class="text-sm font-semibold">Front qualification</h3>
            <div class="flex flex-wrap items-center gap-1.5">
              <Badge variant={fq.ok && fq.current ? 'success' : fq.ok ? 'warning' : 'danger'}>
                {fq.ok
                  ? fq.current
                    ? 'Proven end to end'
                    : 'Proof is out of date'
                  : 'Proof failed'}
              </Badge>
              <span class="text-muted-foreground text-xs">
                checked {relativeTime(fq.checkedAt)}, expires {relativeTime(fq.expiresAt)}
              </span>
            </div>
            {#if !fq.ok && fq.code}
              <CodeNote issue={{ code: fq.code }} tone="warning" compact />
            {/if}
          </section>
        {/if}

        {#if edge.listeners.length > 0}
          <section class="space-y-2">
            <h3 class="text-sm font-semibold">Forwarding</h3>
            <ul class="space-y-1 text-sm">
              {#each edge.listeners as l (`${l.edgePort}:${l.originPort}`)}
                <li class="font-mono text-xs">
                  port {l.edgePort} <span aria-hidden="true">→</span><span class="sr-only">to</span>
                  {l.originAddress}:{l.originPort}
                </li>
              {/each}
            </ul>
          </section>
        {/if}

        {#if edge.resources.length > 0}
          <section class="space-y-2">
            <h3 class="text-sm font-semibold">Provider resources</h3>
            <ul class="divide-border divide-y rounded-md border text-sm">
              {#each edge.resources as r (`${r.stepId}:${r.resourceId}`)}
                <li class="flex flex-wrap items-center justify-between gap-2 px-2.5 py-1.5">
                  <span>
                    {humanizeCode(r.kind)}
                    <span class="text-muted-foreground font-mono text-xs"
                      >{shortId(r.resourceId, 10)}</span
                    >
                  </span>
                  <span class="flex gap-1">
                    <Badge variant="outline"
                      >{r.ownership === 'created' ? 'Created by FCP' : 'Imported'}</Badge
                    >
                    <Badge
                      variant={r.deleteState === 'present'
                        ? 'neutral'
                        : r.deleteState === 'confirmed_gone'
                          ? 'muted'
                          : 'warning'}
                    >
                      {DELETE_STATE_WORDS[r.deleteState]}
                    </Badge>
                  </span>
                </li>
              {/each}
            </ul>
          </section>
        {/if}

        <section class="space-y-2">
          <h3 class="text-sm font-semibold">Reachability by country</h3>
          {#if edge.reachability && edge.reachability.byCountry.length > 0}
            <ul class="flex flex-wrap gap-1.5">
              {#each edge.reachability.byCountry as c (c.country)}
                <li>
                  <Badge
                    variant={VERDICT_TONE[c.verdict]}
                    title={`${countryName(c.country, 'en')}: ${c.okVantages} ok, ${c.failVantages} failing, ${relativeTime(c.lastAt)}`}
                  >
                    {c.country}: {humanizeCode(c.verdict).toLowerCase()}
                  </Badge>
                </li>
              {/each}
            </ul>
            <p class="text-muted-foreground text-xs">
              Updated {relativeTime(edge.reachability.updatedAt)}.
            </p>
          {:else}
            <p class="text-muted-foreground text-sm">
              No probe has measured this edge yet. Run a probe from the relay page to get a verdict.
            </p>
          {/if}
        </section>

        {#if detail.data && detail.data.probes.length > 0}
          <section class="space-y-2">
            <h3 class="text-sm font-semibold">Recent probes</h3>
            <ul class="space-y-1 text-sm">
              {#each detail.data.probes as p (p.id)}
                <li class="flex flex-wrap justify-between gap-2">
                  <span>{humanizeCode(p.source)}, {humanizeCode(p.status).toLowerCase()}</span>
                  <span class="text-muted-foreground text-xs">
                    {p.okVantages} ok, {p.failVantages} failing · {relativeTime(p.requestedAt)}
                  </span>
                </li>
              {/each}
            </ul>
          </section>
        {/if}

        <section class="space-y-3">
          <KeyValue
            title="Live at the provider"
            description={live
              ? `Snapshot taken ${relativeTime(live.liveAt)}.`
              : 'No snapshot recorded yet. Refresh to ask the provider now.'}
            rows={liveRows}
            hideEmpty
          >
            {#snippet actions()}
              <Button
                size="sm"
                variant="outline"
                disabled={refresh.isPending || !edgeId}
                onclick={() => edgeId && refresh.mutate(edgeId)}
              >
                <RefreshCw class={refresh.isPending ? 'animate-spin' : ''} aria-hidden="true" />
                {refresh.isPending ? 'Refreshing…' : 'Refresh live'}
              </Button>
            {/snippet}
          </KeyValue>
          {#if live}
            {#if live.summary.members.length > 0}
              <div>
                <h4 class="text-muted-foreground mb-1 text-xs">Members</h4>
                <ul class="space-y-0.5 font-mono text-xs">
                  {#each live.summary.members as m (`${m.address}:${m.port}`)}
                    <li>
                      {m.address}:{m.port}
                      {#if m.health}
                        <span class="text-muted-foreground font-sans">{codeLabel(m.health)}</span>
                      {/if}
                    </li>
                  {/each}
                </ul>
              </div>
            {/if}
            {#if live.summary.listeners.length > 0}
              <div>
                <h4 class="text-muted-foreground mb-1 text-xs">Listeners</h4>
                <p class="font-mono text-xs">
                  {live.summary.listeners
                    .map((l) => `${l.port}${l.protocol ? ` ${l.protocol}` : ''}`)
                    .join(', ')}
                </p>
              </div>
            {/if}
            <div>
              <Button
                size="sm"
                variant="ghost"
                aria-expanded={showRaw}
                aria-controls="edge-live-raw"
                onclick={() => (showRaw = !showRaw)}
              >
                {showRaw ? 'Hide raw' : 'Show raw'}
              </Button>
              {#if showRaw}
                <p class="text-muted-foreground mt-1 text-xs">
                  The provider's own description of the resource, for diagnostics. It can contain
                  provider-internal identifiers: do not paste it into public places.
                </p>
                <pre
                  id="edge-live-raw"
                  class="bg-muted mt-2 max-h-80 overflow-auto rounded-md p-2 text-xs"
                  tabindex="0">{rawText}</pre>
              {/if}
            </div>
          {/if}
        </section>
      {/if}
    </div>

    {#if actions && edge}
      <Sheet.Footer class="border-t">{@render actions(edge)}</Sheet.Footer>
    {/if}
  </Sheet.Content>
</Sheet.Root>
