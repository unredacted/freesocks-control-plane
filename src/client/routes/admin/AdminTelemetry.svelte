<script lang="ts">
  import AdminLayout from './AdminLayout.svelte';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Input } from '@client/components/ui/input';
  import { Skeleton } from '@client/components/ui/skeleton';
  import InlineError from '../../components/InlineError.svelte';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import {
    adminTelemetryConfigQuery,
    adminTelemetrySummaryQuery,
    queryKeys,
  } from '../../lib/queries';
  import {
    AdminDiagnosticsConfig,
    AdminTelemetryEvents,
    type AdminTelemetrySummary,
  } from '@shared/contracts/telemetry';
  import { createMutation, createInfiniteQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  /**
   * Admin → Telemetry: what members' switch-server moves and issue reports are
   * saying, aggregated (reasons, trending vs the previous window, and where /
   * which networks the problems cluster on), plus the `diagnostics.*` collection
   * settings. Every row in the underlying table is UNLINKED — no user, no
   * subscription, no IP — so the raw event list is safe to show.
   */
  const qc = useQueryClient();
  const cfg = adminTelemetryConfigQuery();

  // --- settings draft (the AdminSettings pattern: seed once, then edit) -------
  let draft = $state<AdminDiagnosticsConfig>({
    enabled: true,
    cloudflareEnabled: false,
    collectCountry: true,
    collectCity: true,
    collectAsn: true,
    asnHeader: 'x-client-asn',
    retentionDays: 90,
  });
  let seeded = $state(false);
  $effect(() => {
    if (cfg.data && !seeded) {
      seeded = true;
      draft = { ...cfg.data };
    }
  });

  const save = createMutation(() => ({
    mutationFn: () => apiClient.patch('/api/v1/admin/telemetry', draft, AdminDiagnosticsConfig),
    onSuccess: (updated) => {
      draft = { ...updated };
      void qc.invalidateQueries({ queryKey: queryKeys.adminTelemetryConfig });
      toast.success('Telemetry settings saved');
    },
    onError: (err) => toast.error('Save failed', { description: apiErrorMessage(err) }),
  }));

  // --- summary window ----------------------------------------------------------
  const DAY = 86_400_000;
  const WINDOWS = [
    { label: '24 hours', ms: DAY },
    { label: '7 days', ms: 7 * DAY },
    { label: '30 days', ms: 30 * DAY },
  ];
  let windowMs = $state(7 * DAY);
  const summary = adminTelemetrySummaryQuery(() => windowMs);

  /** Trend arrow for a reason: current vs the previous equal window. */
  function trend(s: AdminTelemetrySummary, reason: string): string {
    const cur = s.reasons.current.find((r) => r.reason === reason)?.count ?? 0;
    const prev = s.reasons.previous.find((r) => r.reason === reason)?.count ?? 0;
    if (prev === 0) return cur > 0 ? 'new' : '';
    const ratio = cur / prev;
    if (ratio >= 1.5) return `▲ ${ratio.toFixed(1)}×`;
    if (ratio <= 0.67) return `▼ ${(1 / ratio).toFixed(1)}×`;
    return '≈';
  }

  /** Counts below this render as "<3": one shy member should never be a
   *  chartable singleton, even on an admin-only page. */
  const FLOOR = 3;
  const shown = (n: number) => (n > 0 && n < FLOOR ? `<${FLOOR}` : String(n));

  // --- raw events (infinite page) ----------------------------------------------
  const events = createInfiniteQuery(() => ({
    queryKey: queryKeys.adminTelemetryEvents,
    queryFn: ({ pageParam }: { pageParam: string | null }) =>
      apiClient.get(
        `/api/v1/admin/telemetry/events${pageParam ? `?cursor=${encodeURIComponent(pageParam)}` : ''}`,
        AdminTelemetryEvents,
      ),
    initialPageParam: null as string | null,
    getNextPageParam: (last: AdminTelemetryEvents) => last.nextCursor,
    staleTime: 30_000,
  }));
  const allEvents = $derived((events.data?.pages ?? []).flatMap((p) => p.events));

  const fmtAt = (iso: string) =>
    new Date(iso).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

  /** Geo cell: the submitted value, flagged when the member edited it away from
   *  what the CDN detected (the dirty-data tell). */
  function geoCell(v: string | number | null, detected: string | number | null): string {
    if (v === null) return '·';
    return v === detected || detected === null ? String(v) : `${v}*`;
  }
</script>

<AdminLayout>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-display font-bold tracking-tight">Telemetry</h1>
      <p class="text-sm text-muted-foreground mt-1">
        What members' server switches and issue reports are saying. Rows are unlinked by design: no
        user, no subscription, never an IP.
      </p>
    </div>

    <!-- Summary -->
    <Card>
      <CardHeader>
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle class="text-base">Issue trends</CardTitle>
            <CardDescription>
              Current window vs the previous equal window. * on a geo value = the member edited it
              before sending.
            </CardDescription>
          </div>
          <div class="flex gap-1">
            {#each WINDOWS as w (w.ms)}
              <Button
                size="sm"
                variant={windowMs === w.ms ? 'default' : 'outline'}
                onclick={() => (windowMs = w.ms)}
              >
                {w.label}
              </Button>
            {/each}
          </div>
        </div>
      </CardHeader>
      <CardContent class="space-y-5 text-sm">
        {#if summary.isPending}
          <Skeleton class="h-24 w-full" />
        {:else if summary.isError}
          <InlineError message={apiErrorMessage(summary.error)} />
        {:else if summary.data}
          {@const s = summary.data}
          <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div class="rounded-lg border border-border p-3">
              <div class="text-2xl font-display font-bold tabular-nums">{s.totals.current}</div>
              <div class="text-xs text-muted-foreground">
                events (prev: {s.totals.previous})
              </div>
            </div>
            <div class="rounded-lg border border-border p-3">
              <div class="text-2xl font-display font-bold tabular-nums">
                {s.totals.switch} / {s.totals.report}
              </div>
              <div class="text-xs text-muted-foreground">switches / reports</div>
            </div>
            <div class="rounded-lg border border-border p-3">
              <div class="text-2xl font-display font-bold tabular-nums">
                {s.totals.withTelemetry}
              </div>
              <div class="text-xs text-muted-foreground">with network context</div>
            </div>
            <div class="rounded-lg border border-border p-3">
              <div class="text-2xl font-display font-bold tabular-nums">{s.totals.edited}</div>
              <div class="text-xs text-muted-foreground">edited before sending</div>
            </div>
          </div>

          <div>
            <p class="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Reasons
            </p>
            {#if s.reasons.current.length === 0}
              <p class="text-muted-foreground">No events in this window.</p>
            {:else}
              <div class="overflow-x-auto">
                <table class="w-full text-sm">
                  <thead>
                    <tr class="border-b border-border text-start text-xs text-muted-foreground">
                      <th class="py-1.5 pe-4 text-start font-medium">Reason</th>
                      <th class="py-1.5 pe-4 text-start font-medium">Count</th>
                      <th class="py-1.5 pe-4 text-start font-medium">Trend</th>
                      <th class="py-1.5 pe-4 text-start font-medium">Switches</th>
                      <th class="py-1.5 text-start font-medium">Reports</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each s.reasons.current as r (r.reason)}
                      <tr class="border-b border-border/50">
                        <td class="py-1.5 pe-4 font-medium">{r.reason}</td>
                        <td class="py-1.5 pe-4 tabular-nums">{shown(r.count)}</td>
                        <td class="py-1.5 pe-4 tabular-nums">{trend(s, r.reason)}</td>
                        <td class="py-1.5 pe-4 tabular-nums">
                          {shown(s.reasons.switch.find((x) => x.reason === r.reason)?.count ?? 0)}
                        </td>
                        <td class="py-1.5 tabular-nums">
                          {shown(s.reasons.report.find((x) => x.reason === r.reason)?.count ?? 0)}
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </div>

          <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {#each [{ title: 'By location', rows: s.byLocation }, { title: 'By country', rows: s.byCountry }, { title: 'By network (ASN)', rows: s.byAsn }, { title: 'By connection mode', rows: s.byMode }, { title: 'By backend', rows: s.byBackend }] as dim (dim.title)}
              <div class="rounded-lg border border-border p-3">
                <p
                  class="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground"
                >
                  {dim.title}
                </p>
                {#if dim.rows.length === 0}
                  <p class="text-xs text-muted-foreground">No data.</p>
                {:else}
                  <ul class="space-y-1">
                    {#each dim.rows as row (row.key)}
                      <li class="flex items-baseline justify-between gap-2 text-sm">
                        <span class="truncate font-medium">{row.key}</span>
                        <span class="shrink-0 text-xs text-muted-foreground tabular-nums">
                          {shown(row.count)}{row.topReason ? ` · ${row.topReason}` : ''}
                        </span>
                      </li>
                    {/each}
                  </ul>
                {/if}
              </div>
            {/each}
          </div>

          {#if s.truncated}
            <p class="text-xs text-amber-600">
              The window holds more events than one summary reads (20k). Narrow the window for exact
              numbers.
            </p>
          {/if}
        {/if}
      </CardContent>
    </Card>

    <!-- Raw events -->
    <Card>
      <CardHeader>
        <CardTitle class="text-base">Recent events</CardTitle>
        <CardDescription>
          Newest first. Geo columns show the member-sent value; * = edited away from what the CDN
          detected; · = not shared.
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-3 text-sm">
        {#if events.isPending}
          <Skeleton class="h-24 w-full" />
        {:else if events.isError}
          <InlineError message={apiErrorMessage(events.error)} />
        {:else if allEvents.length === 0}
          <p class="text-muted-foreground">No events recorded yet.</p>
        {:else}
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-border text-xs text-muted-foreground">
                  <th class="py-1.5 pe-4 text-start font-medium">When</th>
                  <th class="py-1.5 pe-4 text-start font-medium">Kind</th>
                  <th class="py-1.5 pe-4 text-start font-medium">Reason</th>
                  <th class="py-1.5 pe-4 text-start font-medium">Location</th>
                  <th class="py-1.5 pe-4 text-start font-medium">Mode</th>
                  <th class="py-1.5 pe-4 text-start font-medium">Country</th>
                  <th class="py-1.5 pe-4 text-start font-medium">City</th>
                  <th class="py-1.5 text-start font-medium">ASN</th>
                </tr>
              </thead>
              <tbody>
                {#each allEvents as e (e.id)}
                  <tr class="border-b border-border/50">
                    <td class="py-1.5 pe-4 whitespace-nowrap tabular-nums">{fmtAt(e.at)}</td>
                    <td class="py-1.5 pe-4">{e.kind}</td>
                    <td class="py-1.5 pe-4 font-medium">{e.reason}</td>
                    <td class="py-1.5 pe-4">{e.locationCode ?? '·'}</td>
                    <td class="py-1.5 pe-4">{e.connectionModeId ?? '·'}</td>
                    <td class="py-1.5 pe-4 tabular-nums">{geoCell(e.country, e.detectedCountry)}</td
                    >
                    <td class="py-1.5 pe-4">{geoCell(e.city, e.detectedCity)}</td>
                    <td class="py-1.5 tabular-nums">
                      {geoCell(
                        e.asn !== null ? `AS${e.asn}` : null,
                        e.detectedAsn !== null ? `AS${e.detectedAsn}` : null,
                      )}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if events.hasNextPage}
            <Button
              variant="outline"
              size="sm"
              onclick={() => events.fetchNextPage()}
              disabled={events.isFetchingNextPage}
            >
              {events.isFetchingNextPage ? 'Loading…' : 'Load more'}
            </Button>
          {/if}
        {/if}
      </CardContent>
    </Card>

    <!-- Settings -->
    <Card>
      <CardHeader>
        <CardTitle class="text-base">Collection settings</CardTitle>
        <CardDescription>
          What the switch-server and report-issue dialogs may collect. Members see the exact values
          before sending, can edit them, and can decline with one checkbox. Geo prefill needs
          Cloudflare in front: country/city come from the free "Add visitor location headers"
          Managed Transform (cf-ipcountry / cf-ipcity); ASN needs a Transform Rule that sets the
          header below from <code class="font-mono text-xs">ip.src.asnum</code>.
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-3 text-sm">
        {#if cfg.isError}
          <InlineError message={apiErrorMessage(cfg.error)} />
        {/if}
        <label class="flex items-center gap-3">
          <Checkbox
            checked={draft.enabled}
            onCheckedChange={(v) => (draft = { ...draft, enabled: v === true })}
          />
          <span>Record issue telemetry (reasons always; geo per the toggles below)</span>
        </label>
        <label class="flex items-center gap-3">
          <Checkbox
            checked={draft.cloudflareEnabled}
            onCheckedChange={(v) => (draft = { ...draft, cloudflareEnabled: v === true })}
          />
          <span>
            Cloudflare is in front: trust its geo headers for the member-visible prefill
          </span>
        </label>
        <div class="grid gap-2 sm:grid-cols-3">
          <label class="flex items-center gap-3">
            <Checkbox
              checked={draft.collectCountry}
              onCheckedChange={(v) => (draft = { ...draft, collectCountry: v === true })}
            />
            <span>Country</span>
          </label>
          <label class="flex items-center gap-3">
            <Checkbox
              checked={draft.collectCity}
              onCheckedChange={(v) => (draft = { ...draft, collectCity: v === true })}
            />
            <span>City</span>
          </label>
          <label class="flex items-center gap-3">
            <Checkbox
              checked={draft.collectAsn}
              onCheckedChange={(v) => (draft = { ...draft, collectAsn: v === true })}
            />
            <span>Network (ASN)</span>
          </label>
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <div>
            <label class="mb-1 block text-xs text-muted-foreground" for="diag-asn-header">
              ASN header name
            </label>
            <Input
              id="diag-asn-header"
              value={draft.asnHeader}
              placeholder="x-client-asn"
              oninput={(e) =>
                (draft = { ...draft, asnHeader: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="mb-1 block text-xs text-muted-foreground" for="diag-retention">
              Retention (days, 1-365)
            </label>
            <Input
              id="diag-retention"
              type="number"
              min="1"
              max="365"
              value={String(draft.retentionDays)}
              oninput={(e) =>
                (draft = {
                  ...draft,
                  retentionDays: Number((e.target as HTMLInputElement).value) || 90,
                })}
            />
          </div>
        </div>
        <div class="flex justify-end">
          {#if !seeded}
            <span class="me-3 self-center text-xs text-muted-foreground"
              >Loading current values…</span
            >
          {/if}
          <Button onclick={() => save.mutate()} disabled={save.isPending || !seeded}>
            {save.isPending ? 'Saving…' : 'Save telemetry settings'}
          </Button>
        </div>
      </CardContent>
    </Card>
  </div>
</AdminLayout>
