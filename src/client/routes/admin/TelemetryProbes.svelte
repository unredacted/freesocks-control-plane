<script lang="ts">
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
  import * as Dialog from '@client/components/ui/dialog';
  import { Skeleton } from '@client/components/ui/skeleton';
  import InlineError from '../../components/InlineError.svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import {
    adminProbeAuditQuery,
    adminProbeMatrixQuery,
    adminProbeRunsQuery,
    adminProbeTargetsQuery,
    adminRelayConfigQuery,
    queryKeys,
  } from '../../lib/queries';
  import {
    ProbeManyRequestedResponse,
    ProbeTargetCreatedResponse,
    RelayConfigPatchResponse,
    RelayOkResponse,
    type ProbeMatrixTarget,
    type ProbeTargetAdmin,
  } from '../../../shared/contracts/relays';
  import { formatDateTime } from '../../lib/i18n/format';
  import ProbeTimeChart from './ProbeTimeChart.svelte';

  /**
   * Telemetry → Probes: reachability of FCP's own addresses as measured from
   * the configured countries. Targets are the edges of every relay, relay nodes
   * that opted in, and operator-entered custom host:port pairs. Only edge
   * evidence reaches the block detector; everything else here is operator
   * evidence. No member data is involved anywhere on this page.
   */
  const qc = useQueryClient();
  const cfg = adminRelayConfigQuery();
  const matrix = adminProbeMatrixQuery();
  const targets = adminProbeTargetsQuery();
  const audit = adminProbeAuditQuery();
  const onError = (title: string) => (err: unknown) =>
    toast.error(title, { description: apiErrorMessage(err) });
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['admin', 'relays'] });
  };

  // --- settings (the relay.probe.* namespace; tokens are write-only) -----------
  let patch = $state<Record<string, unknown>>({});
  let secrets = $state({ globalpingToken: '', ripeAtlasKey: '' });
  function set(path: string, value: unknown) {
    patch = { ...patch, [path]: value };
  }
  function get<T>(path: string, fallback: T): T {
    if (path in patch) return patch[path] as T;
    const c = cfg.data?.config as Record<string, unknown> | undefined;
    if (!c) return fallback;
    const v = path
      .split('.')
      .reduce<unknown>(
        (acc, k) =>
          acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[k] : undefined,
        c,
      );
    return (v as T | undefined) ?? fallback;
  }
  const num = (path: string, fallback: number) => Number(get(path, fallback));
  function nested(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [path, value] of Object.entries(patch)) {
      const parts = path.split('.');
      let cur = out;
      for (const p of parts.slice(0, -1)) {
        if (!cur[p] || typeof cur[p] !== 'object') cur[p] = {};
        cur = cur[p] as Record<string, unknown>;
      }
      cur[parts[parts.length - 1] ?? path] = value;
    }
    const s = Object.fromEntries(Object.entries(secrets).filter(([, v]) => v.trim() !== ''));
    if (Object.keys(s).length > 0) out.secrets = s;
    return out;
  }
  const dirty = $derived(
    Object.keys(patch).length > 0 || secrets.globalpingToken !== '' || secrets.ripeAtlasKey !== '',
  );
  const save = createMutation(() => ({
    mutationFn: () =>
      apiClient.patch('/api/v1/admin/relay/config', nested(), RelayConfigPatchResponse),
    onSuccess: (r) => {
      patch = {};
      secrets = { globalpingToken: '', ripeAtlasKey: '' };
      void qc.invalidateQueries({ queryKey: queryKeys.adminRelayConfig });
      invalidate();
      toast.success(
        r.changedKeys.length
          ? `Saved ${r.changedKeys.length} setting${r.changedKeys.length === 1 ? '' : 's'}`
          : 'Nothing changed',
      );
    },
    onError: onError('Could not save the probe settings'),
  }));

  // --- probe now (any selection of targets) ------------------------------------
  let selected = $state<Set<string>>(new Set());
  function toggle(key: string, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(key);
    else next.delete(key);
    selected = next;
  }
  const probeNow = createMutation(() => ({
    mutationFn: (keys: string[]) =>
      apiClient.post('/api/v1/admin/relay/probes', { targets: keys }, ProbeManyRequestedResponse),
    onSuccess: (r) => {
      selected = new Set();
      invalidate();
      toast.success(
        `${r.runIds.length} probe run${r.runIds.length === 1 ? '' : 's'} requested${
          r.skipped.length ? `, ${r.skipped.length} target(s) skipped` : ''
        }`,
      );
    },
    onError: onError('Probe request refused'),
  }));

  // --- custom targets ------------------------------------------------------------------
  type Draft = {
    id: string | null;
    label: string;
    address: string;
    port: number;
    enabled: boolean;
    notes: string;
  };
  let editor = $state<Draft | null>(null);
  const newDraft = (): Draft => ({
    id: null,
    label: '',
    address: '',
    port: 443,
    enabled: true,
    notes: '',
  });
  const editDraft = (t: ProbeTargetAdmin): Draft => ({
    id: t.id,
    label: t.label,
    address: t.address,
    port: t.port,
    enabled: t.enabled,
    notes: t.notes ?? '',
  });
  const saveTarget = createMutation(() => ({
    mutationFn: async () => {
      const d = editor!;
      const body = {
        label: d.label.trim(),
        address: d.address.trim(),
        port: Number(d.port) || 443,
        enabled: d.enabled,
        notes: d.notes.trim(),
      };
      if (d.id)
        return apiClient.patch(`/api/v1/admin/relay/probes/targets/${d.id}`, body, RelayOkResponse);
      return apiClient.post('/api/v1/admin/relay/probes/targets', body, ProbeTargetCreatedResponse);
    },
    onSuccess: () => {
      editor = null;
      invalidate();
      toast.success('Target saved');
    },
    onError: onError('Could not save the target'),
  }));
  const removeTarget = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/relay/probes/targets/${id}`, RelayOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Target removed');
    },
    onError: onError('Could not remove the target'),
  }));

  // --- run history for one target ---------------------------------------------------
  let historyFor = $state<string | null>(null);
  const runs = adminProbeRunsQuery(() => historyFor);

  const verdictClass = (v: string) =>
    v === 'unreachable'
      ? 'text-destructive'
      : v === 'reachable'
        ? 'text-emerald-600'
        : v === 'mixed'
          ? 'text-amber-600'
          : 'text-muted-foreground';
  const cell = (t: ProbeMatrixTarget, country: string) => {
    const c = t.reachability.byCountry.find((x) => x.country === country);
    if (!c) return { text: '·', cls: 'text-muted-foreground', title: 'never probed' };
    const v6 = c.v6Verdict ? ` / v6 ${c.v6Verdict}` : '';
    return {
      text: `${c.verdict}${c.v6Verdict ? ` (v6 ${c.v6Verdict[0]})` : ''}`,
      cls: verdictClass(c.verdict),
      title: `${c.okVantages} ok / ${c.failVantages} failing vantages${v6} · ${formatDateTime(c.lastAt)}`,
    };
  };
  const kindLabel: Record<string, string> = { edge: 'Edge', relay: 'Relay node', custom: 'Custom' };
  const fmtAt = (iso: string) =>
    new Date(iso).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
</script>

<div class="space-y-6">
  <ProbeTimeChart />

  <!-- Matrix -->
  <Card>
    <CardHeader>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <CardTitle class="text-base">Reachability matrix</CardTitle>
          <CardDescription>
            Last verdict per target and country: IPv4 path, with the IPv6 path in brackets where
            probed. "FCP" is the internal connect check (outage vs block). Only edge rows feed the
            block detector.
          </CardDescription>
        </div>
        <div class="flex items-center gap-2">
          <Button
            size="sm"
            disabled={selected.size === 0 || probeNow.isPending}
            onclick={() => probeNow.mutate([...selected])}
          >
            Probe {selected.size || ''} selected now
          </Button>
        </div>
      </div>
    </CardHeader>
    <CardContent class="text-sm">
      {#if matrix.isPending}
        <Skeleton class="h-24 w-full" />
      {:else if matrix.isError}
        <InlineError message={apiErrorMessage(matrix.error)} />
      {:else if matrix.data}
        {#if matrix.data.targets.length === 0}
          <p class="text-muted-foreground">
            Nothing to probe yet: publish an edge, opt a relay's node in, or add a custom target
            below.
          </p>
        {:else}
          <div class="overflow-x-auto">
            <table class="w-full text-xs">
              <thead class="text-left text-muted-foreground">
                <tr>
                  <th class="py-1 pr-2"></th>
                  <th class="py-1 pr-3">Target</th>
                  <th class="pr-3">Kind</th>
                  {#each matrix.data.countries as c (c)}<th class="pr-3">{c}</th>{/each}
                  <th class="pr-3">FCP</th>
                  <th class="pr-3">Updated</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {#each matrix.data.targets as t (t.key)}
                  {@const fcp = t.reachability.byCountry.find((x) => x.country === 'XX')}
                  <tr class="border-t {t.enabled ? '' : 'opacity-70'}">
                    <td class="py-1 pr-2">
                      <Checkbox
                        checked={selected.has(t.key)}
                        onCheckedChange={(v) => toggle(t.key, v === true)}
                      />
                    </td>
                    <td class="py-1 pr-3">
                      <div class="font-medium">{t.label}</div>
                      <div class="text-muted-foreground">{t.detail}</div>
                    </td>
                    <td class="pr-3">
                      {kindLabel[t.kind] ?? t.kind}{t.enabled ? '' : ' · unscheduled'}
                    </td>
                    {#each matrix.data.countries as c (c)}
                      {@const x = cell(t, c)}
                      <td class="pr-3 {x.cls}" title={x.title}>{x.text}</td>
                    {/each}
                    <td class="pr-3 {fcp ? verdictClass(fcp.verdict) : 'text-muted-foreground'}"
                      >{fcp?.verdict ?? '·'}</td
                    >
                    <td class="pr-3 whitespace-nowrap text-muted-foreground"
                      >{t.reachability.updatedAt ? fmtAt(t.reachability.updatedAt) : '·'}</td
                    >
                    <td class="whitespace-nowrap">
                      <Button
                        size="sm"
                        variant="ghost"
                        class="h-6 px-2 text-xs"
                        onclick={() => probeNow.mutate([t.key])}>Probe</Button
                      >
                      <Button
                        size="sm"
                        variant="ghost"
                        class="h-6 px-2 text-xs"
                        onclick={() => (historyFor = historyFor === t.key ? null : t.key)}
                        >{historyFor === t.key ? 'Hide runs' : 'Runs'}</Button
                      >
                    </td>
                  </tr>
                  {#if historyFor === t.key}
                    <tr class="border-t bg-muted/30">
                      <td colspan={matrix.data.countries.length + 6} class="p-2">
                        {#if runs.isPending}
                          <Skeleton class="h-10 w-full" />
                        {:else if runs.isError}
                          <InlineError message={apiErrorMessage(runs.error)} />
                        {:else if (runs.data?.runs ?? []).length === 0}
                          <p class="text-muted-foreground">No runs recorded for this target.</p>
                        {:else}
                          <table class="w-full text-[11px]">
                            <thead class="text-left text-muted-foreground">
                              <tr
                                ><th class="pr-3">When</th><th class="pr-3">Source</th><th
                                  class="pr-3">Family</th
                                ><th class="pr-3">Status</th><th class="pr-3">Trigger</th><th
                                  class="pr-3">ok / fail</th
                                ><th>Per country</th></tr
                              >
                            </thead>
                            <tbody>
                              {#each runs.data?.runs ?? [] as r (r.id)}
                                <tr class="border-t border-border/40">
                                  <td class="py-0.5 pr-3 whitespace-nowrap"
                                    >{fmtAt(r.requestedAt)}</td
                                  >
                                  <td class="pr-3">{r.source}</td>
                                  <td class="pr-3">v{r.ipVersion}</td>
                                  <td class="pr-3">{r.status}</td>
                                  <td class="pr-3">{r.trigger}</td>
                                  <td class="pr-3 tabular-nums"
                                    >{r.okVantages} / {r.failVantages}</td
                                  >
                                  <td>
                                    {#each Object.entries(r.results.reduce((acc, x) => {
                                          const k = x.country;
                                          const cur = acc[k] ?? { ok: 0, fail: 0 };
                                          if (x.ok) cur.ok++;
                                          else cur.fail++;
                                          acc[k] = cur;
                                          return acc;
                                        }, {} as Record<string, { ok: number; fail: number }>)) as [country, n] (country)}
                                      <span class="me-2 whitespace-nowrap"
                                        >{country}
                                        <span
                                          class={n.fail > 0 && n.ok === 0 ? 'text-destructive' : ''}
                                          >{n.ok}/{n.fail}</span
                                        ></span
                                      >
                                    {/each}
                                  </td>
                                </tr>
                              {/each}
                            </tbody>
                          </table>
                        {/if}
                      </td>
                    </tr>
                  {/if}
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      {/if}
    </CardContent>
  </Card>

  <!-- Custom targets -->
  <Card>
    <CardHeader>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <CardTitle class="text-base">Custom targets</CardTitle>
          <CardDescription>
            Any host:port worth watching from the configured countries (a node's own address, a
            decoy, a competitor's endpoint). Enabled targets join the cron rounds; disabled ones are
            probed on demand only. Operator evidence: the detector never reads them.
          </CardDescription>
        </div>
        <Button size="sm" onclick={() => (editor = newDraft())}>Add target</Button>
      </div>
    </CardHeader>
    <CardContent class="text-sm">
      {#if targets.isError}
        <InlineError message={apiErrorMessage(targets.error)} />
      {:else if (targets.data?.targets ?? []).length === 0}
        <p class="text-muted-foreground">No custom targets.</p>
      {:else}
        <ul class="divide-y">
          {#each targets.data?.targets ?? [] as t (t.id)}
            <li class="flex flex-wrap items-center justify-between gap-2 py-2">
              <div>
                <span class="font-medium">{t.label}</span>
                <span class="ms-2 font-mono text-xs">{t.display}</span>
                {#if !t.enabled}<span class="ms-2 rounded-full border px-2 py-0.5 text-xs"
                    >disabled</span
                  >{/if}
                {#if t.notes}<div class="text-xs text-muted-foreground">{t.notes}</div>{/if}
              </div>
              <div class="flex gap-1">
                <Button
                  size="sm"
                  variant="outline"
                  class="h-7 px-2 text-xs"
                  onclick={() => probeNow.mutate([t.key])}>Probe now</Button
                >
                <Button
                  size="sm"
                  variant="ghost"
                  class="h-7 px-2 text-xs"
                  onclick={() => (editor = editDraft(t))}>Edit</Button
                >
                <Button
                  size="sm"
                  variant="ghost"
                  class="h-7 px-2 text-xs text-destructive"
                  onclick={() => removeTarget.mutate(t.id)}>Remove</Button
                >
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    </CardContent>
  </Card>

  <!-- Settings -->
  <Card>
    <CardHeader>
      <CardTitle class="text-base">Probe settings</CardTitle>
      <CardDescription>
        Measurement services open TCP connections to the targets above from the configured
        countries. No member data is involved. Tokens are write-only.
      </CardDescription>
    </CardHeader>
    <CardContent class="space-y-4 text-sm">
      {#if cfg.isError}
        <InlineError message={apiErrorMessage(cfg.error)} />
      {:else if cfg.data}
        <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <label class="flex items-center gap-2"
            ><Checkbox
              checked={get('probe.enabled', false)}
              onCheckedChange={(v) => set('probe.enabled', Boolean(v))}
            /> Probes enabled (cron rounds)</label
          >
          <label class="flex items-center gap-2"
            ><Checkbox
              checked={get('probe.sources.globalping', true)}
              onCheckedChange={(v) => set('probe.sources.globalping', Boolean(v))}
            /> Globalping</label
          >
          <label class="flex items-center gap-2"
            ><Checkbox
              checked={get('probe.sources.checkhost', true)}
              onCheckedChange={(v) => set('probe.sources.checkhost', Boolean(v))}
            /> check-host.net</label
          >
          <label class="flex items-center gap-2"
            ><Checkbox
              checked={get('probe.sources.ripeatlas', false)}
              onCheckedChange={(v) => set('probe.sources.ripeatlas', Boolean(v))}
            /> RIPE Atlas (needs a key)</label
          >
          <label class="flex items-center gap-2"
            ><Checkbox
              checked={get('probe.sources.internal', true)}
              onCheckedChange={(v) => set('probe.sources.internal', Boolean(v))}
            /> Internal connect check (outage vs block)</label
          >
          <label class="flex items-center gap-2"
            ><Checkbox
              checked={get('probe.preferEyeball', true)}
              onCheckedChange={(v) => set('probe.preferEyeball', Boolean(v))}
            /> Prefer residential (eyeball) vantages</label
          >
          <label class="text-xs"
            >Countries (comma separated)<Input
              class="mt-1"
              value={(get('probe.countries', []) as string[]).join(', ')}
              oninput={(e) =>
                set(
                  'probe.countries',
                  e.currentTarget.value
                    .split(/[,\s]+/)
                    .map((s) => s.trim())
                    .filter(Boolean),
                )}
            /></label
          >
          <label class="text-xs"
            >Interval minutes<Input
              class="mt-1"
              type="number"
              value={num('probe.intervalMinutes', 15)}
              oninput={(e) => set('probe.intervalMinutes', Number(e.currentTarget.value))}
            /></label
          >
          <label class="text-xs"
            >Interval while a relay is suspected<Input
              class="mt-1"
              type="number"
              value={num('probe.suspectedIntervalMinutes', 5)}
              oninput={(e) => set('probe.suspectedIntervalMinutes', Number(e.currentTarget.value))}
            /></label
          >
          <label class="text-xs"
            >Vantages per country<Input
              class="mt-1"
              type="number"
              value={num('probe.perCountryLimit', 3)}
              oninput={(e) => set('probe.perCountryLimit', Number(e.currentTarget.value))}
            /></label
          >
          <label class="text-xs"
            >Hourly budget (runs)<Input
              class="mt-1"
              type="number"
              value={num('probe.hourlyBudget', 200)}
              oninput={(e) => set('probe.hourlyBudget', Number(e.currentTarget.value))}
            /></label
          >
          <label class="text-xs"
            >Agreement vantages<Input
              class="mt-1"
              type="number"
              value={num('probe.agreementVantages', 2)}
              oninput={(e) => set('probe.agreementVantages', Number(e.currentTarget.value))}
            /></label
          >
          <label class="text-xs"
            >Globalping token {cfg.data.secrets.globalpingToken ? '(set)' : '(not set)'}<Input
              class="mt-1 font-mono"
              type="password"
              autocomplete="off"
              bind:value={secrets.globalpingToken}
              placeholder="leave blank to keep"
            /></label
          >
          <label class="text-xs"
            >RIPE Atlas key {cfg.data.secrets.ripeAtlasKey ? '(set)' : '(not set)'}<Input
              class="mt-1 font-mono"
              type="password"
              autocomplete="off"
              bind:value={secrets.ripeAtlasKey}
              placeholder="leave blank to keep"
            /></label
          >
        </div>
        <div class="flex justify-end">
          <Button disabled={!dirty || save.isPending} onclick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save probe settings'}
          </Button>
        </div>
      {/if}
    </CardContent>
  </Card>

  <!-- Audit feed -->
  <Card>
    <CardHeader>
      <CardTitle class="text-base">Probe audit log</CardTitle>
      <CardDescription>
        Every probe request, run and verdict change, plus target and setting edits. Rows carry
        target keys and codes only, never addresses. The full log with filters is under Audit log.
      </CardDescription>
    </CardHeader>
    <CardContent class="text-sm">
      {#if audit.isPending}
        <Skeleton class="h-16 w-full" />
      {:else if audit.isError}
        <InlineError message={apiErrorMessage(audit.error)} />
      {:else if (audit.data?.entries ?? []).length === 0}
        <p class="text-muted-foreground">Nothing yet.</p>
      {:else}
        <div class="overflow-x-auto">
          <table class="w-full text-xs">
            <thead class="text-left text-muted-foreground">
              <tr
                ><th class="py-1 pr-3">When</th><th class="pr-3">Action</th><th class="pr-3"
                  >Actor</th
                ><th class="pr-3">Target</th><th>Detail</th></tr
              >
            </thead>
            <tbody>
              {#each audit.data?.entries ?? [] as e (e.id)}
                <tr class="border-t">
                  <td class="py-1 pr-3 whitespace-nowrap tabular-nums">{fmtAt(e.createdAt)}</td>
                  <td class="pr-3 font-mono">{e.action}</td>
                  <td class="pr-3">{e.actorType}</td>
                  <td class="pr-3 font-mono">{e.targetId ?? '·'}</td>
                  <td class="max-w-[28rem] truncate font-mono" title={JSON.stringify(e.payload)}
                    >{e.payload ? JSON.stringify(e.payload) : '·'}</td
                  >
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </CardContent>
  </Card>
</div>

<Dialog.Root open={editor !== null} onOpenChange={(v) => !v && (editor = null)}>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>{editor?.id ? 'Edit target' : 'New custom target'}</Dialog.Title>
      <Dialog.Description
        >A host or IP literal plus a TCP port. Changing the address or port resets its history.</Dialog.Description
      >
    </Dialog.Header>
    {#if editor}
      <div class="grid gap-3">
        <label class="text-xs">Label<Input class="mt-1" bind:value={editor.label} /></label>
        <div class="grid gap-3 sm:grid-cols-[1fr_8rem]">
          <label class="text-xs"
            >Address<Input
              class="mt-1 font-mono"
              bind:value={editor.address}
              placeholder="host.example or 203.0.113.9"
            /></label
          >
          <label class="text-xs"
            >Port<Input class="mt-1" type="number" bind:value={editor.port} /></label
          >
        </div>
        <label class="text-xs">Notes<Input class="mt-1" bind:value={editor.notes} /></label>
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox bind:checked={editor.enabled} /> Probe on the cron schedule</label
        >
      </div>
    {/if}
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (editor = null)}>Cancel</Button>
      <Button disabled={saveTarget.isPending} onclick={() => saveTarget.mutate()}>Save</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
