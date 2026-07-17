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
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import * as Select from '@client/components/ui/select';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AdminListState from './AdminListState.svelte';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import {
    adminStatusIncidentsQuery,
    adminStatusPageQuery,
    configQuery,
    queryKeys,
  } from '../../lib/queries';
  import {
    AdminStatusIncidentCreateResponse,
    AdminStatusPageConfig,
    type StatusIncident,
    type CensorshipCell,
  } from '../../../shared/contracts/status';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { z } from 'zod';
  import { toast } from 'svelte-sonner';

  /**
   * Admin Status page: the operator-facing half of the public /status page.
   * Publish + resolve incidents, curate the censorship-availability matrix
   * (country × connection mode), and tune the load-band thresholds. Writes go
   * to the `status.*` namespace; nothing here needs a redeploy. English-only
   * (admin CMS convention).
   */
  const config = configQuery();
  const page = adminStatusPageQuery();
  const incidents = adminStatusIncidentsQuery();
  const qc = useQueryClient();

  const MODES = $derived((config.data?.connectionModes ?? []).map((m) => m.id));

  function invalidate() {
    void qc.invalidateQueries({ queryKey: queryKeys.adminStatusPage });
    void qc.invalidateQueries({ queryKey: queryKeys.adminStatusIncidents });
  }

  // --- incident editor ------------------------------------------------------

  type IncidentDraft = {
    id: string | null; // null = creating
    title: string;
    body: string;
    severity: StatusIncident['severity'];
    locationCodes: string; // comma-separated in the UI
    startedAtLocal: string; // <input type="datetime-local">
  };

  let editor = $state<IncidentDraft | null>(null);

  function toLocalInput(ms: number): string {
    const d = new Date(ms);
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function openCreate() {
    editor = {
      id: null,
      title: '',
      body: '',
      severity: 'degraded',
      locationCodes: '',
      startedAtLocal: toLocalInput(Date.now()),
    };
  }

  function openEdit(i: StatusIncident) {
    editor = {
      id: i.id,
      title: i.title,
      body: i.body ?? '',
      severity: i.severity,
      locationCodes: i.locationCodes.join(', '),
      startedAtLocal: toLocalInput(i.startedAt),
    };
  }

  const saveIncident = createMutation(() => ({
    mutationFn: async (draft: IncidentDraft) => {
      const input = {
        title: draft.title,
        body: draft.body,
        severity: draft.severity,
        locationCodes: draft.locationCodes
          .split(',')
          .map((c) => c.trim())
          .filter(Boolean),
        startedAt: new Date(draft.startedAtLocal).getTime(),
      };
      if (draft.id) {
        await apiClient.patch(`/api/v1/admin/status/incidents/${draft.id}`, input, z.null());
        return null;
      }
      return apiClient.post(
        '/api/v1/admin/status/incidents',
        input,
        AdminStatusIncidentCreateResponse,
      );
    },
    onSuccess: () => {
      toast.success('Incident saved');
      editor = null;
      invalidate();
    },
    onError: (e) => toast.error(apiErrorMessage(e)),
  }));

  const resolveIncident = createMutation(() => ({
    mutationFn: ({ id, resolve }: { id: string; resolve: boolean }) =>
      apiClient.patch(`/api/v1/admin/status/incidents/${id}`, { resolve }, z.null()),
    onSuccess: (_d, v) => {
      toast.success(v.resolve ? 'Incident resolved' : 'Incident re-opened');
      invalidate();
    },
    onError: (e) => toast.error(apiErrorMessage(e)),
  }));

  const deleteIncident = createMutation(() => ({
    mutationFn: (id: string) => apiClient.delete(`/api/v1/admin/status/incidents/${id}`, z.null()),
    onSuccess: () => {
      toast.success('Incident deleted');
      invalidate();
    },
    onError: (e) => toast.error(apiErrorMessage(e)),
  }));

  // --- censorship matrix + thresholds ----------------------------------------

  type MatrixDraftRow = {
    countryCode: string;
    label: string;
    cells: Record<string, CensorshipCell | ''>;
  };
  let matrixDraft = $state<MatrixDraftRow[] | null>(null);
  let thresholds = $state<{ busyAt: string; crowdedAt: string } | null>(null);

  function matrixRows(): MatrixDraftRow[] {
    if (matrixDraft) return matrixDraft;
    return (page.data?.rows ?? []).map((r) => ({
      countryCode: r.countryCode,
      label: r.label ?? '',
      cells: Object.fromEntries(MODES.map((m) => [m, r.cells[m] ?? ''])),
    }));
  }
  function setMatrix(rows: MatrixDraftRow[]) {
    matrixDraft = rows;
  }
  function addMatrixRow() {
    setMatrix([
      ...matrixRows(),
      { countryCode: '', label: '', cells: Object.fromEntries(MODES.map((m) => [m, ''])) },
    ]);
  }
  function removeMatrixRow(idx: number) {
    setMatrix(matrixRows().filter((_, i) => i !== idx));
  }
  function setMatrixCell(idx: number, modeId: string, val: string) {
    setMatrix(
      matrixRows().map((r, i) =>
        i === idx ? { ...r, cells: { ...r.cells, [modeId]: val as CensorshipCell | '' } } : r,
      ),
    );
  }

  const saveMatrix = createMutation(() => ({
    mutationFn: () =>
      apiClient.patch(
        '/api/v1/admin/status/page',
        {
          rows: matrixRows().map((r) => ({
            countryCode: r.countryCode,
            label: r.label || undefined,
            cells: Object.fromEntries(Object.entries(r.cells).filter(([, v]) => v !== '')),
          })),
        },
        AdminStatusPageConfig,
      ),
    onSuccess: () => {
      toast.success('Availability matrix saved');
      matrixDraft = null;
      invalidate();
    },
    onError: (e) => toast.error(apiErrorMessage(e)),
  }));

  const saveThresholds = createMutation(() => ({
    mutationFn: () =>
      apiClient.patch(
        '/api/v1/admin/status/page',
        {
          busyAt: Number(thresholds?.busyAt ?? 0),
          crowdedAt: Number(thresholds?.crowdedAt ?? 0),
        },
        AdminStatusPageConfig,
      ),
    onSuccess: () => {
      toast.success('Load thresholds saved');
      thresholds = null;
      invalidate();
    },
    onError: (e) => toast.error(apiErrorMessage(e)),
  }));

  function fmt(ms: number): string {
    return new Date(ms).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  }

  const SEVERITY_STYLES: Record<StatusIncident['severity'], string> = {
    outage: 'bg-destructive/10 text-destructive',
    degraded: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
    maintenance: 'bg-muted text-muted-foreground',
  };
</script>

<AdminLayout>
  <div class="space-y-8">
    <div>
      <h1 class="text-2xl font-bold">Status page</h1>
      <p class="text-sm text-muted-foreground">
        The operator half of the public <code>/status</code> page: publish incidents, curate the censorship-availability
        matrix, and tune load-band thresholds. Changes go live immediately.
      </p>
    </div>

    <!-- Incidents -->
    <Card>
      <CardHeader>
        <div class="flex items-center justify-between gap-4">
          <div>
            <CardTitle>Incidents</CardTitle>
            <CardDescription>
              Published on /status while open, and for 30 days after resolution.
            </CardDescription>
          </div>
          <Button size="sm" onclick={openCreate} disabled={editor !== null}>New incident</Button>
        </div>
      </CardHeader>
      <CardContent class="space-y-4">
        {#if editor}
          <form
            class="space-y-3 rounded-md border border-border p-4"
            onsubmit={(e) => {
              e.preventDefault();
              if (editor) saveIncident.mutate(editor);
            }}
          >
            <div class="grid gap-3 sm:grid-cols-2">
              <div class="space-y-1.5">
                <Label for="inc-title">Title</Label>
                <Input id="inc-title" bind:value={editor.title} maxlength={120} required />
              </div>
              <div class="space-y-1.5">
                <Label>Severity</Label>
                <Select.Root
                  type="single"
                  value={editor.severity}
                  onValueChange={(v) => {
                    if (editor) editor.severity = v as StatusIncident['severity'];
                  }}
                >
                  <Select.Trigger>{editor.severity}</Select.Trigger>
                  <Select.Content>
                    <Select.Item value="degraded">degraded</Select.Item>
                    <Select.Item value="outage">outage</Select.Item>
                    <Select.Item value="maintenance">maintenance</Select.Item>
                  </Select.Content>
                </Select.Root>
              </div>
              <div class="space-y-1.5">
                <Label for="inc-started">Started</Label>
                <Input
                  id="inc-started"
                  type="datetime-local"
                  bind:value={editor.startedAtLocal}
                  required
                />
              </div>
              <div class="space-y-1.5">
                <Label for="inc-locs">Locations (comma-separated codes; empty = global)</Label>
                <Input id="inc-locs" bind:value={editor.locationCodes} placeholder="MCI, AMS" />
              </div>
            </div>
            <div class="space-y-1.5">
              <Label for="inc-body">Details (optional)</Label>
              <textarea
                id="inc-body"
                class="min-h-20 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                bind:value={editor.body}
                maxlength={2000}
              ></textarea>
            </div>
            <div class="flex gap-2">
              <Button type="submit" size="sm" disabled={saveIncident.isPending}>
                {editor.id ? 'Save changes' : 'Publish incident'}
              </Button>
              <Button type="button" size="sm" variant="ghost" onclick={() => (editor = null)}>
                Cancel
              </Button>
            </div>
          </form>
        {/if}

        {#if incidents.isPending}
          <div class="space-y-2">
            {#each Array(3) as _, i (i)}<Skeleton class="h-10 w-full" />{/each}
          </div>
        {:else if incidents.isError || (incidents.data?.incidents ?? []).length === 0}
          <AdminListState
            error={incidents.isError ? incidents.error : undefined}
            onRetry={() => void incidents.refetch()}
            emptyText={incidents.isError ? undefined : 'No incidents published yet.'}
          />
        {:else}
          <ul class="divide-y divide-border">
            {#each incidents.data?.incidents ?? [] as i (i.id)}
              <li class="flex flex-wrap items-center gap-x-3 gap-y-1 py-3">
                <span
                  class="rounded-full px-2 py-0.5 text-xs font-medium {SEVERITY_STYLES[i.severity]}"
                >
                  {i.severity}
                </span>
                <span class="font-medium">{i.title}</span>
                {#if i.locationCodes.length > 0}
                  <span class="font-mono text-xs text-muted-foreground">
                    {i.locationCodes.join(', ')}
                  </span>
                {:else}
                  <span class="text-xs text-muted-foreground">global</span>
                {/if}
                <span class="text-xs text-muted-foreground">
                  {fmt(i.startedAt)} → {i.resolvedAt ? fmt(i.resolvedAt) : 'ongoing'}
                </span>
                <span class="ms-auto flex gap-1">
                  {#if i.resolvedAt}
                    <Button
                      size="sm"
                      variant="ghost"
                      onclick={() => resolveIncident.mutate({ id: i.id, resolve: false })}
                    >
                      Re-open
                    </Button>
                  {:else}
                    <Button
                      size="sm"
                      variant="ghost"
                      onclick={() => resolveIncident.mutate({ id: i.id, resolve: true })}
                    >
                      Resolve
                    </Button>
                  {/if}
                  <Button size="sm" variant="ghost" onclick={() => openEdit(i)}>Edit</Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    class="text-destructive"
                    onclick={() => {
                      if (confirm(`Delete incident "${i.title}"?`)) deleteIncident.mutate(i.id);
                    }}
                  >
                    Delete
                  </Button>
                </span>
              </li>
            {/each}
          </ul>
        {/if}
      </CardContent>
    </Card>

    <!-- Censorship matrix -->
    <Card>
      <CardHeader>
        <CardTitle>Censorship availability matrix</CardTitle>
        <CardDescription>
          Per-country availability of each connection mode, as judged by the operator (user reports,
          community signal). Shown on /status as country × mode.
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-4">
        {#if page.isPending}
          <Skeleton class="h-32 w-full" />
        {:else}
          <div class="space-y-2">
            <div
              class="grid grid-cols-[7rem_1fr_repeat(auto,6rem)] items-center gap-2 text-xs font-medium text-muted-foreground"
            >
              <span>Country (alpha-2)</span>
              <span>Label (optional)</span>
              {#each MODES as m (m)}
                <span class="text-center">{m}</span>
              {/each}
              <span></span>
            </div>
            {#each matrixRows() as row, idx (idx)}
              <div class="grid grid-cols-[7rem_1fr_repeat(auto,6rem)] items-center gap-2">
                <Input
                  value={row.countryCode}
                  oninput={(e) => {
                    const rows = matrixRows();
                    rows[idx] = { ...rows[idx]!, countryCode: e.currentTarget.value.toUpperCase() };
                    setMatrix(rows);
                  }}
                  placeholder="IR"
                  maxlength={2}
                  class="font-mono uppercase"
                />
                <Input
                  value={row.label}
                  oninput={(e) => {
                    const rows = matrixRows();
                    rows[idx] = { ...rows[idx]!, label: e.currentTarget.value };
                    setMatrix(rows);
                  }}
                  placeholder="Iran"
                />
                {#each MODES as m (m)}
                  <Select.Root
                    type="single"
                    value={row.cells[m] || 'unset'}
                    onValueChange={(v) => setMatrixCell(idx, m, v === 'unset' ? '' : v)}
                  >
                    <Select.Trigger class="w-full text-xs">
                      {row.cells[m] || '—'}
                    </Select.Trigger>
                    <Select.Content>
                      <Select.Item value="unset">—</Select.Item>
                      <Select.Item value="available">available</Select.Item>
                      <Select.Item value="partial">partial</Select.Item>
                      <Select.Item value="blocked">blocked</Select.Item>
                    </Select.Content>
                  </Select.Root>
                {/each}
                <Button size="sm" variant="ghost" onclick={() => removeMatrixRow(idx)}>✕</Button>
              </div>
            {/each}
          </div>
          <div class="flex gap-2">
            <Button size="sm" variant="outline" onclick={addMatrixRow}>Add country</Button>
            <Button
              size="sm"
              onclick={() => saveMatrix.mutate()}
              disabled={matrixDraft === null || saveMatrix.isPending}
            >
              Save matrix
            </Button>
          </div>
        {/if}
      </CardContent>
    </Card>

    <!-- Load thresholds -->
    <Card>
      <CardHeader>
        <CardTitle>Load bands</CardTitle>
        <CardDescription>
          Users-per-online-node cutoffs for the "busy" / "crowded" bands, used where instances have
          no maxKeys capacity cap. Current: {page.data?.busyAt ?? '…'} / {page.data?.crowdedAt ??
            '…'}.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          class="flex flex-wrap items-end gap-3"
          onsubmit={(e) => {
            e.preventDefault();
            saveThresholds.mutate();
          }}
        >
          <div class="space-y-1.5">
            <Label for="th-busy">Busy at</Label>
            <Input
              id="th-busy"
              type="number"
              min="1"
              max="100000"
              value={thresholds?.busyAt ?? String(page.data?.busyAt ?? '')}
              oninput={(e) =>
                (thresholds = {
                  busyAt: e.currentTarget.value,
                  crowdedAt: thresholds?.crowdedAt ?? String(page.data?.crowdedAt ?? ''),
                })}
              class="w-28"
            />
          </div>
          <div class="space-y-1.5">
            <Label for="th-crowded">Crowded at</Label>
            <Input
              id="th-crowded"
              type="number"
              min="1"
              max="100000"
              value={thresholds?.crowdedAt ?? String(page.data?.crowdedAt ?? '')}
              oninput={(e) =>
                (thresholds = {
                  busyAt: thresholds?.busyAt ?? String(page.data?.busyAt ?? ''),
                  crowdedAt: e.currentTarget.value,
                })}
              class="w-28"
            />
          </div>
          <Button
            type="submit"
            size="sm"
            disabled={thresholds === null || saveThresholds.isPending}
          >
            Save thresholds
          </Button>
        </form>
      </CardContent>
    </Card>
  </div>
</AdminLayout>
