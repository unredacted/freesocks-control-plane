<script lang="ts">
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Select from '@client/components/ui/select';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminRelayConfigQuery, queryKeys } from '../../lib/queries';
  import {
    RENDER_CLIENT_FAMILY_IDS,
    RelayConfigPatchResponse,
    RelayRenderPreviewResponse,
    type RelayAdmin,
    type RelayRenderPreviewResponse as Preview,
  } from '../../../shared/contracts/relays';
  import AdminListState from './AdminListState.svelte';

  /**
   * The `relay.*` namespace: master switches, pool defaults and rotation limits,
   * how each client family's subscription is rendered (with a live preview) and
   * the detector knobs. Probe sources / countries / budget / tokens live under
   * Telemetry → Probes. Saves send only the fields the operator touched.
   */
  interface Props {
    relays: RelayAdmin[];
  }
  let { relays }: Props = $props();
  const cfg = adminRelayConfigQuery();
  const qc = useQueryClient();
  const onError = (title: string) => (err: unknown) =>
    toast.error(title, { description: apiErrorMessage(err) });

  // A shallow patch accumulator: nested paths like 'render.clients.singbox.enabled'.
  let patch = $state<Record<string, unknown>>({});
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
    return out;
  }
  const dirty = $derived(Object.keys(patch).length > 0);
  const save = createMutation(() => ({
    mutationFn: () =>
      apiClient.patch('/api/v1/admin/relay/config', nested(), RelayConfigPatchResponse),
    onSuccess: (r) => {
      patch = {};
      void qc.invalidateQueries({ queryKey: queryKeys.adminRelayConfig });
      void qc.invalidateQueries({ queryKey: ['admin', 'relays'] });
      toast.success(
        r.changedKeys.length
          ? `Saved ${r.changedKeys.length} setting${r.changedKeys.length === 1 ? '' : 's'}`
          : 'Nothing changed',
      );
    },
    onError: onError('Could not save the relay settings'),
  }));

  // Preview.
  let previewOrigin = $state<string>('');
  let previewFamily = $state<string>('v2rayng');
  let preview = $state<Preview | null>(null);
  const runPreview = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/admin/relay/render/preview',
        { relayId: previewOrigin || relays[0]?.id, family: previewFamily },
        RelayRenderPreviewResponse,
      ),
    onSuccess: (r) => (preview = r),
    onError: onError('Preview failed'),
  }));

  const ipv6Modes = ['off', 'auto-group-only', 'both'] as const;
  const ruleModes = ['inherit', ...ipv6Modes] as const;
  const num = (path: string, fallback: number) => Number(get(path, fallback));
</script>

{#if cfg.isError}
  <AdminListState error={cfg.error} onRetry={() => void cfg.refetch()} />
{:else if cfg.data}
  <div class="space-y-6">
    <Card>
      <CardHeader class="pb-2">
        <CardTitle class="text-base">Master switches and rotation limits</CardTitle>
        <CardDescription
          >The detector and automatic actions ship off; nothing rotates without the global switch,
          the per-origin opt-in and edge-level evidence.</CardDescription
        >
      </CardHeader>
      <CardContent class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox
            checked={get('enabled', false)}
            onCheckedChange={(v) => set('enabled', Boolean(v))}
          /> Relay layer enabled (detector + automation)</label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox
            checked={get('autoRotate', false)}
            onCheckedChange={(v) => set('autoRotate', Boolean(v))}
          /> Allow automatic rotation (global gate)</label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox
            checked={get('autoPublishStandby', true)}
            onCheckedChange={(v) => set('autoPublishStandby', Boolean(v))}
          /> Publish standbys into free pool slots</label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox
            checked={get('autoProvisionToDesired', false)}
            onCheckedChange={(v) => set('autoProvisionToDesired', Boolean(v))}
          /> Provision automatically up to the desired pool</label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox
            checked={get('requireProviderHealth', true)}
            onCheckedChange={(v) => set('requireProviderHealth', Boolean(v))}
          /> Publish only provider-healthy edges</label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox
            checked={get('refreshMirrorsAfterFlip', true)}
            onCheckedChange={(v) => set('refreshMirrorsAfterFlip', Boolean(v))}
          /> Refresh S3 mirrors after a flip</label
        >
        <label class="text-xs"
          >Desired published edges (default)<Input
            class="mt-1"
            type="number"
            value={num('desiredPublishedDefault', 2)}
            oninput={(e) => set('desiredPublishedDefault', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Standby edges per origin (default)<Input
            class="mt-1"
            type="number"
            value={num('standbyPerRelay', 0)}
            oninput={(e) => set('standbyPerRelay', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Drain minutes<Input
            class="mt-1"
            type="number"
            value={num('drainMinutes', 1440)}
            oninput={(e) => set('drainMinutes', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Burned drain minutes<Input
            class="mt-1"
            type="number"
            value={num('burnedDrainMinutes', 60)}
            oninput={(e) => set('burnedDrainMinutes', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Server-name drain minutes<Input
            class="mt-1"
            type="number"
            value={num('sniDrainMinutes', 1440)}
            oninput={(e) => set('sniDrainMinutes', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Cooldown minutes<Input
            class="mt-1"
            type="number"
            value={num('cooldownMinutes', 120)}
            oninput={(e) => set('cooldownMinutes', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Max rotations per origin per day<Input
            class="mt-1"
            type="number"
            value={num('maxRotationsPerRelayPerDay', 3)}
            oninput={(e) => set('maxRotationsPerRelayPerDay', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Max concurrent rotations<Input
            class="mt-1"
            type="number"
            value={num('maxConcurrentRotations', 2)}
            oninput={(e) => set('maxConcurrentRotations', Number(e.currentTarget.value))}
          /></label
        >
      </CardContent>
    </Card>

    <Card>
      <CardHeader class="pb-2">
        <CardTitle class="text-base">Client rendering</CardTitle>
        <CardDescription
          >How each client family's subscription is rewritten: template entries become the
          subscriber's primary and backup edges, one server name each. Off = the panel body passes
          through.</CardDescription
        >
      </CardHeader>
      <CardContent class="space-y-4">
        <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <label class="flex items-center gap-2 text-sm"
            ><Checkbox
              checked={get('render.enabled', false)}
              onCheckedChange={(v) => set('render.enabled', Boolean(v))}
            /> Rendering enabled</label
          >
          <label class="flex items-center gap-2 text-sm"
            ><Checkbox
              checked={get('render.preferDistinctProviders', true)}
              onCheckedChange={(v) => set('render.preferDistinctProviders', Boolean(v))}
            /> Backup on a different provider when possible</label
          >
          <label class="text-xs"
            >Auto group name<Input
              class="mt-1"
              value={get('render.autoGroupName', '')}
              oninput={(e) => set('render.autoGroupName', e.currentTarget.value)}
            /></label
          >
          <label class="text-xs"
            >Primary label<Input
              class="mt-1"
              value={get('render.primaryLabel', '')}
              oninput={(e) => set('render.primaryLabel', e.currentTarget.value)}
            /></label
          >
          <label class="text-xs"
            >Backup label<Input
              class="mt-1"
              value={get('render.backupLabel', '')}
              oninput={(e) => set('render.backupLabel', e.currentTarget.value)}
            /></label
          >
          <label class="text-xs"
            >IPv6 label<Input
              class="mt-1"
              value={get('render.ipv6Label', '')}
              oninput={(e) => set('render.ipv6Label', e.currentTarget.value)}
            /></label
          >
          <label class="text-xs"
            >IPv6 entries
            <Select.Root
              type="single"
              value={get('render.ipv6Mode', 'both')}
              onValueChange={(v) => set('render.ipv6Mode', v)}
            >
              <Select.Trigger class="mt-1 w-full">{get('render.ipv6Mode', 'both')}</Select.Trigger>
              <Select.Content
                >{#each ipv6Modes as m (m)}<Select.Item value={m}>{m}</Select.Item
                  >{/each}</Select.Content
              >
            </Select.Root>
          </label>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-xs">
            <thead class="text-left text-muted-foreground"
              ><tr
                ><th class="py-1 pr-3">Family</th><th class="pr-3">Enabled</th><th class="pr-3"
                  >Auto group</th
                ><th class="pr-3">Backup</th><th class="pr-3">IPv6</th><th class="pr-3">Order</th
                ><th class="pr-3">Max entries</th><th class="pr-3">Drop templates</th></tr
              ></thead
            >
            <tbody>
              {#each RENDER_CLIENT_FAMILY_IDS as fam (fam)}
                {@const base = `render.clients.${fam}`}
                <tr class="border-t">
                  <td class="py-1.5 pr-3 font-medium">{fam}</td>
                  <td class="pr-3"
                    ><Checkbox
                      checked={get(`${base}.enabled`, true)}
                      onCheckedChange={(v) => set(`${base}.enabled`, Boolean(v))}
                    /></td
                  >
                  <td class="pr-3"
                    ><Checkbox
                      checked={get(`${base}.autoGroup`, fam === 'singbox' || fam === 'mihomo')}
                      onCheckedChange={(v) => set(`${base}.autoGroup`, Boolean(v))}
                    /></td
                  >
                  <td class="pr-3"
                    ><Checkbox
                      checked={get(`${base}.includeBackup`, true)}
                      onCheckedChange={(v) => set(`${base}.includeBackup`, Boolean(v))}
                    /></td
                  >
                  <td class="pr-3">
                    <Select.Root
                      type="single"
                      value={get(`${base}.ipv6Mode`, 'inherit')}
                      onValueChange={(v) => set(`${base}.ipv6Mode`, v)}
                    >
                      <Select.Trigger class="h-7 w-36"
                        >{get(`${base}.ipv6Mode`, 'inherit')}</Select.Trigger
                      >
                      <Select.Content
                        >{#each ruleModes as m (m)}<Select.Item value={m}>{m}</Select.Item
                          >{/each}</Select.Content
                      >
                    </Select.Root>
                  </td>
                  <td class="pr-3">
                    <Select.Root
                      type="single"
                      value={get(`${base}.order`, 'primary-first')}
                      onValueChange={(v) => set(`${base}.order`, v)}
                    >
                      <Select.Trigger class="h-7 w-36"
                        >{get(`${base}.order`, 'primary-first')}</Select.Trigger
                      >
                      <Select.Content
                        ><Select.Item value="primary-first">primary-first</Select.Item><Select.Item
                          value="backup-first">backup-first</Select.Item
                        ></Select.Content
                      >
                    </Select.Root>
                  </td>
                  <td class="pr-3"
                    ><Input
                      class="h-7 w-20"
                      type="number"
                      value={num(`${base}.maxEntries`, 0)}
                      oninput={(e) => set(`${base}.maxEntries`, Number(e.currentTarget.value))}
                    /></td
                  >
                  <td class="pr-3"
                    ><Checkbox
                      checked={get(`${base}.dropTemplateEntries`, true)}
                      onCheckedChange={(v) => set(`${base}.dropTemplateEntries`, Boolean(v))}
                    /></td
                  >
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="rounded-md border p-3">
          <div class="flex flex-wrap items-end gap-3">
            <label class="text-xs"
              >Origin
              <Select.Root
                type="single"
                value={previewOrigin || relays[0]?.id || ''}
                onValueChange={(v) => (previewOrigin = v)}
              >
                <Select.Trigger class="mt-1 w-56"
                  >{relays.find((o) => o.id === (previewOrigin || relays[0]?.id))?.slug ??
                    'No relays'}</Select.Trigger
                >
                <Select.Content
                  >{#each relays as o (o.id)}<Select.Item value={o.id}>{o.slug}</Select.Item
                    >{/each}</Select.Content
                >
              </Select.Root>
            </label>
            <label class="text-xs"
              >Client family
              <Select.Root
                type="single"
                value={previewFamily}
                onValueChange={(v) => (previewFamily = v)}
              >
                <Select.Trigger class="mt-1 w-40">{previewFamily}</Select.Trigger>
                <Select.Content
                  >{#each RENDER_CLIENT_FAMILY_IDS as f (f)}<Select.Item value={f}>{f}</Select.Item
                    >{/each}</Select.Content
                >
              </Select.Root>
            </label>
            <Button
              size="sm"
              variant="outline"
              disabled={relays.length === 0 || runPreview.isPending}
              onclick={() => runPreview.mutate()}>Preview (saved settings)</Button
            >
          </div>
          {#if preview}
            <p class="mt-2 text-xs text-muted-foreground">
              {preview.format} · {preview.applied
                ? `${preview.emitted} entries emitted`
                : `passthrough (${preview.reason ?? 'not applied'})`}
            </p>
            <pre
              class="mt-2 max-h-72 overflow-auto rounded bg-muted p-2 text-[11px]">{preview.body}</pre>
          {/if}
        </div>
      </CardContent>
    </Card>

    <Card>
      <CardHeader class="pb-2">
        <CardTitle class="text-base">Block detector</CardTitle>
        <CardDescription
          >Origin-level evidence (reports, load) only hints; edge-level evidence (probes, members
          naming the connection) may rotate when every gate is open.</CardDescription
        >
      </CardHeader>
      <CardContent class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <label class="text-xs"
          >Window minutes<Input
            class="mt-1"
            type="number"
            value={num('detect.windowMinutes', 30)}
            oninput={(e) => set('detect.windowMinutes', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Min reporters<Input
            class="mt-1"
            type="number"
            value={num('detect.minReporters', 4)}
            oninput={(e) => set('detect.minReporters', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Min edge reporters<Input
            class="mt-1"
            type="number"
            value={num('detect.minEdgeReporters', 3)}
            oninput={(e) => set('detect.minEdgeReporters', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Spike factor<Input
            class="mt-1"
            type="number"
            step="0.1"
            value={num('detect.spikeFactor', 3)}
            oninput={(e) => set('detect.spikeFactor', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Load drop percent<Input
            class="mt-1"
            type="number"
            value={num('detect.loadDropPct', 50)}
            oninput={(e) => set('detect.loadDropPct', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Suspect at score<Input
            class="mt-1"
            type="number"
            step="0.05"
            value={num('detect.suspectAt', 0.6)}
            oninput={(e) => set('detect.suspectAt', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Clear below score<Input
            class="mt-1"
            type="number"
            step="0.05"
            value={num('detect.clearBelow', 0.3)}
            oninput={(e) => set('detect.clearBelow', Number(e.currentTarget.value))}
          /></label
        >
        <label class="text-xs"
          >Probe weight<Input
            class="mt-1"
            type="number"
            step="0.05"
            value={num('detect.probeWeight', 0.5)}
            oninput={(e) => set('detect.probeWeight', Number(e.currentTarget.value))}
          /></label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox
            checked={get('detect.requireLoadCorroboration', true)}
            onCheckedChange={(v) => set('detect.requireLoadCorroboration', Boolean(v))}
          /> Reports need a load drop to count</label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox
            checked={get('detect.allowProbeOnlyAutoRotate', true)}
            onCheckedChange={(v) => set('detect.allowProbeOnlyAutoRotate', Boolean(v))}
          /> Probe evidence alone may auto-rotate</label
        >
      </CardContent>
    </Card>

    <div class="flex items-center justify-end gap-2">
      {#if dirty}<span class="text-xs text-muted-foreground">Unsaved changes</span>{/if}
      <Button variant="outline" disabled={!dirty} onclick={() => (patch = {})}>Discard</Button>
      <Button disabled={!dirty || save.isPending} onclick={() => save.mutate()}
        >Save relay settings</Button
      >
    </div>
  </div>
{/if}
