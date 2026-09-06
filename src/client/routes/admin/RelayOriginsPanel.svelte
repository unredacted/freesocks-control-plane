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
  import * as Dialog from '@client/components/ui/dialog';
  import * as Select from '@client/components/ui/select';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import {
    adminBackendServersQuery,
    adminRelayEdgesQuery,
    adminRelayEndpointsQuery,
    adminRelayRotationQuery,
    adminRelayRotationsQuery,
    adminRelaySlotsQuery,
    queryKeys,
  } from '../../lib/queries';
  import {
    RelayAdoptResponse,
    RelayIdResponse,
    RelayOkResponse,
    RelayProbeRequestedResponse,
    RelayRotationStartedResponse,
    RelayEdgeLiveResponse,
    type RelayOriginAdmin,
    type RelaySummary,
  } from '../../../shared/contracts/relays';
  import { formatDateTime } from '../../lib/i18n/format';
  import AdminListState from './AdminListState.svelte';

  interface Props {
    summary: RelaySummary | null;
  }
  let { summary }: Props = $props();
  const qc = useQueryClient();
  const servers = adminBackendServersQuery();

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['admin', 'relays'] });
    void qc.invalidateQueries({ queryKey: queryKeys.adminStatus });
  };
  const onError = (title: string) => (err: unknown) =>
    toast.error(title, { description: apiErrorMessage(err) });

  // --- origin editor -------------------------------------------------------------
  type OriginDraft = {
    id: string | null;
    slug: string;
    backendServerId: string;
    nodeHostname: string;
    originAddress: string;
    locationCode: string;
    modeSlugs: string;
    enabled: boolean;
    autoRotate: boolean;
    hostManaged: boolean;
    providerAffinity: 'rotate' | 'sticky';
    desiredPublished: number;
    standbyPerOrigin: number;
    cooldownMinutes: number;
    maxRotationsPerDay: number;
    drainMinutes: number;
  };
  let editor = $state<OriginDraft | null>(null);
  function newDraft(): OriginDraft {
    return {
      id: null,
      slug: '',
      backendServerId: servers.data?.[0]?.id ?? '',
      nodeHostname: '',
      originAddress: '',
      locationCode: '',
      modeSlugs: 'freedom-reality',
      enabled: true,
      autoRotate: false,
      hostManaged: true,
      providerAffinity: 'rotate',
      desiredPublished: 2,
      standbyPerOrigin: 0,
      cooldownMinutes: 120,
      maxRotationsPerDay: 3,
      drainMinutes: 1440,
    };
  }
  function editDraft(o: RelayOriginAdmin): OriginDraft {
    return {
      id: o.id,
      slug: o.slug,
      backendServerId: o.backendServerId,
      nodeHostname: o.nodeHostname,
      originAddress: o.originAddress,
      locationCode: o.locationCode ?? '',
      modeSlugs: o.modeSlugs.join(', '),
      enabled: o.enabled,
      autoRotate: o.autoRotate,
      hostManaged: o.hostManaged,
      providerAffinity: o.providerAffinity,
      desiredPublished: o.desiredPublished,
      standbyPerOrigin: o.standbyPerOrigin,
      cooldownMinutes: o.cooldownMinutes,
      maxRotationsPerDay: o.maxRotationsPerDay,
      drainMinutes: o.drainMinutes,
    };
  }
  const saveOrigin = createMutation(() => ({
    mutationFn: async () => {
      const d = editor!;
      const body = {
        nodeHostname: d.nodeHostname.trim(),
        originAddress: d.originAddress.trim(),
        locationCode: d.locationCode.trim() || null,
        modeSlugs: d.modeSlugs
          .split(/[,\s]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        enabled: d.enabled,
        autoRotate: d.autoRotate,
        hostManaged: d.hostManaged,
        providerAffinity: d.providerAffinity,
        desiredPublished: Number(d.desiredPublished),
        standbyPerOrigin: Number(d.standbyPerOrigin),
        cooldownMinutes: Number(d.cooldownMinutes),
        maxRotationsPerDay: Number(d.maxRotationsPerDay),
        drainMinutes: Number(d.drainMinutes),
      };
      if (d.id)
        return apiClient.patch(`/api/v1/admin/relays/origins/${d.id}`, body, RelayOkResponse);
      return apiClient.post(
        '/api/v1/admin/relays/origins',
        { ...body, slug: d.slug.trim(), backendServerId: d.backendServerId },
        RelayIdResponse,
      );
    },
    onSuccess: () => {
      editor = null;
      invalidate();
      toast.success('Origin saved');
    },
    onError: onError('Could not save the origin'),
  }));
  const deleteOrigin = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/relays/origins/${id}`, RelayOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Teardown requested; edges drain and destroy in the background');
    },
    onError: onError('Could not delete the origin'),
  }));

  // --- origin actions ---------------------------------------------------------------
  const act = createMutation(() => ({
    mutationFn: ({ id, op, body }: { id: string; op: string; body?: Record<string, unknown> }) =>
      apiClient.post(
        `/api/v1/admin/relays/origins/${id}/${op}`,
        body ?? {},
        RelayRotationStartedResponse.or(RelayOkResponse).or(RelayProbeRequestedResponse),
      ),
    onSuccess: (r, vars) => {
      invalidate();
      if ('rotationId' in r && typeof r.rotationId === 'string') openRotation = r.rotationId;
      toast.success(
        vars.op === 'probe'
          ? 'Probe round requested'
          : vars.op === 'cancel'
            ? 'Cancel requested'
            : `${vars.op} started`,
      );
    },
    onError: onError('Action refused'),
  }));

  // --- adopt --------------------------------------------------------------------------
  let adoptFor = $state<string | null>(null);
  let adopt = $state({ slotId: '', ipv4: '', ipv6: '', port: 443, publish: true });
  const slotsForAdopt = adminRelaySlotsQuery(() => adoptFor);
  const adoptEdge = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        `/api/v1/admin/relays/origins/${adoptFor}/adopt`,
        {
          slotId: adopt.slotId,
          ipv4: adopt.ipv4.trim(),
          ipv6: adopt.ipv6.trim() || null,
          port: Number(adopt.port) || 443,
          publish: adopt.publish,
        },
        RelayAdoptResponse,
      ),
    onSuccess: () => {
      adoptFor = null;
      invalidate();
      toast.success('Edge adopted');
    },
    onError: onError('Could not adopt the edge'),
  }));

  // --- detail drawer (edges, rotations, endpoints) ------------------------------------------
  let detailFor = $state<string | null>(null);
  const edges = adminRelayEdgesQuery(() => detailFor);
  const rotations = adminRelayRotationsQuery(() => detailFor);
  const endpoints = adminRelayEndpointsQuery(() => detailFor);
  let openRotation = $state<string | null>(null);
  const rotation = adminRelayRotationQuery(() => openRotation);
  let liveFor = $state<string | null>(null);
  let live = $state<Record<string, unknown> | null>(null);

  const edgeAct = createMutation(() => ({
    mutationFn: ({ id, op, body }: { id: string; op: string; body?: Record<string, unknown> }) =>
      apiClient.post(
        `/api/v1/admin/relays/edges/${id}/${op}`,
        body ?? {},
        RelayOkResponse.or(RelayRotationStartedResponse).or(RelayProbeRequestedResponse),
      ),
    onSuccess: (r) => {
      invalidate();
      if ('rotationId' in r && typeof r.rotationId === 'string') openRotation = r.rotationId;
      toast.success('Done');
    },
    onError: onError('Edge action refused'),
  }));
  const edgeDelete = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/relays/edges/${id}`, RelayOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Edge scheduled for destruction');
    },
    onError: onError('Could not delete the edge'),
  }));
  const pullLive = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.post(`/api/v1/admin/relays/edges/${id}/live/refresh`, {}, RelayEdgeLiveResponse),
    onSuccess: (r, id) => {
      liveFor = id;
      live = (r.live as Record<string, unknown> | null) ?? null;
      invalidate();
    },
    onError: onError('Could not pull live data'),
  }));

  function suspicionBadge(o: RelayOriginAdmin): { text: string; cls: string } | null {
    if (o.quarantine)
      return {
        text: 'quarantined',
        cls: 'border-destructive/40 bg-destructive/10 text-destructive',
      };
    if (o.suspicion?.state === 'suspected') {
      return {
        text: `suspected (${o.suspicion.hintLevel})`,
        cls: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
      };
    }
    return null;
  }
</script>

<div class="space-y-4">
  <div class="flex justify-end">
    <Button onclick={() => (editor = newDraft())}>New origin</Button>
  </div>

  {#if !summary || summary.origins.length === 0}
    <AdminListState
      emptyText="No relay origins yet. The node role registers one per REALITY node (PUT /api/v1/admin/relays/origins/by-slug/<slug>), or create one here."
    />
  {/if}

  {#each summary?.origins ?? [] as row (row.origin.id)}
    {@const o = row.origin}
    {@const badge = suspicionBadge(o)}
    <Card>
      <CardHeader class="pb-2">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle class="flex flex-wrap items-center gap-2 text-base">
              <span class="font-mono">{o.slug}</span>
              {#if !o.enabled}<span class="rounded-full border px-2 py-0.5 text-xs">disabled</span
                >{/if}
              {#if badge}<span class="rounded-full border px-2 py-0.5 text-xs {badge.cls}"
                  >{badge.text}</span
                >{/if}
              {#if o.autoRotate}<span class="rounded-full border px-2 py-0.5 text-xs"
                  >auto-rotate</span
                >{/if}
              {#if !o.hostManaged}<span class="rounded-full border px-2 py-0.5 text-xs"
                  >host unmanaged</span
                >{/if}
            </CardTitle>
            <CardDescription class="mt-1">
              node <span class="font-mono">{o.nodeHostname}</span> · origin
              <span class="font-mono">{o.originAddress}</span> · pool {row.origin
                .publishedCount}/{o.desiredPublished}
              · {row.standbys} standby · {row.draining} draining · epoch {o.publicationEpoch}
              {#if o.cooldownUntil}· cooling down until {formatDateTime(o.cooldownUntil)}{/if}
            </CardDescription>
          </div>
          <div class="flex flex-wrap gap-1.5">
            <Button
              size="sm"
              variant="outline"
              onclick={() => (detailFor = detailFor === o.id ? null : o.id)}
            >
              {detailFor === o.id ? 'Hide detail' : 'Edges and rotations'}
            </Button>
            <Button size="sm" variant="outline" onclick={() => (adoptFor = o.id)}>Adopt edge</Button
            >
            <Button
              size="sm"
              variant="outline"
              disabled={!!row.rotation}
              onclick={() => act.mutate({ id: o.id, op: 'provision', body: { publish: true } })}
            >
              Provision
            </Button>
            <Button
              size="sm"
              variant="outline"
              onclick={() => act.mutate({ id: o.id, op: 'probe' })}>Probe now</Button
            >
            {#if row.rotation}
              <Button
                size="sm"
                variant="outline"
                onclick={() => act.mutate({ id: o.id, op: 'cancel' })}>Cancel rotation</Button
              >
            {/if}
            {#if o.quarantine}
              <Button
                size="sm"
                variant="destructive"
                onclick={() =>
                  act.mutate({ id: o.id, op: 'resolve-quarantine', body: { keep: 'previous' } })}
              >
                Resolve: keep previous
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onclick={() =>
                  act.mutate({ id: o.id, op: 'resolve-quarantine', body: { keep: 'current' } })}
              >
                Resolve: keep current
              </Button>
            {/if}
            <Button size="sm" variant="ghost" onclick={() => (editor = editDraft(o))}>Edit</Button>
          </div>
        </div>
      </CardHeader>
      <CardContent class="space-y-3">
        {#if o.quarantine}
          <div
            class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
          >
            Quarantined since {formatDateTime(o.quarantine.since)}: {o.quarantine.reason}. Nothing
            rotates or deletes here until an operator resolves it after checking the panel Hosts by
            hand.
          </div>
        {/if}
        {#if o.suspicion?.hint}
          <div class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
            {o.suspicion.hint}
            {#if o.suspicion.lastRotateError}<span class="text-muted-foreground">
                (last automatic rotation refused: {o.suspicion.lastRotateError})</span
              >{/if}
          </div>
        {/if}
        {#if row.rotation}
          <button
            type="button"
            class="w-full rounded-md border px-3 py-2 text-left text-sm hover:bg-muted/40"
            onclick={() => (openRotation = row.rotation!.id)}
          >
            <div class="flex items-center justify-between">
              <span>Rotation in progress: {row.rotation.kind} · {row.rotation.phase}</span>
              <span class="tabular-nums">{row.rotation.percent}%</span>
            </div>
            <div class="mt-1 h-2 w-full overflow-hidden rounded bg-muted">
              <div
                class="h-full bg-sky-500 transition-all"
                style="width: {row.rotation.percent}%"
              ></div>
            </div>
          </button>
        {/if}
        <div class="flex flex-wrap gap-2">
          {#each row.pool as p (p.edgeId)}
            <div class="rounded-lg border px-3 py-2 text-xs">
              <div class="flex items-center gap-2">
                <span class="font-medium"
                  >{p.poolIndex === 0 ? 'Primary slot' : `Pool ${p.poolIndex}`}</span
                >
                <span class="rounded-full border px-1.5">{p.provider ?? 'adopted'}</span>
                <span
                  class="rounded-full border px-1.5 {p.health === 'online'
                    ? 'border-emerald-500/40'
                    : ''}">{p.health}</span
                >
                {#if p.unreachableIn.length > 0}
                  <span
                    class="rounded-full border border-destructive/40 bg-destructive/10 px-1.5 text-destructive"
                    >unreachable in {p.unreachableIn.join(', ')}</span
                  >
                {:else if p.mixedIn.length > 0}
                  <span class="rounded-full border border-amber-500/40 px-1.5"
                    >mixed in {p.mixedIn.join(', ')}</span
                  >
                {/if}
              </div>
              <div class="mt-1 font-mono">
                {p.addresses.v4 ?? '-'}{p.addresses.v6 ? ` · ${p.addresses.v6}` : ''}
              </div>
              <div class="mt-1.5 flex gap-1">
                <Button
                  size="sm"
                  variant="outline"
                  class="h-6 px-2 text-xs"
                  disabled={!!row.rotation}
                  onclick={() => act.mutate({ id: o.id, op: 'rotate', body: { edgeId: p.edgeId } })}
                  >Rotate</Button
                >
                <Button
                  size="sm"
                  variant="outline"
                  class="h-6 px-2 text-xs"
                  disabled={!!row.rotation}
                  onclick={() => act.mutate({ id: o.id, op: 'burn', body: { edgeId: p.edgeId } })}
                  >Burn</Button
                >
              </div>
            </div>
          {/each}
          {#if row.pool.length === 0}
            <span class="text-sm text-muted-foreground"
              >Nothing published. Adopt the existing edge or provision one.</span
            >
          {/if}
        </div>

        {#if detailFor === o.id}
          <div class="mt-2 space-y-4 border-t pt-4">
            <div>
              <h3 class="mb-2 text-sm font-semibold">Edges</h3>
              {#if edges.isError}<AdminListState error={edges.error} />{/if}
              <div class="overflow-x-auto">
                <table class="w-full text-xs">
                  <thead class="text-left text-muted-foreground">
                    <tr
                      ><th class="py-1 pr-3">Name</th><th class="pr-3">Provider</th><th class="pr-3"
                        >Status</th
                      ><th class="pr-3">Publication</th><th class="pr-3">Addresses</th><th
                        class="pr-3">Health</th
                      ><th class="pr-3">Steps</th><th></th></tr
                    >
                  </thead>
                  <tbody>
                    {#each edges.data ?? [] as e (e.id)}
                      <tr class="border-t">
                        <td class="py-1.5 pr-3 font-mono">{e.name}</td>
                        <td class="pr-3">{e.provider ?? (e.managed ? '-' : 'adopted')}</td>
                        <td class="pr-3"
                          >{e.status}{e.failure ? ` (${e.failure.code ?? e.failure.step})` : ''}</td
                        >
                        <td class="pr-3"
                          >{e.publication}{e.poolIndex !== null ? ` #${e.poolIndex}` : ''}</td
                        >
                        <td class="pr-3 font-mono"
                          >{e.addresses.v4 ?? '-'}{e.addresses.v6 ? ` / ${e.addresses.v6}` : ''}</td
                        >
                        <td class="pr-3">{e.health}</td>
                        <td class="pr-3">{e.progress.done}/{e.progress.total}</td>
                        <td class="whitespace-nowrap">
                          {#if e.publication === 'published'}
                            <Button
                              size="sm"
                              variant="ghost"
                              class="h-6 px-2 text-xs"
                              onclick={() =>
                                edgeAct.mutate({
                                  id: e.id,
                                  op: 'unpublish',
                                  body: { keepActive: true },
                                })}>Unpublish</Button
                            >
                          {:else if e.status === 'active'}
                            <Button
                              size="sm"
                              variant="ghost"
                              class="h-6 px-2 text-xs"
                              onclick={() => edgeAct.mutate({ id: e.id, op: 'publish' })}
                              >Publish</Button
                            >
                          {/if}
                          {#if e.status === 'needs_operator'}
                            <Button
                              size="sm"
                              variant="ghost"
                              class="h-6 px-2 text-xs"
                              onclick={() =>
                                edgeAct.mutate({
                                  id: e.id,
                                  op: 'resolve-operator',
                                  body: { action: 'destroy' },
                                })}>Destroy</Button
                            >
                            <Button
                              size="sm"
                              variant="ghost"
                              class="h-6 px-2 text-xs"
                              onclick={() =>
                                edgeAct.mutate({
                                  id: e.id,
                                  op: 'resolve-operator',
                                  body: { action: 'reactivate' },
                                })}>Reactivate</Button
                            >
                            <Button
                              size="sm"
                              variant="ghost"
                              class="h-6 px-2 text-xs"
                              onclick={() =>
                                edgeAct.mutate({
                                  id: e.id,
                                  op: 'resolve-operator',
                                  body: { action: 'forget' },
                                })}>Forget</Button
                            >
                          {/if}
                          {#if e.managed && e.status !== 'destroyed'}
                            <Button
                              size="sm"
                              variant="ghost"
                              class="h-6 px-2 text-xs"
                              onclick={() => pullLive.mutate(e.id)}>Live</Button
                            >
                          {/if}
                          <Button
                            size="sm"
                            variant="ghost"
                            class="h-6 px-2 text-xs"
                            onclick={() => edgeAct.mutate({ id: e.id, op: 'probe' })}>Probe</Button
                          >
                          {#if e.publication !== 'published' && e.status !== 'destroyed'}
                            <Button
                              size="sm"
                              variant="ghost"
                              class="h-6 px-2 text-xs text-destructive"
                              onclick={() => edgeDelete.mutate(e.id)}>Delete</Button
                            >
                          {/if}
                        </td>
                      </tr>
                      {#if liveFor === e.id && live}
                        <tr class="border-t bg-muted/30"
                          ><td colspan="8" class="p-2">
                            <pre class="max-h-64 overflow-auto text-[11px]">{JSON.stringify(
                                live,
                                null,
                                2,
                              )}</pre>
                          </td></tr
                        >
                      {/if}
                    {/each}
                  </tbody>
                </table>
              </div>
            </div>
            <div>
              <h3 class="mb-2 text-sm font-semibold">Published endpoints (what members receive)</h3>
              {#if endpoints.data}
                <ul class="space-y-1 text-xs">
                  {#each endpoints.data.published as p (p.edgeId)}
                    <li class="font-mono">
                      #{p.poolIndex}
                      {p.addresses.v4 ?? '-'}{p.addresses.v6 ? ` [${p.addresses.v6}]` : ''}:{p.port} ·
                      slot {p.slotKey} · {p.provider} · SNIs: {p.activeServerNames.join(', ')}
                    </li>
                  {/each}
                </ul>
                <p class="mt-1 text-xs text-muted-foreground">
                  Sample assignment: primary {endpoints.data.sample.primary
                    ? `${endpoints.data.sample.primary.sni}`
                    : '-'}, backup {endpoints.data.sample.backup
                    ? endpoints.data.sample.backup.sni
                    : '-'}. Each subscriber gets a stable pick.
                </p>
              {/if}
            </div>
            <div>
              <h3 class="mb-2 text-sm font-semibold">Recent rotations</h3>
              <ul class="space-y-1 text-xs">
                {#each rotations.data ?? [] as r (r.id)}
                  <li>
                    <button
                      type="button"
                      class="underline-offset-2 hover:underline"
                      onclick={() => (openRotation = r.id)}
                    >
                      {formatDateTime(r.startedAt)} · {r.kind}{r.burn ? ' (burn)' : ''} · {r.trigger}
                      · {r.phase}{r.outcome ? ` · ${r.outcome}` : ''}
                    </button>
                  </li>
                {/each}
                {#if (rotations.data ?? []).length === 0}<li class="text-muted-foreground">
                    None yet.
                  </li>{/if}
              </ul>
            </div>
            <div class="flex justify-end">
              <Button size="sm" variant="destructive" onclick={() => deleteOrigin.mutate(o.id)}
                >Delete origin</Button
              >
            </div>
          </div>
        {/if}
      </CardContent>
    </Card>
  {/each}
</div>

<!-- Origin editor -->
<Dialog.Root open={editor !== null} onOpenChange={(v) => !v && (editor = null)}>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
    <Dialog.Header>
      <Dialog.Title>{editor?.id ? 'Edit origin' : 'New origin'}</Dialog.Title>
      <Dialog.Description>One REALITY node fronted by a pool of published edges.</Dialog.Description
      >
    </Dialog.Header>
    {#if editor}
      <div class="grid gap-3 sm:grid-cols-2">
        {#if !editor.id}
          <label class="text-xs"
            >Slug<Input class="mt-1" bind:value={editor.slug} placeholder="node-one" /></label
          >
          <label class="text-xs"
            >Panel
            <Select.Root
              type="single"
              value={editor.backendServerId}
              onValueChange={(v) => (editor!.backendServerId = v)}
            >
              <Select.Trigger class="mt-1 w-full"
                >{servers.data?.find((s) => s.id === editor?.backendServerId)?.slug ??
                  'Select a panel'}</Select.Trigger
              >
              <Select.Content>
                {#each servers.data ?? [] as s (s.id)}<Select.Item value={s.id}
                    >{s.slug}</Select.Item
                  >{/each}
              </Select.Content>
            </Select.Root>
          </label>
        {/if}
        <label class="text-xs"
          >Node hostname (panel node name)<Input
            class="mt-1"
            bind:value={editor.nodeHostname}
          /></label
        >
        <label class="text-xs"
          >Origin address<Input class="mt-1" bind:value={editor.originAddress} /></label
        >
        <label class="text-xs"
          >Location code<Input class="mt-1" bind:value={editor.locationCode} /></label
        >
        <label class="text-xs">Mode slugs<Input class="mt-1" bind:value={editor.modeSlugs} /></label
        >
        <label class="text-xs"
          >Desired published (1-4)<Input
            class="mt-1"
            type="number"
            bind:value={editor.desiredPublished}
          /></label
        >
        <label class="text-xs"
          >Standby edges (0-2)<Input
            class="mt-1"
            type="number"
            bind:value={editor.standbyPerOrigin}
          /></label
        >
        <label class="text-xs"
          >Cooldown (minutes)<Input
            class="mt-1"
            type="number"
            bind:value={editor.cooldownMinutes}
          /></label
        >
        <label class="text-xs"
          >Max rotations per day<Input
            class="mt-1"
            type="number"
            bind:value={editor.maxRotationsPerDay}
          /></label
        >
        <label class="text-xs"
          >Drain (minutes)<Input
            class="mt-1"
            type="number"
            bind:value={editor.drainMinutes}
          /></label
        >
        <label class="text-xs"
          >Provider affinity
          <Select.Root
            type="single"
            value={editor.providerAffinity}
            onValueChange={(v) => (editor!.providerAffinity = v === 'sticky' ? 'sticky' : 'rotate')}
          >
            <Select.Trigger class="mt-1 w-full">{editor.providerAffinity}</Select.Trigger>
            <Select.Content
              ><Select.Item value="rotate">rotate</Select.Item><Select.Item value="sticky"
                >sticky</Select.Item
              ></Select.Content
            >
          </Select.Root>
        </label>
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox bind:checked={editor.enabled} /> Enabled</label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox bind:checked={editor.hostManaged} /> FCP manages the template Host</label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox bind:checked={editor.autoRotate} /> Automatic rotation (also needs the global switch)</label
        >
      </div>
    {/if}
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (editor = null)}>Cancel</Button>
      <Button disabled={saveOrigin.isPending} onclick={() => saveOrigin.mutate()}>Save</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<!-- Adopt edge -->
<Dialog.Root open={adoptFor !== null} onOpenChange={(v) => !v && (adoptFor = null)}>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>Adopt an existing edge</Dialog.Title>
      <Dialog.Description>
        Record a load balancer that exists outside FCP's ledger (observe-only: FCP never destroys
        it).
      </Dialog.Description>
    </Dialog.Header>
    <div class="grid gap-3">
      <label class="text-xs"
        >Slot
        <Select.Root type="single" value={adopt.slotId} onValueChange={(v) => (adopt.slotId = v)}>
          <Select.Trigger class="mt-1 w-full"
            >{slotsForAdopt.data?.find((s) => s.id === adopt.slotId)?.slotKey ??
              'Select a slot'}</Select.Trigger
          >
          <Select.Content>
            {#each slotsForAdopt.data ?? [] as s (s.id)}<Select.Item value={s.id}
                >{s.slotKey} · {s.provider} · {s.templateHostRemark}</Select.Item
              >{/each}
          </Select.Content>
        </Select.Root>
      </label>
      <label class="text-xs"
        >IPv4<Input class="mt-1" bind:value={adopt.ipv4} placeholder="198.51.100.7" /></label
      >
      <label class="text-xs">IPv6 (optional)<Input class="mt-1" bind:value={adopt.ipv6} /></label>
      <label class="text-xs">Port<Input class="mt-1" type="number" bind:value={adopt.port} /></label
      >
      <label class="flex items-center gap-2 text-sm"
        ><Checkbox bind:checked={adopt.publish} /> Publish at the next free pool index</label
      >
    </div>
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (adoptFor = null)}>Cancel</Button>
      <Button disabled={adoptEdge.isPending || !adopt.slotId} onclick={() => adoptEdge.mutate()}
        >Adopt</Button
      >
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<!-- Rotation progress -->
<Dialog.Root open={openRotation !== null} onOpenChange={(v) => !v && (openRotation = null)}>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
    <Dialog.Header>
      <Dialog.Title>Rotation</Dialog.Title>
      {#if rotation.data}
        <Dialog.Description>
          {rotation.data.kind}{rotation.data.burn ? ' (burn)' : ''} · {rotation.data.trigger} · started
          {formatDateTime(rotation.data.startedAt)}
        </Dialog.Description>
      {/if}
    </Dialog.Header>
    {#if rotation.data}
      {@const r = rotation.data}
      <div class="space-y-3 text-sm">
        <div>
          <div class="flex items-center justify-between">
            <span>{r.phase}{r.outcome ? ` · ${r.outcome}` : ''}</span><span class="tabular-nums"
              >{r.progress.percent}%</span
            >
          </div>
          <div class="mt-1 h-2 w-full overflow-hidden rounded bg-muted">
            <div
              class="h-full transition-all {r.phase === 'done'
                ? 'bg-emerald-500'
                : r.terminal
                  ? 'bg-destructive'
                  : 'bg-sky-500'}"
              style="width: {r.progress.percent}%"
            ></div>
          </div>
        </div>
        {#if r.edge}
          <div class="text-xs">
            New edge: {r.edge.provider ?? '-'} ·
            <span class="font-mono"
              >{r.edge.addresses.v4 ?? '-'}{r.edge.addresses.v6
                ? ` / ${r.edge.addresses.v6}`
                : ''}</span
            >
            · {r.edge.health} · {r.edge.status}
          </div>
        {/if}
        {#if r.steps.length > 0}
          <ul class="grid gap-1 text-xs sm:grid-cols-2">
            {#each r.steps as s (s.stepId)}
              <li class="rounded border px-2 py-1">
                <span class="font-mono">{s.stepId}</span> · {s.kind} ·
                <span
                  class={s.state === 'done'
                    ? 'text-emerald-600'
                    : s.state === 'pending'
                      ? 'text-muted-foreground'
                      : ''}>{s.state}</span
                >
              </li>
            {/each}
          </ul>
        {/if}
        <div>
          <h4 class="mb-1 text-xs font-semibold">Live log</h4>
          <ul class="max-h-64 space-y-0.5 overflow-auto rounded border p-2 font-mono text-[11px]">
            {#each r.events as ev, i (i)}
              <li
                class={ev.level === 'error'
                  ? 'text-destructive'
                  : ev.level === 'warn'
                    ? 'text-amber-600'
                    : ''}
              >
                {formatDateTime(ev.at)}
                {ev.code}{ev.detail ? `: ${ev.detail}` : ''}
              </li>
            {/each}
          </ul>
        </div>
        {#if !r.terminal}
          <div class="flex justify-end">
            <Button
              size="sm"
              variant="outline"
              onclick={() => act.mutate({ id: r.originId, op: 'cancel' })}>Cancel rotation</Button
            >
          </div>
        {/if}
      </div>
    {/if}
  </Dialog.Content>
</Dialog.Root>
