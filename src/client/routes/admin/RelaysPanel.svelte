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
    adminEdgeInventoryQuery,
    adminEdgeProvidersQuery,
    adminRelayEdgesQuery,
    adminRelayNodeCandidatesQuery,
    adminRelayEndpointsQuery,
    adminRelayRotationQuery,
    adminRelayRotationsQuery,
    adminRelaySlotsQuery,
    queryKeys,
  } from '../../lib/queries';
  import {
    EdgeAdoptResponse,
    EdgeIdResponse,
    EdgeInventoryResponse,
    RelayNodeCandidatesResponse,
    EdgeOkResponse,
    ProbeRequestedResponse,
    EdgeRotationStartedResponse,
    EdgeLiveResponse,
    type RelayAdmin,
    type EdgeSummary,
  } from '../../../shared/contracts/edges';
  import { formatDateTime } from '../../lib/i18n/format';
  import AdminListState from './AdminListState.svelte';

  interface Props {
    summary: EdgeSummary | null;
  }
  let { summary }: Props = $props();
  const qc = useQueryClient();
  const servers = adminBackendServersQuery();

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['admin', 'edges'] });
    void qc.invalidateQueries({ queryKey: queryKeys.adminStatus });
  };
  const onError = (title: string) => (err: unknown) =>
    toast.error(title, { description: apiErrorMessage(err) });

  // --- relay editor -------------------------------------------------------------
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
    probeNode: boolean;
    providerAffinity: 'rotate' | 'sticky';
    desiredPublished: number;
    standbyPerRelay: number;
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
      probeNode: false,
      providerAffinity: 'rotate',
      desiredPublished: 2,
      standbyPerRelay: 0,
      cooldownMinutes: 120,
      maxRotationsPerDay: 3,
      drainMinutes: 1440,
    };
  }
  function editDraft(o: RelayAdmin): OriginDraft {
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
      probeNode: o.probeNode,
      providerAffinity: o.providerAffinity,
      desiredPublished: o.desiredPublished,
      standbyPerRelay: o.standbyPerRelay,
      cooldownMinutes: o.cooldownMinutes,
      maxRotationsPerDay: o.maxRotationsPerDay,
      drainMinutes: o.drainMinutes,
    };
  }
  // Node picker: the panel's node list (inventory cache) pre-fills hostname,
  // uuid, origin address and location; "Refresh nodes" pulls it again now.
  const nodeCandidates = adminRelayNodeCandidatesQuery(() =>
    editor && !editor.id ? editor.backendServerId || null : null,
  );
  const refreshNodes = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/admin/edges/relays/node-candidates/refresh',
        { backendServerId: editor?.backendServerId },
        RelayNodeCandidatesResponse,
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['admin', 'edges', 'node-candidates'] });
      toast.success('Node list refreshed');
    },
    onError: onError('Could not pull the node list'),
  }));
  function pickNode(uuid: string) {
    const n = nodeCandidates.data?.nodes.find((x) => x.nodeUuid === uuid);
    if (!n || !editor) return;
    editor.nodeHostname = n.name;
    if (n.address) editor.originAddress = n.address;
    if (n.countryCode) editor.locationCode = n.countryCode;
    if (!editor.slug) editor.slug = n.name.toLowerCase().replace(/[^a-z0-9-]/g, '-');
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
        probeNode: d.probeNode,
        providerAffinity: d.providerAffinity,
        desiredPublished: Number(d.desiredPublished),
        standbyPerRelay: Number(d.standbyPerRelay),
        cooldownMinutes: Number(d.cooldownMinutes),
        maxRotationsPerDay: Number(d.maxRotationsPerDay),
        drainMinutes: Number(d.drainMinutes),
      };
      if (d.id) return apiClient.patch(`/api/v1/admin/edges/relays/${d.id}`, body, EdgeOkResponse);
      return apiClient.post(
        '/api/v1/admin/edges/relays',
        { ...body, slug: d.slug.trim(), backendServerId: d.backendServerId },
        EdgeIdResponse,
      );
    },
    onSuccess: () => {
      editor = null;
      invalidate();
      toast.success('Relay saved');
    },
    onError: onError('Could not save the relay'),
  }));
  const deleteOrigin = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/edges/relays/${id}`, EdgeOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Teardown requested; edges drain and destroy in the background');
    },
    onError: onError('Could not delete the relay'),
  }));

  // --- relay actions ---------------------------------------------------------------
  const act = createMutation(() => ({
    mutationFn: ({ id, op, body }: { id: string; op: string; body?: Record<string, unknown> }) =>
      apiClient.post(
        `/api/v1/admin/edges/relays/${id}/${op}`,
        body ?? {},
        EdgeRotationStartedResponse.or(EdgeOkResponse).or(ProbeRequestedResponse),
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

  // --- import / adopt -----------------------------------------------------------------
  // Two ways to bring an existing load balancer under FCP: pick it from a
  // provider account's inventory (managed: FCP can describe, rotate and destroy
  // it) or type its addresses (observe-only: never touched at the provider).
  let adoptFor = $state<string | null>(null);
  let adopt = $state({
    source: 'provider' as 'provider' | 'manual',
    slotId: '',
    accountId: '',
    lbId: '',
    ipv4: '',
    ipv6: '',
    port: 443,
    publish: true,
  });
  const slotsForAdopt = adminRelaySlotsQuery(() => adoptFor);
  const accounts = adminEdgeProvidersQuery();
  const inventory = adminEdgeInventoryQuery(() =>
    adoptFor !== null && adopt.source === 'provider' && adopt.accountId ? adopt.accountId : null,
  );
  const adoptSlot = $derived(slotsForAdopt.data?.find((s) => s.id === adopt.slotId) ?? null);
  // Accounts the slot's profile allows (a provider-scoped profile narrows the list).
  const adoptAccounts = $derived(
    (accounts.data?.accounts ?? []).filter(
      (a) => !adoptSlot?.provider || a.provider === adoptSlot.provider,
    ),
  );
  const inventoryLbs = $derived(
    [...(inventory.data?.inventory?.loadBalancers ?? [])].sort(
      (a, b) => Number(b.unowned ?? true) - Number(a.unowned ?? true),
    ),
  );
  function pickLb(id: string) {
    const lb = inventoryLbs.find((x) => x.id === id);
    if (!lb) return;
    adopt.lbId = id;
    adopt.ipv4 = lb.addresses.v4 ?? '';
    adopt.ipv6 = lb.addresses.v6 ?? '';
  }
  const refreshInventory = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.post(
        `/api/v1/admin/edges/providers/${id}/inventory/refresh`,
        {},
        EdgeInventoryResponse,
      ),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: [...queryKeys.adminEdgeProviders, 'inventory'] }),
    onError: onError('Could not pull the inventory'),
  }));
  const adoptEdge = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        `/api/v1/admin/edges/relays/${adoptFor}/adopt`,
        {
          slotId: adopt.slotId,
          ipv4: adopt.ipv4.trim(),
          ipv6: adopt.ipv6.trim() || null,
          port: Number(adopt.port) || 443,
          publish: adopt.publish,
          ...(adopt.source === 'provider' && adopt.accountId && adopt.lbId
            ? {
                accountId: adopt.accountId,
                resources: [{ kind: 'lb', resourceId: adopt.lbId }],
              }
            : {}),
        },
        EdgeAdoptResponse,
      ),
    onSuccess: () => {
      adoptFor = null;
      invalidate();
      toast.success(adopt.source === 'provider' ? 'Edge imported' : 'Edge recorded');
    },
    onError: onError('Could not import the edge'),
  }));
  const adoptReady = $derived(
    !!adopt.slotId &&
      !!adopt.ipv4.trim() &&
      (adopt.source === 'manual' || (!!adopt.accountId && !!adopt.lbId)),
  );

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
        `/api/v1/admin/edges/${id}/${op}`,
        body ?? {},
        EdgeOkResponse.or(EdgeRotationStartedResponse).or(ProbeRequestedResponse),
      ),
    onSuccess: (r) => {
      invalidate();
      if ('rotationId' in r && typeof r.rotationId === 'string') openRotation = r.rotationId;
      toast.success('Done');
    },
    onError: onError('Edge action refused'),
  }));
  const edgeDelete = createMutation(() => ({
    mutationFn: (id: string) => apiClient.delete(`/api/v1/admin/edges/${id}`, EdgeOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Edge scheduled for destruction');
    },
    onError: onError('Could not delete the edge'),
  }));
  const pullLive = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.post(`/api/v1/admin/edges/${id}/live/refresh`, {}, EdgeLiveResponse),
    onSuccess: (r, id) => {
      liveFor = id;
      live = (r.live as Record<string, unknown> | null) ?? null;
      invalidate();
    },
    onError: onError('Could not pull live data'),
  }));

  function suspicionBadge(o: RelayAdmin): { text: string; cls: string } | null {
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
    <Button onclick={() => (editor = newDraft())}>New relay</Button>
  </div>

  {#if !summary || summary.relays.length === 0}
    <AdminListState
      emptyText="No relays yet. The node role registers one per relay node (PUT /api/v1/admin/edges/relays/by-slug/<slug>), or create one here."
    />
  {/if}

  {#each summary?.relays ?? [] as row (row.relay.id)}
    {@const o = row.relay}
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
              <span class="font-mono">{o.originAddress}</span> · pool {row.relay
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
            <Button size="sm" variant="outline" onclick={() => (adoptFor = o.id)}
              >Import edge</Button
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
                      slot {p.slotKey} ({p.protocol}) · {p.provider}{p.protocol === 'reality'
                        ? ` · SNIs: ${p.activeServerNames.join(', ')}`
                        : ''}
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
                >Delete relay</Button
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
      <Dialog.Title>{editor?.id ? 'Edit relay' : 'New relay'}</Dialog.Title>
      <Dialog.Description
        >One node fronted by a pool of published edges; each slot declares the protocol it speaks.</Dialog.Description
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
        {#if !editor.id && editor.backendServerId}
          <div class="sm:col-span-2 rounded-md border p-2">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-medium">Pick a node from the panel</span>
              <Button
                size="sm"
                variant="ghost"
                class="h-6 px-2 text-xs"
                disabled={refreshNodes.isPending}
                onclick={() => refreshNodes.mutate()}
                >{refreshNodes.isPending ? 'Refreshing…' : 'Refresh nodes'}</Button
              >
            </div>
            {#if nodeCandidates.data && nodeCandidates.data.nodes.length > 0}
              <Select.Root type="single" value="" onValueChange={(v) => pickNode(v)}>
                <Select.Trigger class="mt-1 w-full"
                  >Select a node to pre-fill the fields</Select.Trigger
                >
                <Select.Content>
                  {#each nodeCandidates.data.nodes as n (n.nodeUuid)}
                    <Select.Item value={n.nodeUuid} disabled={!!n.relaySlug}
                      >{n.name} · {n.address ?? 'no address'}{n.countryCode
                        ? ` · ${n.countryCode}`
                        : ''} · {n.online ? 'online' : 'offline'}{n.relaySlug
                        ? ` · already relay ${n.relaySlug}`
                        : ''}</Select.Item
                    >
                  {/each}
                </Select.Content>
              </Select.Root>
              <p class="mt-1 text-[11px] text-muted-foreground">
                From the panel's node list{nodeCandidates.data.fetchedAt
                  ? ` as of ${formatDateTime(nodeCandidates.data.fetchedAt)}`
                  : ''}. Fields stay editable.
              </p>
            {:else if nodeCandidates.isPending}
              <p class="mt-1 text-[11px] text-muted-foreground">Loading nodes…</p>
            {:else}
              <p class="mt-1 text-[11px] text-muted-foreground">
                No cached node list for this panel yet. Refresh to pull it now.
              </p>
            {/if}
          </div>
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
            bind:value={editor.standbyPerRelay}
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
          ><Checkbox bind:checked={editor.probeNode} /> Probe the node's own address too (Telemetry →
          Probes)</label
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
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-xl">
    <Dialog.Header>
      <Dialog.Title>Import an existing edge</Dialog.Title>
      <Dialog.Description>
        Bring a load balancer that already fronts this relay under FCP. Picked from a provider
        account it becomes a managed edge (FCP can describe, rotate and destroy it); entered by
        address it is observe-only and never touched at the provider.
      </Dialog.Description>
    </Dialog.Header>
    <div class="grid gap-3">
      <div class="flex gap-1">
        <Button
          size="sm"
          variant={adopt.source === 'provider' ? 'default' : 'outline'}
          onclick={() => (adopt.source = 'provider')}>From a provider account</Button
        >
        <Button
          size="sm"
          variant={adopt.source === 'manual' ? 'default' : 'outline'}
          onclick={() => (adopt.source = 'manual')}>By address (observe-only)</Button
        >
      </div>
      <label class="text-xs"
        >Slot
        <Select.Root type="single" value={adopt.slotId} onValueChange={(v) => (adopt.slotId = v)}>
          <Select.Trigger class="mt-1 w-full"
            >{slotsForAdopt.data?.find((s) => s.id === adopt.slotId)?.slotKey ??
              'Select a slot'}</Select.Trigger
          >
          <Select.Content>
            {#each slotsForAdopt.data ?? [] as s (s.id)}<Select.Item value={s.id}
                >{s.slotKey} · {s.protocol} · {s.provider ?? 'any provider'} · {s.templateHostRemark}</Select.Item
              >{/each}
          </Select.Content>
        </Select.Root>
      </label>
      {#if adopt.source === 'provider'}
        <label class="text-xs"
          >Provider account
          <Select.Root
            type="single"
            value={adopt.accountId}
            onValueChange={(v) => {
              adopt.accountId = v;
              adopt.lbId = '';
            }}
          >
            <Select.Trigger class="mt-1 w-full"
              >{adoptAccounts.find((a) => a.id === adopt.accountId)?.name ??
                (adoptAccounts.length
                  ? 'Select an account'
                  : 'No account for this slot')}</Select.Trigger
            >
            <Select.Content>
              {#each adoptAccounts as a (a.id)}<Select.Item value={a.id}
                  >{a.name} · {a.provider}</Select.Item
                >{/each}
            </Select.Content>
          </Select.Root>
        </label>
        {#if adopt.accountId}
          <div class="rounded-md border border-border">
            <div class="flex items-center justify-between gap-2 border-b px-3 py-2 text-xs">
              <span class="text-muted-foreground">
                {#if inventory.isPending}Loading the account's load balancers…{:else if inventory.data?.inventoryAt}Load
                  balancers as of {formatDateTime(inventory.data.inventoryAt)}{:else}Not pulled yet{/if}
              </span>
              <Button
                size="sm"
                variant="ghost"
                disabled={refreshInventory.isPending}
                onclick={() => refreshInventory.mutate(adopt.accountId)}>Refresh</Button
              >
            </div>
            {#if inventory.isError}
              <p class="px-3 py-2 text-xs text-destructive">{apiErrorMessage(inventory.error)}</p>
            {:else if !inventory.isPending && inventoryLbs.length === 0}
              <p class="px-3 py-2 text-xs text-muted-foreground">
                No load balancers in this account. Provision one from the relay instead, or enter
                the addresses by hand.
              </p>
            {:else}
              <ul class="max-h-56 overflow-y-auto divide-y">
                {#each inventoryLbs as lb (lb.id)}
                  <li>
                    <button
                      type="button"
                      class="flex w-full items-start justify-between gap-3 px-3 py-2 text-left text-xs hover:bg-muted/50 {adopt.lbId ===
                      lb.id
                        ? 'bg-muted'
                        : ''}"
                      onclick={() => pickLb(lb.id)}
                    >
                      <span>
                        <span class="font-medium">{lb.name}</span>
                        <span class="ml-2 font-mono text-muted-foreground"
                          >{lb.addresses.v4 ?? 'no IPv4'}{lb.addresses.v6
                            ? ` · ${lb.addresses.v6}`
                            : ''}</span
                        >
                      </span>
                      <span class="shrink-0 text-muted-foreground">
                        {lb.status ?? ''}{lb.unowned === false ? ' · already an edge' : ''}
                      </span>
                    </button>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        {/if}
      {/if}
      <div class="grid gap-3 sm:grid-cols-3">
        <label class="text-xs"
          >IPv4<Input
            class="mt-1"
            bind:value={adopt.ipv4}
            placeholder="198.51.100.7"
            readonly={adopt.source === 'provider'}
          /></label
        >
        <label class="text-xs"
          >IPv6 (optional)<Input
            class="mt-1"
            bind:value={adopt.ipv6}
            readonly={adopt.source === 'provider'}
          /></label
        >
        <label class="text-xs"
          >Port<Input class="mt-1" type="number" bind:value={adopt.port} /></label
        >
      </div>
      <label class="flex items-center gap-2 text-sm"
        ><Checkbox bind:checked={adopt.publish} /> Publish at the next free pool index</label
      >
    </div>
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (adoptFor = null)}>Cancel</Button>
      <Button disabled={adoptEdge.isPending || !adoptReady} onclick={() => adoptEdge.mutate()}
        >{adopt.source === 'provider' ? 'Import' : 'Record'}</Button
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
        <div>
          <h4 class="mb-1 text-xs font-semibold">Audit trail</h4>
          <p class="mb-1 text-[11px] text-muted-foreground">
            Every audit row this rotation produced: the operator's request, publish and unpublish,
            Host flips, the outcome, quarantine and its resolution.
          </p>
          {#if r.audit.length === 0}
            <p class="text-xs text-muted-foreground">No audit rows yet.</p>
          {:else}
            <ul class="max-h-64 space-y-0.5 overflow-auto rounded border p-2 text-[11px]">
              {#each r.audit as a (a.id)}
                <li class="flex flex-wrap gap-x-2">
                  <span class="tabular-nums text-muted-foreground"
                    >{formatDateTime(a.createdAt)}</span
                  >
                  <span class="font-mono">{a.action}</span>
                  <span class="text-muted-foreground">{a.actorType}</span>
                  <span
                    class="truncate font-mono text-muted-foreground"
                    title={JSON.stringify(a.payload)}
                    >{a.payload ? JSON.stringify(a.payload) : ''}</span
                  >
                </li>
              {/each}
            </ul>
          {/if}
        </div>
        {#if !r.terminal}
          <div class="flex justify-end">
            <Button
              size="sm"
              variant="outline"
              onclick={() => act.mutate({ id: r.relayId, op: 'cancel' })}>Cancel rotation</Button
            >
          </div>
        {/if}
      </div>
    {/if}
  </Dialog.Content>
</Dialog.Root>
