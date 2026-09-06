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
  import { adminEdgeProvidersQuery, adminEdgeTemplatesQuery } from '../../lib/queries';
  import {
    EDGE_PROVIDER_IDS,
    RelayIdResponse,
    EdgeInventoryResponse,
    RelayOkResponse,
    EdgeTestCredentialsResponse,
    type EdgeProviderAccountAdmin,
    type EdgeProviderId,
  } from '../../../shared/contracts/relays';
  import { formatDateTime } from '../../lib/i18n/format';
  import AdminListState from './AdminListState.svelte';

  /**
   * Provider accounts: credentials (write-only, keep-on-blank), the fixed
   * settings (project/region/zone/network), the qualification gate, and a live
   * inventory pull (load balancers + IPs the account holds, unowned ones flagged).
   */
  const providers = adminEdgeProvidersQuery();
  const templates = adminEdgeTemplatesQuery();
  const qc = useQueryClient();
  const invalidate = () => void qc.invalidateQueries({ queryKey: ['admin', 'relays'] });
  const onError = (title: string) => (err: unknown) =>
    toast.error(title, { description: apiErrorMessage(err) });

  // Settings the adapters need per provider (the server validates the exact shape).
  const SETTINGS_HINT: Record<EdgeProviderId, string> = {
    gcore: '{ "projectId": 123, "regionId": 45, "networkId": "optional", "subnetId": "optional" }',
    upcloud: '{ "zone": "de-fra1" }',
    scaleway: '{ "accessKey": "SCW…", "projectId": "uuid", "zone": "fr-par-1" }',
    ovh: '{ "applicationKey": "…", "endpoint": "ovh-eu", "serviceName": "…", "regionName": "…", "networkId": "…", "subnetId": "…", "gatewayId": "optional" }',
  };

  type Draft = {
    id: string | null;
    provider: EdgeProviderId;
    name: string;
    settings: string;
    credentials: Record<string, string>;
    enabled: boolean;
    priority: number;
    dailyAllocationBudget: number;
    maxLiveEdges: number;
    defaultTemplateId: string;
  };
  let editor = $state<Draft | null>(null);
  function newDraft(): Draft {
    return {
      id: null,
      provider: 'gcore',
      name: '',
      settings: SETTINGS_HINT.gcore,
      credentials: {},
      enabled: true,
      priority: 10,
      dailyAllocationBudget: 6,
      maxLiveEdges: 4,
      defaultTemplateId: '',
    };
  }
  function editDraft(a: EdgeProviderAccountAdmin): Draft {
    return {
      id: a.id,
      provider: a.provider,
      name: a.name,
      settings: JSON.stringify(a.settings, null, 2),
      credentials: {},
      enabled: a.enabled,
      priority: a.priority,
      dailyAllocationBudget: a.dailyAllocationBudget,
      maxLiveEdges: a.maxLiveEdges,
      defaultTemplateId: a.defaultTemplateId ?? '',
    };
  }
  const credentialFields = $derived(providers.data?.credentialFields ?? {});

  const save = createMutation(() => ({
    mutationFn: async () => {
      const d = editor!;
      let settings: unknown;
      try {
        settings = JSON.parse(d.settings);
      } catch {
        throw new Error('Settings must be valid JSON');
      }
      const creds = Object.fromEntries(
        Object.entries(d.credentials).filter(([, v]) => v.trim() !== ''),
      );
      const body = {
        settings,
        ...(Object.keys(creds).length > 0 ? { credentials: creds } : {}),
        enabled: d.enabled,
        priority: Number(d.priority),
        dailyAllocationBudget: Number(d.dailyAllocationBudget),
        maxLiveEdges: Number(d.maxLiveEdges),
        defaultTemplateId: d.defaultTemplateId || null,
      };
      if (d.id)
        return apiClient.patch(`/api/v1/admin/relay/providers/${d.id}`, body, RelayOkResponse);
      return apiClient.post(
        '/api/v1/admin/relay/providers',
        { ...body, provider: d.provider, name: d.name.trim(), credentials: creds },
        RelayIdResponse,
      );
    },
    onSuccess: () => {
      editor = null;
      invalidate();
      toast.success('Account saved');
    },
    onError: onError('Could not save the account'),
  }));
  const remove = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/relay/providers/${id}`, RelayOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Account removed');
    },
    onError: onError('Could not remove the account'),
  }));
  let testResult = $state<Record<string, { ok: boolean; code: string | null; regions: string[] }>>(
    {},
  );
  const test = createMutation(() => ({
    mutationFn: (accountId: string) =>
      apiClient.post(
        '/api/v1/admin/relay/providers/test-credentials',
        { accountId },
        EdgeTestCredentialsResponse,
      ),
    onSuccess: (r, accountId) => {
      testResult = {
        ...testResult,
        [accountId]: { ok: r.ok, code: r.code, regions: r.regions.map((x) => x.id) },
      };
      invalidate();
      if (r.ok) toast.success('Credentials work');
      else toast.error('Credentials rejected', { description: r.code ?? undefined });
    },
    onError: onError('Test failed'),
  }));
  const qualify = createMutation(() => ({
    mutationFn: ({ id, qualified }: { id: string; qualified: boolean }) =>
      apiClient.post(`/api/v1/admin/relay/providers/${id}/qualify`, { qualified }, RelayOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Qualification updated');
    },
    onError: onError('Could not update qualification'),
  }));
  let inventory = $state<
    Record<string, { at: string | null; lbs: number; ips: number; unowned: number; rows: string[] }>
  >({});
  const pullInventory = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.post(
        `/api/v1/admin/relay/providers/${id}/inventory/refresh`,
        {},
        EdgeInventoryResponse,
      ),
    onSuccess: (r, id) => {
      const inv = r.inventory;
      inventory = {
        ...inventory,
        [id]: {
          at: r.inventoryAt,
          lbs: inv?.loadBalancers.length ?? 0,
          ips: inv?.ips.length ?? 0,
          unowned: inv?.loadBalancers.filter((l) => l.unowned).length ?? 0,
          rows: (inv?.loadBalancers ?? []).map(
            (l) =>
              `${l.name} · ${l.status ?? '-'} · ${l.addresses.v4 ?? '-'}${l.unowned ? ' · UNOWNED' : ''}`,
          ),
        },
      };
      invalidate();
    },
    onError: onError('Could not pull the inventory'),
  }));
</script>

<div class="space-y-4">
  <div class="flex justify-end">
    <Button onclick={() => (editor = newDraft())}>New account</Button>
  </div>
  {#if providers.isError}<AdminListState
      error={providers.error}
      onRetry={() => void providers.refetch()}
    />{/if}
  {#if providers.data && providers.data.accounts.length === 0}
    <AdminListState
      emptyText="No provider accounts. Add one, test its credentials, then qualify it after a manual REALITY check through a test edge."
    />
  {/if}
  {#each providers.data?.accounts ?? [] as a (a.id)}
    <Card>
      <CardHeader class="pb-2">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle class="flex items-center gap-2 text-base">
              <span>{a.name}</span>
              <span class="rounded-full border px-2 py-0.5 text-xs">{a.provider}</span>
              {#if !a.enabled}<span class="rounded-full border px-2 py-0.5 text-xs">disabled</span
                >{/if}
              <span
                class="rounded-full border px-2 py-0.5 text-xs {a.qualified
                  ? 'border-emerald-500/40 bg-emerald-500/10'
                  : 'border-amber-500/40 bg-amber-500/10'}"
                >{a.qualified ? 'qualified' : 'not qualified'}</span
              >
            </CardTitle>
            <CardDescription class="mt-1">
              priority {a.priority} · budget {a.allocationsToday}/{a.dailyAllocationBudget} today · cap
              {a.maxLiveEdges} live edges · credentials {Object.entries(a.credentialsSet)
                .map(([k, v]) => `${k}${v ? ' set' : ' missing'}`)
                .join(', ')}
              {#if a.lastTestOkAt}· last test OK {formatDateTime(a.lastTestOkAt)}{/if}
              {#if a.lastTestError}· last test failed: {a.lastTestError}{/if}
            </CardDescription>
          </div>
          <div class="flex flex-wrap gap-1.5">
            <Button
              size="sm"
              variant="outline"
              disabled={test.isPending}
              onclick={() => test.mutate(a.id)}>Test credentials</Button
            >
            <Button
              size="sm"
              variant="outline"
              disabled={pullInventory.isPending}
              onclick={() => pullInventory.mutate(a.id)}>Inventory</Button
            >
            <Button
              size="sm"
              variant={a.qualified ? 'ghost' : 'default'}
              onclick={() => qualify.mutate({ id: a.id, qualified: !a.qualified })}
              >{a.qualified ? 'Revoke qualification' : 'Mark qualified'}</Button
            >
            <Button size="sm" variant="ghost" onclick={() => (editor = editDraft(a))}>Edit</Button>
            <Button
              size="sm"
              variant="ghost"
              class="text-destructive"
              onclick={() => remove.mutate(a.id)}>Remove</Button
            >
          </div>
        </div>
      </CardHeader>
      <CardContent class="space-y-2 text-xs">
        <div class="font-mono text-muted-foreground">{JSON.stringify(a.settings)}</div>
        {@const tr = testResult[a.id]}
        {#if tr}
          <div>
            Test: {tr.ok ? 'OK' : `failed (${tr.code ?? 'unknown'})`}{tr.regions.length
              ? ` · regions: ${tr.regions.join(', ')}`
              : ''}
          </div>
        {/if}
        {@const inv = inventory[a.id]}
        {#if inv}
          <div>
            Inventory {inv.at ? formatDateTime(inv.at) : ''}: {inv.lbs} load balancers, {inv.ips} IPs{inv.unowned >
            0
              ? `, ${inv.unowned} not in any edge ledger`
              : ''}
            <ul class="mt-1 space-y-0.5 font-mono">
              {#each inv.rows as row, i (i)}<li>{row}</li>{/each}
            </ul>
          </div>
        {/if}
      </CardContent>
    </Card>
  {/each}
</div>

<Dialog.Root open={editor !== null} onOpenChange={(v) => !v && (editor = null)}>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
    <Dialog.Header>
      <Dialog.Title>{editor?.id ? 'Edit account' : 'New provider account'}</Dialog.Title>
      <Dialog.Description
        >Credentials are write-only: blank fields keep the stored value. Changing credentials or
        settings clears the qualification.</Dialog.Description
      >
    </Dialog.Header>
    {#if editor}
      <div class="grid gap-3">
        {#if !editor.id}
          <label class="text-xs"
            >Provider
            <Select.Root
              type="single"
              value={editor.provider}
              onValueChange={(v) => {
                editor!.provider = v as EdgeProviderId;
                editor!.settings = SETTINGS_HINT[v as EdgeProviderId];
              }}
            >
              <Select.Trigger class="mt-1 w-full">{editor.provider}</Select.Trigger>
              <Select.Content
                >{#each EDGE_PROVIDER_IDS as p (p)}<Select.Item value={p}>{p}</Select.Item
                  >{/each}</Select.Content
              >
            </Select.Root>
          </label>
          <label class="text-xs"
            >Name<Input class="mt-1" bind:value={editor.name} placeholder="account-a" /></label
          >
        {/if}
        <label class="text-xs"
          >Settings (JSON)
          <textarea
            class="mt-1 w-full rounded-md border bg-background p-2 font-mono text-xs"
            rows="4"
            bind:value={editor.settings}
          ></textarea>
        </label>
        {#each credentialFields[editor.provider] ?? [] as field (field)}
          <label class="text-xs"
            >{field}<Input
              class="mt-1 font-mono"
              type="password"
              autocomplete="off"
              bind:value={editor.credentials[field]}
              placeholder={editor.id ? '(unchanged)' : ''}
            /></label
          >
        {/each}
        <div class="grid gap-3 sm:grid-cols-3">
          <label class="text-xs"
            >Priority (lower first)<Input
              class="mt-1"
              type="number"
              bind:value={editor.priority}
            /></label
          >
          <label class="text-xs"
            >Daily allocation budget<Input
              class="mt-1"
              type="number"
              bind:value={editor.dailyAllocationBudget}
            /></label
          >
          <label class="text-xs"
            >Max live edges<Input
              class="mt-1"
              type="number"
              bind:value={editor.maxLiveEdges}
            /></label
          >
        </div>
        <label class="text-xs"
          >Default template
          <Select.Root
            type="single"
            value={editor.defaultTemplateId}
            onValueChange={(v) => (editor!.defaultTemplateId = v)}
          >
            <Select.Trigger class="mt-1 w-full"
              >{templates.data?.templates.find((t) => t.id === editor?.defaultTemplateId)?.name ??
                'Provider default'}</Select.Trigger
            >
            <Select.Content>
              <Select.Item value="">Provider default</Select.Item>
              {#each (templates.data?.templates ?? []).filter((t) => t.provider === editor?.provider) as t (t.id)}<Select.Item
                  value={t.id}>{t.name}</Select.Item
                >{/each}
            </Select.Content>
          </Select.Root>
        </label>
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox bind:checked={editor.enabled} /> Enabled</label
        >
      </div>
    {/if}
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (editor = null)}>Cancel</Button>
      <Button disabled={save.isPending} onclick={() => save.mutate()}>Save</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
