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
    EdgeIdResponse,
    EdgeDiscoverResponse,
    EdgeInventoryResponse,
    EdgeOkResponse,
    EdgeRotateCredentialsResponse,
    EdgeTestCredentialsResponse,
    type EdgeProviderAccountAdmin,
    type EdgeProviderId,
  } from '../../../shared/contracts/edges';
  import { formatDateTime } from '../../lib/i18n/format';
  import {
    EDGE_PROVIDER_META,
    addressLine,
    layerLabel,
    providerLabel,
  } from '../../lib/edgeProviderMeta';
  import AdminListState from './AdminListState.svelte';

  /**
   * Provider accounts. The form asks only for what an adapter cannot discover:
   * credentials (write-only, keep-on-blank) and the public identifiers a
   * provider's API keys need on the request. "Connect" then lists what the
   * account can see (projects, regions or zones, private networks) so the rest
   * is a pick, not a paste. Everything still stores as the adapter's settings
   * shape; the raw JSON stays available under "Advanced".
   *
   * An L7 account (a CDN front) differs in two ways only: its edges are named
   * by hostname, and one of its settings may point at another account (the DNS
   * account whose zone holds the hostname's records).
   */
  const providers = adminEdgeProvidersQuery();
  const templates = adminEdgeTemplatesQuery();
  const qc = useQueryClient();
  const invalidate = () => void qc.invalidateQueries({ queryKey: ['admin', 'edges'] });
  const onError = (title: string) => (err: unknown) =>
    toast.error(title, { description: apiErrorMessage(err) });

  /**
   * What each provider's settings hold and where the value comes from.
   *  - `select`: from the discovery lists (projects / regions / networks / subnets);
   *  - `text`: an identifier the operator types (public, non-secret);
   *  - `advanced` fields stay collapsed and optional.
   */
  type Field = {
    key: string;
    label: string;
    kind: 'text' | 'number' | 'select';
    from?:
      | 'projects'
      | 'regions'
      | 'networks'
      | 'subnets'
      | 'zones'
      | 'tlsConfigurations'
      | 'dnsAccounts'
      | 'fixed';
    options?: Array<{ id: string; label: string }>;
    required: boolean;
    advanced?: boolean;
    help?: string;
    /** Store as a number (Gcore ids). */
    numeric?: boolean;
    /** Derived from another field (the zone's name); shown, never typed. */
    readOnly?: boolean;
  };
  const FIELDS: Record<EdgeProviderId, Field[]> = {
    gcore: [
      {
        key: 'projectId',
        label: 'Project',
        kind: 'select',
        from: 'projects',
        required: true,
        numeric: true,
      },
      {
        key: 'regionId',
        label: 'Region',
        kind: 'select',
        from: 'regions',
        required: true,
        numeric: true,
      },
      {
        key: 'networkId',
        label: 'Private network',
        kind: 'select',
        from: 'networks',
        required: false,
        advanced: true,
        help: 'Leave empty for a public VIP. Choose a network + subnet for the private-VIP + floating-IP mode.',
      },
      {
        key: 'subnetId',
        label: 'Subnet',
        kind: 'select',
        from: 'subnets',
        required: false,
        advanced: true,
      },
    ],
    upcloud: [{ key: 'zone', label: 'Zone', kind: 'select', from: 'regions', required: true }],
    scaleway: [
      {
        key: 'accessKey',
        label: 'Access key (public id)',
        kind: 'text',
        required: true,
        help: 'The SCW… id paired with the secret key. Not a secret.',
      },
      { key: 'zone', label: 'Zone', kind: 'select', from: 'regions', required: true },
      {
        key: 'projectId',
        label: 'Project id',
        kind: 'text',
        required: false,
        advanced: true,
        help: "Leave empty to use the API key's default project.",
      },
    ],
    ovh: [
      { key: 'applicationKey', label: 'Application key (public id)', kind: 'text', required: true },
      {
        key: 'endpoint',
        label: 'API endpoint',
        kind: 'select',
        from: 'fixed',
        options: [
          { id: 'ovh-eu', label: 'ovh-eu' },
          { id: 'ovh-ca', label: 'ovh-ca' },
          { id: 'ovh-us', label: 'ovh-us' },
        ],
        required: true,
      },
      {
        key: 'serviceName',
        label: 'Public Cloud project',
        kind: 'select',
        from: 'projects',
        required: true,
      },
      { key: 'regionName', label: 'Region', kind: 'select', from: 'regions', required: true },
      {
        key: 'networkId',
        label: 'Private network (the balancer’s VIP network)',
        kind: 'select',
        from: 'networks',
        required: true,
      },
      { key: 'subnetId', label: 'Subnet', kind: 'select', from: 'subnets', required: true },
      {
        key: 'gatewayId',
        label: 'Existing gateway id',
        kind: 'text',
        required: false,
        advanced: true,
        help: 'Leave empty to let each edge create its own gateway (template setting).',
      },
    ],
    cloudflare: [
      {
        key: 'zoneId',
        label: 'DNS zone',
        kind: 'select',
        from: 'zones',
        required: true,
        help: 'Every edge of this account mints one hostname directly under the zone apex.',
      },
      {
        key: 'zoneName',
        label: 'Zone name',
        kind: 'text',
        required: false,
        readOnly: true,
        help: 'Filled from the chosen zone.',
      },
      {
        key: 'accountId',
        label: 'Account id',
        kind: 'text',
        required: false,
        advanced: true,
        help: 'Only needed when the token can see several accounts. Not a secret.',
      },
    ],
    fastly: [
      {
        key: 'dnsAccountId',
        label: 'DNS account',
        kind: 'select',
        from: 'dnsAccounts',
        required: true,
        help: 'The account whose zone holds the hostname records and the certificate challenges. Add it first.',
      },
      {
        key: 'certificateAuthority',
        label: 'Certificate authority',
        kind: 'select',
        from: 'fixed',
        options: [
          { id: 'certainly', label: 'certainly (default)' },
          { id: 'lets-encrypt', label: 'lets-encrypt' },
          { id: 'globalsign', label: 'globalsign (paid plans only)' },
        ],
        required: true,
      },
      {
        key: 'tlsConfigurationId',
        label: 'TLS configuration',
        kind: 'select',
        from: 'tlsConfigurations',
        required: false,
        advanced: true,
        help: "Leave empty to use the account's default configuration.",
      },
    ],
  };
  /** Which credential fields must be filled before "Connect" can list anything. */
  const NEEDS_FOR_DISCOVERY: Record<EdgeProviderId, string[]> = {
    gcore: [],
    upcloud: [],
    scaleway: ['accessKey'],
    ovh: ['applicationKey', 'endpoint'],
    cloudflare: [],
    fastly: [],
  };
  /** What each provider's API token must be allowed to do, shown above the field. */
  const CREDENTIAL_HELP: Partial<Record<EdgeProviderId, string>> = {
    cloudflare:
      'A zone-scoped API token with Zone DNS Edit, Zone Read, Zone Settings Read, SSL and Certificates Read, plus Origin Rules Edit when an edge needs an origin port other than the zone default.',
    fastly:
      'An API token with the global scope, issued on a dedicated automation user. The account also needs the WebSockets product entitlement.',
  };

  type Draft = {
    id: string | null;
    provider: EdgeProviderId;
    name: string;
    settings: Record<string, string>;
    credentials: Record<string, string>;
    enabled: boolean;
    priority: number;
    dailyAllocationBudget: number;
    maxLiveEdges: number;
    defaultTemplateId: string;
    showAdvanced: boolean;
    rawJson: string | null;
  };
  let editor = $state<Draft | null>(null);
  let discovered = $state<EdgeDiscoverResponse | null>(null);

  /** The few settings that have a sensible value before the operator picks anything. */
  const defaultSettings = (): Record<string, string> => ({
    endpoint: 'ovh-eu',
    certificateAuthority: 'certainly',
  });

  function newDraft(): Draft {
    return {
      id: null,
      provider: 'gcore',
      name: '',
      settings: defaultSettings(),
      credentials: {},
      enabled: true,
      priority: 10,
      dailyAllocationBudget: 6,
      maxLiveEdges: 4,
      defaultTemplateId: '',
      showAdvanced: false,
      rawJson: null,
    };
  }
  function editDraft(a: EdgeProviderAccountAdmin): Draft {
    const settings: Record<string, string> = {};
    for (const [k, v] of Object.entries(a.settings as Record<string, unknown>))
      if (k !== 'type' && v !== undefined && v !== null) settings[k] = String(v);
    return {
      id: a.id,
      provider: a.provider,
      name: a.name,
      settings,
      credentials: {},
      enabled: a.enabled,
      priority: a.priority,
      dailyAllocationBudget: a.dailyAllocationBudget,
      maxLiveEdges: a.maxLiveEdges,
      defaultTemplateId: a.defaultTemplateId ?? '',
      showAdvanced: false,
      rawJson: null,
    };
  }
  const credentialFields = $derived(providers.data?.credentialFields ?? {});
  const fields = $derived(editor ? FIELDS[editor.provider] : []);

  /**
   * Options for one select field. Most come from the discovery result (subnets
   * follow the chosen network); the DNS account list is the accounts already on
   * this page, narrowed to the providers that host DNS.
   */
  function optionsFor(f: Field): Array<{ id: string; label: string }> {
    if (f.from === 'fixed') return f.options ?? [];
    if (f.from === 'dnsAccounts')
      return (providers.data?.accounts ?? [])
        .filter((a) => EDGE_PROVIDER_META[a.provider].providesDns && a.id !== editor?.id)
        .map((a) => ({ id: a.id, label: a.name }));
    if (!discovered) return [];
    if (f.from === 'projects') return discovered.projects ?? [];
    if (f.from === 'regions') return discovered.regions ?? [];
    if (f.from === 'zones') return discovered.zones ?? [];
    if (f.from === 'tlsConfigurations') return discovered.tlsConfigurations ?? [];
    if (f.from === 'networks')
      return (discovered.networks ?? []).map((n) => ({ id: n.id, label: n.label }));
    if (f.from === 'subnets') {
      const net = (discovered.networks ?? []).find((n) => n.id === editor?.settings.networkId);
      return net?.subnets ?? [];
    }
    return [];
  }
  /**
   * Picking a zone also fixes its name: the adapter needs both (the id for every
   * API call, the name to mint `<label>.<zone>`), and typing the name by hand is
   * one more way to mint a hostname in the wrong zone.
   */
  function onSettingChange(f: Field, value: string) {
    if (!editor) return;
    editor.settings[f.key] = value;
    if (f.from === 'zones')
      editor.settings.zoneName = optionsFor(f).find((o) => o.id === value)?.label ?? '';
    // A new network invalidates the subnet choice; a new project/region, the lists below it.
    if (f.from === 'networks') editor.settings.subnetId = '';
    if (f.from === 'projects' || f.from === 'regions') discover.mutate();
  }
  const canDiscover = $derived.by(() => {
    if (!editor) return false;
    const creds = credentialFields[editor.provider] ?? [];
    const haveCreds = editor.id
      ? true
      : creds.every((c) => (editor!.credentials[c] ?? '').trim() !== '');
    const haveIds = NEEDS_FOR_DISCOVERY[editor.provider].every(
      (k) => (editor!.settings[k] ?? '').trim() !== '',
    );
    return haveCreds && haveIds;
  });

  /** Build the settings object the server validates (numbers where the adapter wants them). */
  function settingsBody(d: Draft): Record<string, unknown> {
    if (d.rawJson !== null) {
      try {
        return JSON.parse(d.rawJson) as Record<string, unknown>;
      } catch {
        throw new Error('Advanced JSON must be valid');
      }
    }
    const out: Record<string, unknown> = {};
    for (const f of FIELDS[d.provider]) {
      const raw = (d.settings[f.key] ?? '').trim();
      if (!raw) continue;
      out[f.key] = f.numeric ? Number(raw) : raw;
    }
    return out;
  }

  const discover = createMutation(() => ({
    mutationFn: () => {
      const d = editor!;
      const creds = Object.fromEntries(
        Object.entries(d.credentials).filter(([, v]) => v.trim() !== ''),
      );
      return apiClient.post(
        '/api/v1/admin/edges/providers/discover',
        {
          provider: d.provider,
          credentials: creds,
          settings: settingsBody(d),
          ...(d.id ? { accountId: d.id } : {}),
        },
        EdgeDiscoverResponse,
      );
    },
    onSuccess: (r) => {
      discovered = r;
      if (!editor) return;
      // Pre-select when there is exactly one choice.
      for (const f of fields) {
        if (f.kind !== 'select' || f.from === 'fixed' || editor.settings[f.key]) continue;
        const opts = optionsFor(f);
        if (opts.length === 1 && opts[0]) {
          editor.settings[f.key] = opts[0].id;
          if (f.from === 'zones') editor.settings.zoneName = opts[0].label;
        }
      }
      const failed = Object.entries(r.errors ?? {}).map(([k, code]) => `${k} (${code})`);
      if (failed.length)
        toast.warning(`Could not list: ${failed.join(', ')}. Type the id instead.`);
      else toast.success('Connected');
    },
    onError: onError('Could not connect'),
  }));

  const save = createMutation(() => ({
    mutationFn: async () => {
      const d = editor!;
      const settings = settingsBody(d);
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
        return apiClient.patch(`/api/v1/admin/edges/providers/${d.id}`, body, EdgeOkResponse);
      return apiClient.post(
        '/api/v1/admin/edges/providers',
        { ...body, provider: d.provider, name: d.name.trim(), credentials: creds },
        EdgeIdResponse,
      );
    },
    onSuccess: () => {
      editor = null;
      discovered = null;
      invalidate();
      toast.success('Account saved');
    },
    onError: onError('Could not save the account'),
  }));
  /** Whether the editor holds a typed (non-blank) credential to rotate to. */
  const hasNewCredentials = $derived(
    !!editor?.id && Object.values(editor.credentials).some((v) => v.trim() !== ''),
  );
  /**
   * Rotate the secret WITHOUT losing the qualification (a plain Save with new
   * credentials clears it). The server tests the new secret first and applies
   * it only on a pass; it picks the credential-identifier fields (an access /
   * application key) out of the settings and ignores everything else.
   */
  const rotateCredentials = createMutation(() => ({
    mutationFn: () => {
      const d = editor!;
      const creds = Object.fromEntries(
        Object.entries(d.credentials).filter(([, v]) => v.trim() !== ''),
      );
      return apiClient.post(
        `/api/v1/admin/edges/providers/${d.id}/rotate-credentials`,
        { credentials: creds, identifiers: settingsBody(d) },
        EdgeRotateCredentialsResponse,
      );
    },
    onSuccess: (r) => {
      if (!r.ok) {
        toast.error('New credentials rejected; nothing changed', { description: r.code });
        return;
      }
      editor = null;
      discovered = null;
      invalidate();
      toast.success(
        r.qualified ? 'Credentials rotated (qualification kept)' : 'Credentials rotated',
      );
    },
    onError: onError('Could not rotate the credentials'),
  }));
  const remove = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/edges/providers/${id}`, EdgeOkResponse),
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
        '/api/v1/admin/edges/providers/test-credentials',
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
      apiClient.post(`/api/v1/admin/edges/providers/${id}/qualify`, { qualified }, EdgeOkResponse),
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
        `/api/v1/admin/edges/providers/${id}/inventory/refresh`,
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
              `${l.name} · ${l.status ?? '-'} · ${addressLine(l.addresses)}${
                l.content ? ` → ${l.content}` : ''
              }${l.unowned ? ' · UNOWNED' : ''}`,
          ),
        },
      };
      invalidate();
    },
    onError: onError('Could not pull the inventory'),
  }));

  /** Human summary of an account's settings for the card (labels from FIELDS). */
  function settingsSummary(a: EdgeProviderAccountAdmin): string {
    const s = a.settings as Record<string, unknown>;
    return FIELDS[a.provider]
      .filter((f) => s[f.key] !== undefined && s[f.key] !== null && s[f.key] !== '')
      .map((f) => {
        const raw = String(s[f.key]);
        // A referenced account reads as its name, not as a row id.
        const shown =
          f.from === 'dnsAccounts'
            ? ((providers.data?.accounts ?? []).find((x) => x.id === raw)?.name ?? raw)
            : raw;
        return `${f.label.replace(/ \(.*\)$/, '')}: ${shown}`;
      })
      .join(' · ');
  }
  function openEditor(d: Draft) {
    discovered = null;
    editor = d;
  }
</script>

<div class="space-y-4">
  <div class="flex justify-end">
    <Button onclick={() => openEditor(newDraft())}>New account</Button>
  </div>
  {#if providers.isError}<AdminListState
      error={providers.error}
      onRetry={() => void providers.refetch()}
    />{/if}
  {#if providers.data && providers.data.accounts.length === 0}
    <AdminListState
      emptyText="No provider accounts. Add one, connect it to list its projects, regions or DNS zones, test the credentials, then qualify it after a manual check through a test edge."
    />
  {/if}
  {#each providers.data?.accounts ?? [] as a (a.id)}
    <Card>
      <CardHeader class="pb-2">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle class="flex items-center gap-2 text-base">
              <span>{a.name}</span>
              <span class="rounded-full border px-2 py-0.5 text-xs"
                >{providerLabel(a.provider)}</span
              >
              <span
                class="rounded-full border px-2 py-0.5 text-xs"
                title={EDGE_PROVIDER_META[a.provider].layer === 'l7'
                  ? 'An L7 front: edges are hostnames fronted by the CDN'
                  : 'An L4 forwarder: edges are IP literals in front of the node'}
                >{layerLabel(EDGE_PROVIDER_META[a.provider].layer)}</span
              >
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
            <Button size="sm" variant="ghost" onclick={() => openEditor(editDraft(a))}>Edit</Button>
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
        <div class="text-muted-foreground">{settingsSummary(a) || 'no settings'}</div>
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

<Dialog.Root
  open={editor !== null}
  onOpenChange={(v) => {
    if (!v) {
      editor = null;
      discovered = null;
    }
  }}
>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
    <Dialog.Header>
      <Dialog.Title>{editor?.id ? 'Edit account' : 'New provider account'}</Dialog.Title>
      <Dialog.Description
        >Enter the credentials, connect to list what the account can see, then pick. Credentials are
        write-only: blank fields keep the stored value. Changing credentials or settings clears the
        qualification.</Dialog.Description
      >
    </Dialog.Header>
    {#if editor}
      <div class="grid gap-3">
        {#if !editor.id}
          <div class="grid gap-3 sm:grid-cols-2">
            <label class="text-xs"
              >Provider
              <Select.Root
                type="single"
                value={editor.provider}
                onValueChange={(v) => {
                  editor!.provider = v as EdgeProviderId;
                  editor!.settings = defaultSettings();
                  editor!.rawJson = null;
                  discovered = null;
                }}
              >
                <Select.Trigger class="mt-1 w-full"
                  >{providerLabel(editor.provider)} ({layerLabel(
                    EDGE_PROVIDER_META[editor.provider].layer,
                  )})</Select.Trigger
                >
                <Select.Content
                  >{#each EDGE_PROVIDER_IDS as p (p)}<Select.Item value={p}
                      >{providerLabel(p)} · {layerLabel(EDGE_PROVIDER_META[p].layer)}</Select.Item
                    >{/each}</Select.Content
                >
              </Select.Root>
            </label>
            <label class="text-xs"
              >Name<Input class="mt-1" bind:value={editor.name} placeholder="account-a" /></label
            >
          </div>
        {/if}

        <!-- 1. credentials + the public ids the API needs on every call -->
        <div class="rounded-md border p-3">
          <p class="mb-2 text-xs font-semibold">1. Credentials</p>
          {#if CREDENTIAL_HELP[editor.provider]}
            <p class="mb-2 text-[11px] text-muted-foreground">{CREDENTIAL_HELP[editor.provider]}</p>
          {/if}
          <div class="grid gap-3 sm:grid-cols-2">
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
            {#each fields.filter((f) => f.kind !== 'select' && !f.advanced && !f.readOnly) as f (f.key)}
              <label class="text-xs"
                >{f.label}<Input class="mt-1 font-mono" bind:value={editor.settings[f.key]} />
                {#if f.help}<span class="block text-[11px] text-muted-foreground">{f.help}</span
                  >{/if}</label
              >
            {/each}
            {#each fields.filter((f) => f.from === 'fixed') as f (f.key)}
              <label class="text-xs"
                >{f.label}
                <Select.Root
                  type="single"
                  value={editor.settings[f.key] ?? ''}
                  onValueChange={(v) => (editor!.settings[f.key] = v)}
                >
                  <Select.Trigger class="mt-1 w-full"
                    >{f.options?.find((o) => o.id === editor?.settings[f.key])?.label ??
                      'Select'}</Select.Trigger
                  >
                  <Select.Content
                    >{#each f.options ?? [] as o (o.id)}<Select.Item value={o.id}
                        >{o.label}</Select.Item
                      >{/each}</Select.Content
                  >
                </Select.Root>
              </label>
            {/each}
          </div>
          <div class="mt-3 flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={!canDiscover || discover.isPending}
              onclick={() => discover.mutate()}
              >{discover.isPending
                ? 'Connecting…'
                : discovered
                  ? 'Refresh lists'
                  : 'Connect and list options'}</Button
            >
            {#if !canDiscover}
              <span class="text-[11px] text-muted-foreground"
                >Fill the credentials{NEEDS_FOR_DISCOVERY[editor.provider].length
                  ? ' and the public ids'
                  : ''} first.</span
              >
            {/if}
          </div>
        </div>

        <!-- 2. the choices -->
        <div class="rounded-md border p-3">
          <p class="mb-2 text-xs font-semibold">2. Where the edges go</p>
          <div class="grid gap-3 sm:grid-cols-2">
            {#each fields.filter((f) => f.kind === 'select' && f.from !== 'fixed' && (!f.advanced || editor!.showAdvanced)) as f (f.key)}
              {@const opts = optionsFor(f)}
              {@const err = discovered?.errors?.[f.from ?? '']}
              <label class="text-xs"
                >{f.label}{f.required ? '' : ' (optional)'}
                {#if opts.length > 0 && !err}
                  <Select.Root
                    type="single"
                    value={editor.settings[f.key] ?? ''}
                    onValueChange={(v) => onSettingChange(f, v)}
                  >
                    <Select.Trigger class="mt-1 w-full"
                      >{opts.find((o) => o.id === editor?.settings[f.key])?.label ??
                        (editor.settings[f.key]
                          ? editor.settings[f.key]
                          : 'Select')}</Select.Trigger
                    >
                    <Select.Content
                      >{#each opts as o (o.id)}<Select.Item value={o.id}>{o.label}</Select.Item
                        >{/each}</Select.Content
                    >
                  </Select.Root>
                {:else if f.from === 'dnsAccounts'}
                  <p class="mt-1 rounded-md border border-dashed px-2 py-1.5 text-[11px]">
                    No account that can host DNS yet. Add a Cloudflare account for the zone first,
                    then come back here.
                  </p>
                {:else}
                  <Input
                    class="mt-1 font-mono"
                    bind:value={editor.settings[f.key]}
                    placeholder={discovered
                      ? err
                        ? `could not list (${err}); type the id`
                        : 'nothing listed yet; type the id'
                      : 'connect to list, or type the id'}
                  />
                {/if}
                {#if f.help}<span class="block text-[11px] text-muted-foreground">{f.help}</span
                  >{/if}</label
              >
            {/each}
            {#each fields.filter((f) => f.readOnly) as f (f.key)}
              <label class="text-xs"
                >{f.label}
                <Input class="mt-1 font-mono" readonly value={editor.settings[f.key] ?? ''} />
                {#if f.help}<span class="block text-[11px] text-muted-foreground">{f.help}</span
                  >{/if}</label
              >
            {/each}
          </div>
          {#if fields.some((f) => f.advanced)}
            <button
              type="button"
              class="mt-2 text-[11px] underline"
              onclick={() => (editor!.showAdvanced = !editor!.showAdvanced)}
              >{editor.showAdvanced ? 'Hide advanced' : 'Show advanced'}</button
            >
          {/if}
          {#if editor.showAdvanced}
            {#each fields.filter((f) => f.advanced && f.kind !== 'select') as f (f.key)}
              <label class="mt-2 block text-xs"
                >{f.label} (optional)<Input
                  class="mt-1 font-mono"
                  bind:value={editor.settings[f.key]}
                />
                {#if f.help}<span class="block text-[11px] text-muted-foreground">{f.help}</span
                  >{/if}</label
              >
            {/each}
            <label class="mt-2 block text-xs"
              >Raw settings JSON (overrides the fields above when set)
              <textarea
                class="mt-1 w-full rounded-md border bg-background p-2 font-mono text-xs"
                rows="3"
                value={editor.rawJson ?? ''}
                oninput={(e) => (editor!.rawJson = e.currentTarget.value.trim() || null)}
              ></textarea>
            </label>
          {/if}
        </div>

        <!-- 3. limits -->
        <div class="grid gap-3 sm:grid-cols-3">
          <label class="text-xs"
            >Priority (lower first)<Input
              class="mt-1"
              type="number"
              bind:value={editor.priority}
            /></label
          >
          <label class="text-xs"
            >Daily allocation budget (0 = unlimited)<Input
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
                "Provider's default template"}</Select.Trigger
            >
            <Select.Content>
              {#each (templates.data?.templates ?? []).filter((t) => t.provider === editor?.provider && (!t.accountId || t.accountId === editor?.id)) as t (t.id)}
                <Select.Item value={t.id}>{t.name}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        </label>
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox bind:checked={editor.enabled} /> Enabled</label
        >
      </div>
    {/if}
    <Dialog.Footer>
      <Button
        variant="outline"
        onclick={() => {
          editor = null;
          discovered = null;
        }}>Cancel</Button
      >
      {#if editor?.id}
        <Button
          variant="secondary"
          disabled={!hasNewCredentials || rotateCredentials.isPending || save.isPending}
          title="Test the typed secret against the provider and swap it in, keeping the qualification"
          onclick={() => rotateCredentials.mutate()}>Rotate credentials</Button
        >
      {/if}
      <Button disabled={save.isPending || rotateCredentials.isPending} onclick={() => save.mutate()}
        >Save</Button
      >
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
