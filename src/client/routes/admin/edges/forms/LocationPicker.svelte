<script lang="ts">
  /**
   * Add a location to a stored account: where its edges are created (region or
   * zone, the project, the private network where the provider needs one), and
   * the load balancer flavor of that region when the template's own is not
   * offered there. The lists come live from the provider with the account's
   * stored credentials (`POST providers/{id}/locations/options`); the server
   * checks the region is offered to this key before it saves the location, and
   * the same place twice is the same location.
   *
   * A CDN account's location is a DNS zone: one of the zones its token reaches
   * (a front that writes its records elsewhere: a DNS account, one of that
   * account's zones, and optionally a TLS configuration). Those lists come from
   * the accounts' catalogs (what each reaches, as last listed; listed again when
   * old or on Refresh), and the server checks the zone with the provider before
   * it saves the location.
   *
   * Started from a region the key reaches (`region`, the "Change options" of a
   * region picked when a node is protected), the form opens with that region
   * and what the server would complete it with (`locationOptions` with
   * `defaults`: the project, OVH's network and subnet), every value changeable.
   *
   * Props:
   *   accountId: string
   *   provider: EdgeProviderId
   *   onCreated: (locationId: string) => void
   *   onCancel?: () => void
   *   nodeCountry?: string | null    the node's country, for the region hint
   *   region?: string | null         start from this region, its defaults filled in
   */
  import { untrack } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import type { EdgeDiscoverResponse, EdgeProviderId } from '@shared/contracts/edges';
  import {
    createProviderLocation,
    edgeKeys,
    invalidateProviders,
    locationOptions,
    providerCatalogQuery,
    providersQuery,
    refreshProviderCatalog,
    templatesQuery,
  } from '@client/lib/edgesApi';
  import { EDGE_PROVIDER_META } from '@client/lib/edgeProviderMeta';
  import CodeNote from '../components/CodeNote.svelte';
  import ProviderAnswer from '../components/ProviderAnswer.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import {
    locationFields,
    missingRequired,
    optionsFor,
    placementBody,
    regionPlacement,
    type ProviderField,
  } from './providerFields';
  import { catalogStale, zoneChoices } from './zones';

  interface Props {
    accountId: string;
    provider: EdgeProviderId;
    onCreated: (locationId: string) => void;
    onCancel?: () => void;
    nodeCountry?: string | null;
    region?: string | null;
  }
  let {
    accountId,
    provider,
    onCreated,
    onCancel,
    nodeCountry = null,
    region = null,
  }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const templates = templatesQuery();
  const providers = providersQuery();

  let values = $state<Record<string, string>>({});
  let discovered = $state<EdgeDiscoverResponse | null>(null);
  let regional = $state<Record<string, string>>({});
  let costNote = $state('');
  let tried = $state(false);

  const meta = $derived(EDGE_PROVIDER_META[provider]);
  /** A CDN's place is a DNS zone, picked from the accounts' catalogs. */
  const cdn = $derived(meta.layer === 'l7');
  const fields = $derived(locationFields(provider).filter((f) => !f.readOnly));
  const accounts = $derived(providers.data?.accounts ?? []);
  const account = $derived(accounts.find((a) => a.id === accountId) ?? null);
  const catalog = providerCatalogQuery(() => (cdn ? accountId : null));
  const dnsAccountId = $derived(meta.needsDnsAccount ? (values['dnsAccountId'] ?? '') : '');
  const dnsCatalog = providerCatalogQuery(() => dnsAccountId || null);
  /** "example.org", or "example.org (not active)" for a zone the provider lists as not active. */
  const zoneOptions = (list: ReturnType<typeof zoneChoices>) =>
    list.map((z) => ({
      id: z.id,
      label: z.status && z.status !== 'active' ? `${z.name} (not active)` : z.name,
    }));
  const ownZones = $derived(zoneChoices(catalog.data, account?.locations ?? []));
  const dnsZoneList = $derived(
    zoneChoices(dnsCatalog.data, accounts.find((a) => a.id === dnsAccountId)?.locations ?? []),
  );
  /** For a CDN the lists are the catalogs' (zones, TLS configurations), never a live listing. */
  const cdnDiscovered = $derived<EdgeDiscoverResponse>({
    ...(meta.providesDns ? { zones: zoneOptions(ownZones) } : {}),
    ...(catalog.data?.kinds.tlsConfigurations
      ? { tlsConfigurations: catalog.data.kinds.tlsConfigurations.items }
      : {}),
  });
  const ctx = $derived({
    discovered: cdn ? cdnDiscovered : discovered,
    accounts,
    values,
    dnsZones: zoneOptions(dnsZoneList),
  });
  /** The catalog errors worth saying (a listing that failed keeps its last items). */
  const catalogErrors = $derived(
    [
      ...Object.entries(catalog.data?.kinds ?? {}),
      ...Object.entries(dnsCatalog.data?.kinds ?? {}).filter(([k]) => k === 'zones'),
    ].flatMap(([kind, e]) => (e?.error ? [{ kind, code: e.error, detail: e.errorDetail }] : [])),
  );
  const refresh = createMutation(() => ({
    mutationFn: async (ids: string[]) => {
      for (const id of ids) await refreshProviderCatalog(id);
    },
    onSuccess: (_r, ids) => {
      for (const id of ids) void qc.invalidateQueries({ queryKey: edgeKeys.providerCatalog(id) });
    },
  }));
  const refreshIds = $derived([accountId, ...(dnsAccountId ? [dnsAccountId] : [])]);
  // A catalog never listed, or older than the server says, is listed again once.
  const autoRefreshed = new Set<string>();
  $effect(() => {
    if (!cdn) return;
    for (const [id, data] of [
      [accountId, catalog.data],
      [dnsAccountId, dnsCatalog.data],
    ] as const) {
      if (!id || !data || autoRefreshed.has(id) || !catalogStale(data)) continue;
      autoRefreshed.add(id);
      untrack(() => refresh.mutate([id]));
    }
  });
  const missing = $derived(
    missingRequired(provider, values).filter((l) => fields.some((f) => f.label === l)),
  );

  /**
   * The template fields whose value differs per region, with the value the template carries now.
   * The template is the one the server would use for a new location: the account's chosen one,
   * then the account-scoped default, then the provider default (`resolveTemplateFor`).
   */
  const regionalFields = $derived.by(() => {
    const schema = templates.data?.schemas[provider];
    const list = (templates.data?.templates ?? []).filter(
      (t) => t.provider === provider && (t.accountId === null || t.accountId === accountId),
    );
    const chosenId = providers.data?.accounts.find((a) => a.id === accountId)?.defaultTemplateId;
    const tpl =
      (chosenId ? list.find((t) => t.id === chosenId) : undefined) ??
      list.find((t) => t.isDefault && t.accountId === accountId) ??
      list.find((t) => t.isDefault && t.accountId === null);
    const params = (tpl?.params ?? schema?.defaults ?? {}) as Record<string, unknown>;
    return (schema?.fields ?? [])
      .filter((f) => f.regional)
      .map((f) => ({ key: f.key, label: f.label, templateValue: String(params[f.key] ?? '') }));
  });
  /** A regional value the template leaves empty must be chosen here. */
  const regionalMissing = $derived(
    regionalFields.filter((f) => !f.templateValue && !(regional[f.key] ?? '').trim()),
  );

  const load = createMutation(() => ({
    mutationFn: (v: { placement: Record<string, unknown>; defaults?: boolean }) =>
      locationOptions(accountId, v.placement, { defaults: v.defaults }),
    onSuccess: (r) => {
      discovered = r;
      // A region's defaults (asked once, at the start) fill what is still empty.
      const next = { ...values };
      for (const [k, v] of Object.entries(r.defaults ?? {}))
        if (!next[k] && v !== undefined && v !== null && v !== '') next[k] = String(v);
      // Pre-select a list with one choice; drop a choice the new lists no longer offer.
      for (const f of fields) {
        if (f.kind !== 'select') continue;
        const opts = optionsFor(f, { discovered: r, accounts: [], values: next });
        const current = next[f.key] ?? '';
        if (current && opts.length > 0 && !opts.some((o) => o.id === current)) next[f.key] = '';
        if (!next[f.key] && opts.length === 1 && opts[0]) next[f.key] = opts[0].id;
      }
      values = next;
    },
  }));
  untrack(() => {
    if (cdn) return;
    const start = region ? regionPlacement(provider, region) : null;
    load.mutate(start ? { placement: start, defaults: true } : { placement: {} });
  });

  function onFieldChange(f: ProviderField, value: string) {
    const next = { ...values, [f.key]: value };
    if (f.from === 'networks') next['subnetId'] = '';
    if (f.from === 'zones' || f.from === 'dnsZones')
      next['zoneName'] =
        (f.from === 'zones' ? ownZones : dnsZoneList).find((z) => z.id === value)?.name ?? '';
    if (f.from === 'dnsAccounts') {
      next['zoneId'] = '';
      next['zoneName'] = '';
    }
    values = next;
    // The networks, subnets and flavors of a region depend on the project and the region.
    if (f.from === 'projects' || f.from === 'regions')
      load.mutate({ placement: placementBody(provider, values) });
  }

  const create = createMutation(() => ({
    mutationFn: () =>
      createProviderLocation(accountId, {
        placement: placementBody(provider, values),
        ...(Object.keys(cleanRegional()).length > 0 ? { regionalParams: cleanRegional() } : {}),
        ...(costNote.trim() ? { costNote: costNote.trim() } : {}),
      }),
    onSuccess: (r) => {
      invalidateProviders(qc);
      toast.success(r.created ? 'Location added' : 'This location already exists');
      onCreated(r.id);
    },
  }));
  function cleanRegional(): Record<string, string> {
    return Object.fromEntries(
      Object.entries(regional)
        .map(([k, v]) => [k, v.trim()] as const)
        .filter(([, v]) => v !== ''),
    );
  }
  const issue = $derived(create.error ? edgeErrorIssue(create.error) : null);
  const cdnHint = $derived(
    meta.needsDnsAccount
      ? "The front's names and their certificate challenges are written into this zone of the DNS account."
      : 'Every name FCP writes sits directly under the zone apex.',
  );
  const regionHint = $derived(
    nodeCountry
      ? `The node is in ${nodeCountry}. Pick a region close to it: members reach the address, which forwards to the node.`
      : 'Pick a region close to the node: members reach the address, which forwards to the node.',
  );
</script>

{#snippet fieldInput(f: ProviderField)}
  {@const opts = optionsFor(f, ctx)}
  {@const current = values[f.key] ?? ''}
  <div class="space-y-1.5">
    <Label for={`${uid}-${f.key}`}>{f.label}{f.required ? '' : ' (optional)'}</Label>
    {#if f.kind === 'select' && opts.length > 0}
      <Select.Root
        type="single"
        value={current}
        onValueChange={(v: string) => onFieldChange(f, v === '__none' ? '' : v)}
        disabled={create.isPending}
      >
        <Select.Trigger id={`${uid}-${f.key}`} class="w-full">
          {opts.find((o) => o.id === current)?.label ?? (current || 'Choose one')}
        </Select.Trigger>
        <Select.Content>
          {#if !f.required}
            <Select.Item value="__none" label="None">None</Select.Item>
          {/if}
          {#each opts as o (o.id)}
            <Select.Item value={o.id} label={o.label}>{o.label}</Select.Item>
          {/each}
        </Select.Content>
      </Select.Root>
    {:else}
      <Input
        id={`${uid}-${f.key}`}
        class="font-mono"
        value={current}
        placeholder={f.placeholder}
        disabled={create.isPending}
        oninput={(e) => onFieldChange(f, e.currentTarget.value)}
      />
      {#if f.from === 'dnsZones' && !dnsAccountId}
        <p class="text-muted-foreground text-xs">Choose the DNS account first.</p>
      {:else if f.kind === 'select' && f.from !== 'subnets' && !load.isPending}
        <p class="text-muted-foreground text-xs">
          {cdn
            ? 'No list is stored for this yet: refresh it, or type the id.'
            : 'The provider returned no list for this, so type the id.'}
        </p>
      {/if}
    {/if}
    {#if f.help}<p class="text-muted-foreground text-xs">{f.help}</p>{/if}
    {#if f.from === 'regions'}<p class="text-muted-foreground text-xs">{regionHint}</p>{/if}
    {#if f.from === 'zones' || f.from === 'dnsZones'}
      <p class="text-muted-foreground text-xs">{cdnHint}</p>
    {/if}
  </div>
{/snippet}

<div class="space-y-4">
  <div aria-live="polite">
    {#if cdn}
      <div class="flex flex-wrap items-center gap-2">
        <p class="text-muted-foreground text-sm" role="status">
          {refresh.isPending
            ? 'Asking the provider which zones these credentials reach.'
            : 'Zones and configurations as these credentials reach them.'}
        </p>
        <Button
          variant="ghost"
          size="sm"
          class="h-11 sm:h-7"
          disabled={refresh.isPending}
          onclick={() => refresh.mutate(refreshIds)}
        >
          Refresh the lists
        </Button>
      </div>
      {#each catalogErrors as e (e.kind)}
        <CodeNote
          tone="warning"
          issue={{ code: e.code, subject: e.kind, detail: 'This list could not be read again.' }}
        />
        <ProviderAnswer detail={e.detail ?? undefined} />
      {/each}
      {#if refresh.isError}<InlineError message={edgeErrorMessage(refresh.error)} />{/if}
    {:else if load.isPending && !discovered}
      <p class="text-muted-foreground text-sm" role="status">
        Asking the provider where this account can create addresses.
      </p>
    {:else if load.isError}
      {@const e = edgeErrorIssue(load.error)}
      {#if e}<CodeNote issue={e} />{:else}<InlineError
          message={edgeErrorMessage(load.error)}
        />{/if}
    {/if}
    {#each Object.entries(discovered?.errors ?? {}) as [list, code] (list)}
      <CodeNote
        tone="warning"
        issue={{ code, subject: list, detail: 'This list could not be read. Type the id instead.' }}
      />
      <ProviderAnswer detail={discovered?.errorDetails?.[list]} />
    {/each}
  </div>
  <div class="grid gap-4 sm:grid-cols-2">
    {#each fields as f (f.key)}
      {@render fieldInput(f)}
    {/each}
    {#each regionalFields as rf (rf.key)}
      {@const flavors = discovered?.flavors ?? []}
      {@const current = regional[rf.key] ?? ''}
      <div class="space-y-1.5">
        <Label for={`${uid}-r-${rf.key}`}>{rf.label} in this region</Label>
        {#if flavors.length > 0}
          <Select.Root
            type="single"
            value={current}
            onValueChange={(v: string) =>
              (regional = { ...regional, [rf.key]: v === '__tpl' ? '' : v })}
            disabled={create.isPending}
          >
            <Select.Trigger id={`${uid}-r-${rf.key}`} class="w-full">
              {current
                ? (flavors.find((o) => o.id === current)?.label ?? current)
                : rf.templateValue
                  ? `The template's (${rf.templateValue})`
                  : 'Choose one'}
            </Select.Trigger>
            <Select.Content>
              {#if rf.templateValue}
                <Select.Item value="__tpl" label="The template's">
                  The template's ({rf.templateValue})
                </Select.Item>
              {/if}
              {#each flavors as o (o.id)}
                <Select.Item value={o.id} label={o.label}>{o.label}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        {:else}
          <Input
            id={`${uid}-r-${rf.key}`}
            class="font-mono"
            value={current}
            placeholder={rf.templateValue || undefined}
            disabled={create.isPending}
            oninput={(e) => (regional = { ...regional, [rf.key]: e.currentTarget.value })}
          />
        {/if}
        <p class="text-muted-foreground text-xs">
          A flavor is offered per region. {rf.templateValue
            ? "Leave the template's when this region offers it."
            : 'The template names none, so choose the one to use here.'}
        </p>
      </div>
    {/each}
    <div class="space-y-1.5 sm:col-span-2">
      <Label for={`${uid}-cost`}>Cost note (optional)</Label>
      <Input
        id={`${uid}-cost`}
        bind:value={costNote}
        maxlength={120}
        placeholder="About 10 a month per address"
        disabled={create.isPending}
      />
      <p class="text-muted-foreground text-xs">
        Shown next to this location when it is picked. Only admins see it.
      </p>
    </div>
  </div>
  {#if tried && (missing.length > 0 || regionalMissing.length > 0)}
    <p class="text-destructive text-sm" role="alert">
      Still needed: {[...missing, ...regionalMissing.map((r) => r.label)].join(', ')}.
    </p>
  {/if}
  {#if issue}<CodeNote {issue} />{:else if create.error}<InlineError
      message={edgeErrorMessage(create.error)}
    />{/if}
  <div class="flex flex-wrap gap-2">
    <Button
      class="h-11 sm:h-8"
      disabled={create.isPending || (!cdn && load.isPending)}
      onclick={() => {
        tried = true;
        if (missing.length === 0 && regionalMissing.length === 0) create.mutate();
      }}
    >
      {create.isPending
        ? cdn
          ? 'Checking the zone and adding it'
          : 'Adding the location'
        : 'Add location'}
    </Button>
    {#if onCancel}
      <Button variant="outline" class="h-11 sm:h-8" onclick={onCancel}>Cancel</Button>
    {/if}
  </div>
</div>
