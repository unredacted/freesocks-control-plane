<script lang="ts">
  /**
   * Add a provider account in two steps:
   *   1. Credentials        provider, a name, the write-only secrets and the public identifiers
   *                         the provider needs on every request. Connect asks the provider
   *                         what the credentials can see (projects, regions or zones,
   *                         networks); nothing is stored yet, the lists stay in form state.
   *                         A refused connection stays on this step with the reason.
   *   2. Placement, limits  what the provider answered, the account's FIRST location (where
   *                         its edges are created, picked from those lists), the DNS
   *                         account for a provider that needs one, and the spending
   *                         limits. More locations are added on the account page or
   *                         when a node is protected (`LocationPicker`).
   * Creating the account runs the credential test right away, so the caller gets
   * a tested account (or the reason the test failed).
   *
   * Props:
   *   onCreated: (accountId: string) => void
   *   onCancel?: () => void                     shows a Cancel button on the first step
   *   provider?: EdgeProviderId                 preselect
   *   compact?: boolean                         the protect flow: limits and priority keep their
   *                                             defaults and are not shown; placement comes from
   *                                             the discovered lists as usual
   *   layers?: EdgeLayer[]                      the layers the caller's transports can be carried
   *                                             at: edge providers of another layer are offered
   *                                             disabled, with the reason (a DNS provider is
   *                                             never judged by layer: it fronts nothing)
   *
   * The picker groups providers by what an account is for: L4 edge providers,
   * L7 edge providers, DNS providers (`providerGroups`). A provider that needs
   * a DNS account says so and offers to add one first.
   *   nodeCountry?: string | null               the node's country, for the region hint
   */
  import { untrack } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import CircleCheck from '@lucide/svelte/icons/circle-check';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import {
    EDGE_PROVIDER_IDS,
    type EdgeDiscoverResponse,
    type EdgeLayer,
    type EdgeProviderId,
  } from '@shared/contracts/edges';
  import {
    createProvider,
    discoverProviderOptions,
    edgeConfigQuery,
    invalidateProviders,
    providersQuery,
    testProviderCredentials,
  } from '@client/lib/edgesApi';
  import {
    DNS_ACCOUNT_BLURB,
    EDGE_PROVIDER_META,
    dnsProviderNames,
    providerGroupOf,
    providerGroups,
  } from '@client/lib/edgeProviderMeta';
  import AdminListState from '../../AdminListState.svelte';
  import Stepper from '../components/Stepper.svelte';
  import NumberField from '../components/NumberField.svelte';
  import LayerBadge from '../components/LayerBadge.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import ProviderAnswer from '../components/ProviderAnswer.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import { providerLabel } from '../lib/format';
  import type { StepperStep } from '../lib/types';
  import {
    CREDENTIAL_HELP,
    DEFAULT_SETTINGS,
    applyDiscovery,
    credentialLabel,
    fieldsFor,
    hasLocations,
    missingRequired,
    optionsFor,
    regionLabelOf,
    settingsBody,
    type ProviderField,
  } from './providerFields';

  interface Props {
    onCreated: (accountId: string) => void;
    onCancel?: () => void;
    provider?: EdgeProviderId;
    compact?: boolean;
    layers?: EdgeLayer[];
    nodeCountry?: string | null;
  }
  let {
    onCreated,
    onCancel,
    provider: presetProvider,
    compact = false,
    layers,
    nodeCountry = null,
  }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const providers = providersQuery();
  const edgeConfig = edgeConfigQuery();
  /** Settings lets a DNS account front traffic too (`edge.l7.dnsProvidersFront`, off by default). */
  const dnsMayFront = $derived(
    (edgeConfig.data?.config as { l7?: { dnsProvidersFront?: boolean } } | undefined)?.l7
      ?.dnsProvidersFront === true,
  );
  const groups = providerGroups(EDGE_PROVIDER_IDS);
  const dnsProviders = groups.find((g) => g.id === 'dns')!.providers;

  type StepId = 'credentials' | 'placement';
  let step = $state<StepId>('credentials');
  /** An edge provider whose layer cannot carry the caller's transports (offered disabled). */
  const unfit = (p: EdgeProviderId): boolean =>
    layers !== undefined &&
    EDGE_PROVIDER_META[p].role === 'edge' &&
    !layers.includes(EDGE_PROVIDER_META[p].layer);
  /** The short hint beside a provider in the picker. */
  function providerHint(p: EdgeProviderId): string {
    if (unfit(p)) return 'cannot carry these transports';
    const m = EDGE_PROVIDER_META[p];
    if (m.role === 'dns') return 'DNS account';
    if (m.layer === 'l4') return 'load balancer (L4)';
    return m.needsDnsAccount ? 'CDN front (L7), needs a DNS account' : 'CDN front (L7)';
  }
  const initialProvider = untrack(
    () => presetProvider ?? EDGE_PROVIDER_IDS.find((p) => !unfit(p)) ?? 'gcore',
  );
  let provider = $state<EdgeProviderId>(initialProvider);
  let name = $state('');
  let credentials = $state<Record<string, string>>({});
  let values = $state<Record<string, string>>({
    ...(DEFAULT_SETTINGS[initialProvider] ?? {}),
  });
  let discovered = $state<EdgeDiscoverResponse | null>(null);
  let showAdvanced = $state(false);
  let maxLiveEdges = $state(4);
  let dailyAllocationBudget = $state(6);
  let priority = $state(10);
  let limitsInvalid = $state({ max: false, budget: false, priority: false });
  let triedNext = $state(false);

  const meta = $derived(EDGE_PROVIDER_META[provider]);
  const secretNames = $derived(providers.data?.credentialFields[provider] ?? []);
  const accounts = $derived(providers.data?.accounts ?? []);
  const ctx = $derived({ discovered, accounts, values });

  function setProvider(next: EdgeProviderId) {
    if (next === provider) return;
    provider = next;
    credentials = {};
    values = { ...(DEFAULT_SETTINGS[next] ?? {}) };
    discovered = null;
    discover.reset();
    triedNext = false;
  }

  const credentialIssues = $derived.by(() => {
    const out: string[] = [];
    if (name.trim() === '') out.push('Give the account a name.');
    else if (accounts.some((a) => a.name.toLowerCase() === name.trim().toLowerCase()))
      out.push('Another account already has this name.');
    for (const c of secretNames)
      if ((credentials[c] ?? '').trim() === '') out.push(`Enter the ${credentialLabel(c)}.`);
    for (const l of missingRequired(provider, values, 'credentials')) out.push(`Enter the ${l}.`);
    return out;
  });
  const placementMissing = $derived(missingRequired(provider, values, 'placement'));
  const dnsAccounts = $derived(accounts.filter((a) => EDGE_PROVIDER_META[a.provider].providesDns));
  const needsDnsFirst = $derived(meta.needsDnsAccount && dnsAccounts.length === 0);
  /** "Add a DNS account first": back to the credentials, on the (first) DNS provider. */
  function addDnsAccountFirst() {
    const dns = dnsProviders[0];
    if (!dns) return;
    setProvider(dns);
    step = 'credentials';
  }

  const cleanCredentials = () =>
    Object.fromEntries(
      Object.entries(credentials)
        .map(([k, v]) => [k, v.trim()] as const)
        .filter(([, v]) => v !== ''),
    );

  /** What a discovery is asked with; an answer counts only while the form still says this. */
  const snapshot = () => ({
    provider,
    credentials: cleanCredentials(),
    settings: settingsBody(provider, values),
  });
  type Snapshot = ReturnType<typeof snapshot>;
  const sameSnapshot = (a: Snapshot, b: Snapshot) => JSON.stringify(a) === JSON.stringify(b);

  // Set by Connect: its successful answer opens the placement (a re-list from a
  // project or region pick does not move the step).
  let connecting = false;
  const discover = createMutation(() => ({
    mutationFn: (s: Snapshot) => discoverProviderOptions(s),
    onSuccess: (r, asked) => {
      // The provider, a credential or a setting changed while it was asked:
      // the answer belongs to another form, so it is dropped (ask again).
      if (!sameSnapshot(asked, snapshot())) {
        connecting = false;
        return;
      }
      discovered = r;
      values = applyDiscovery(provider, values, { discovered: r, accounts });
      // Connected: on to the placement (Connect has nothing else to decide).
      if (connecting) {
        connecting = false;
        step = 'placement';
        triedNext = false;
      }
    },
    onError: () => {
      connecting = false;
    },
  }));

  const discoveredLists = $derived.by(() => {
    if (!discovered) return [];
    const rows: Array<{ label: string; count: number }> = [];
    const add = (label: string, list: unknown[] | undefined) => {
      if (list) rows.push({ label, count: list.length });
    };
    add('Projects', discovered.projects);
    add(meta.layer === 'l7' ? 'Locations' : 'Regions or zones', discovered.regions);
    add('Private networks', discovered.networks);
    add('DNS zones', discovered.zones);
    add('TLS configurations', discovered.tlsConfigurations);
    return rows;
  });
  const discoverErrors = $derived(Object.entries(discovered?.errors ?? {}));
  // Connected = the provider answered at least one list without an error for it.
  const connected = $derived(
    discovered !== null &&
      (discoveredLists.length > discoverErrors.length || discoverErrors.length === 0),
  );

  function onFieldChange(f: ProviderField, value: string) {
    const next = { ...values, [f.key]: value };
    if (f.from === 'zones')
      next['zoneName'] = optionsFor(f, ctx).find((o) => o.id === value)?.label ?? '';
    if (f.from === 'networks') next['subnetId'] = '';
    values = next;
    // Lists below a project or a region depend on it.
    if (f.from === 'projects' || f.from === 'regions') discover.mutate(snapshot());
  }

  let testOutcome = $state<{ ok: boolean; code: string | null; detail?: string | null } | null>(
    null,
  );
  let createdId = $state<string | null>(null);
  const create = createMutation(() => ({
    mutationFn: async () => {
      // The settings carry the first location's keys too: the server makes the
      // account (credentials, its own settings) and that location from them.
      const { id } = await createProvider({
        provider,
        name: name.trim(),
        settings: settingsBody(provider, values),
        locationLabel: regionLabelOf(provider, values, discovered),
        credentials: cleanCredentials(),
        maxLiveEdges,
        dailyAllocationBudget,
        priority,
      });
      createdId = id;
      // The account exists from here on: a failed test is reported, never thrown away.
      try {
        const t = await testProviderCredentials(id);
        testOutcome = { ok: t.ok, code: t.code, detail: t.detail };
      } catch (err) {
        testOutcome = { ok: false, code: null };
        toast.error('The account was saved, but the credential test could not run', {
          description: edgeErrorMessage(err),
        });
      }
      return id;
    },
    onSuccess: (id) => {
      invalidateProviders(qc);
      credentials = {};
      if (testOutcome?.ok) {
        toast.success('Account added and tested');
        onCreated(id);
      }
    },
  }));
  const retest = createMutation(() => ({
    mutationFn: () => testProviderCredentials(createdId!),
    onSuccess: (t) => {
      testOutcome = { ok: t.ok, code: t.code, detail: t.detail };
      invalidateProviders(qc);
      if (t.ok) {
        toast.success('Credentials work');
        onCreated(createdId!);
      }
    },
  }));
  const createRefusal = $derived(create.error ? edgeErrorIssue(create.error) : null);

  const limitsBad = $derived(limitsInvalid.max || limitsInvalid.budget || limitsInvalid.priority);

  const ORDER: StepId[] = ['credentials', 'placement'];
  const steps = $derived.by((): StepperStep[] => {
    const at = ORDER.indexOf(step);
    const status = (id: StepId): StepperStep['status'] => {
      const i = ORDER.indexOf(id);
      return i < at ? 'done' : i === at ? 'ready' : 'blocked';
    };
    return [
      {
        id: 'credentials',
        title: 'Credentials',
        description:
          'Which provider, and the secrets FCP uses to call it. Connect checks them; nothing is saved yet.',
        status: status('credentials'),
      },
      {
        id: 'placement',
        title: hasLocations(provider)
          ? compact
            ? 'First location'
            : 'First location and limits'
          : compact
            ? 'Settings'
            : 'Settings and limits',
        description: hasLocations(provider)
          ? compact
            ? 'Where its first addresses are created. Add more locations later.'
            : 'Where its first edges are created (add more locations later), and how many this account may run.'
          : compact
            ? 'Where its addresses are created.'
            : 'Where its edges are created, and how many this account may run.',
        status: status('placement'),
        ...(step !== 'placement' ? { note: 'after connecting' } : {}),
      },
    ];
  });

  /** Credentials -> Connect: the provider lists what they can see, then the placement opens. */
  function connect() {
    triedNext = true;
    if (credentialIssues.length > 0 || unfit(provider)) return;
    // Always asks again: the credentials may have changed since the last answer.
    connecting = true;
    discover.mutate(snapshot());
  }
  /** The region hint: an L4 address near the node keeps the extra hop short. */
  const regionHint = $derived(
    nodeCountry
      ? `The node is in ${nodeCountry}. Pick a region close to it: members reach the address, which forwards to the node.`
      : 'Pick a region close to the node: members reach the address, which forwards to the node.',
  );
  const locked = $derived(create.isPending || createdId !== null);
</script>

{#snippet settingField(f: ProviderField)}
  {@const opts = optionsFor(f, ctx)}
  {@const current = values[f.key] ?? ''}
  <!-- Credential-step settings are part of what Connect asks with: held while it runs. -->
  {@const held = locked || (f.step === 'credentials' && discover.isPending)}
  <div class="space-y-1.5">
    <Label for={`${uid}-${f.key}`}>{f.label}{f.required ? '' : ' (optional)'}</Label>
    {#if f.kind === 'select' && opts.length > 0}
      <Select.Root
        type="single"
        value={current}
        onValueChange={(v: string) => onFieldChange(f, v === '__none' ? '' : v)}
        disabled={held}
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
    {:else if f.from === 'dnsAccounts'}
      <AdminListState
        emptyText="No DNS account exists yet. Add one first (see DNS providers in the provider list), then add this one."
      />
    {:else}
      <Input
        id={`${uid}-${f.key}`}
        class="font-mono"
        value={current}
        placeholder={f.placeholder}
        readonly={f.readOnly === true && (discovered?.zones?.length ?? 0) > 0}
        disabled={held}
        oninput={(e) => onFieldChange(f, e.currentTarget.value)}
      />
      {#if f.kind === 'select' && f.from !== 'subnets'}
        <p class="text-muted-foreground text-xs">
          The provider returned no list for this, so type the id.
        </p>
      {/if}
    {/if}
    {#if f.help}<p class="text-muted-foreground text-xs">{f.help}</p>{/if}
    {#if f.from === 'regions' && meta.layer === 'l4'}
      <p class="text-muted-foreground text-xs">{regionHint}</p>
    {/if}
  </div>
{/snippet}

<Stepper {steps} current={step} label="Add a provider account">
  {#snippet children(s)}
    {#if s.id === 'credentials'}
      <div class="space-y-4">
        {#if providers.isError}
          <AdminListState error={providers.error} onRetry={() => void providers.refetch()} />
        {/if}
        <div class="grid gap-4 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label for={`${uid}-provider`}>Provider</Label>
            <Select.Root
              type="single"
              value={provider}
              onValueChange={(v: string) => setProvider(v as EdgeProviderId)}
              disabled={discover.isPending}
            >
              <Select.Trigger id={`${uid}-provider`} class="w-full">
                {providerLabel(provider)}
              </Select.Trigger>
              <Select.Content>
                {#each groups.filter((g) => g.providers.length > 0) as g (g.id)}
                  <Select.Group>
                    <Select.GroupHeading>{g.title}</Select.GroupHeading>
                    {#each g.providers as p (p)}
                      <Select.Item value={p} label={providerLabel(p)} disabled={unfit(p)}>
                        {providerLabel(p)}
                        <span class="text-muted-foreground text-xs">{providerHint(p)}</span>
                      </Select.Item>
                    {/each}
                  </Select.Group>
                {/each}
              </Select.Content>
            </Select.Root>
            {#if providerGroupOf(provider) === 'dns'}
              <div class="text-muted-foreground space-y-1 text-xs">
                <p class="flex items-start gap-1.5">
                  <LayerBadge layer="dns" />
                  <span>
                    {DNS_ACCOUNT_BLURB}
                    {#if dnsMayFront}
                      Settings currently lets DNS accounts front traffic as well.
                    {/if}
                  </span>
                </p>
                <p>
                  DNS providers FCP supports: {dnsProviderNames(EDGE_PROVIDER_IDS).join(', ')}. More
                  DNS-only providers can be added later.
                </p>
              </div>
            {:else}
              <p class="text-muted-foreground flex items-center gap-1.5 text-xs">
                <LayerBadge layer={meta.layer} />
                {meta.layer === 'l7'
                  ? 'Fronts HTTP transports by hostname.'
                  : 'Forwards connections to the origin by address.'}
              </p>
            {/if}
          </div>
          <div class="space-y-1.5">
            <Label for={`${uid}-name`}>Account name</Label>
            <Input
              id={`${uid}-name`}
              bind:value={name}
              placeholder="Main account"
              disabled={discover.isPending}
            />
            <p class="text-muted-foreground text-xs">Only shown to admins.</p>
          </div>
        </div>
        {#if meta.needsDnsAccount}
          <div
            class="space-y-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm"
          >
            <p>
              {providerLabel(provider)} needs a DNS account first: its names, and the certificate challenge
              for each one, are written into a zone of a DNS provider account.
              {needsDnsFirst
                ? 'No DNS account exists yet.'
                : `You have ${dnsAccounts.length === 1 ? 'one' : dnsAccounts.length} to choose from in the next step.`}
            </p>
            {#if needsDnsFirst && dnsProviders.length > 0}
              <Button
                size="sm"
                variant="outline"
                class="h-11 sm:h-8"
                disabled={discover.isPending}
                onclick={addDnsAccountFirst}
              >
                Add a DNS account first
              </Button>
            {/if}
          </div>
        {/if}
        {#if CREDENTIAL_HELP[provider]}
          <p class="rounded-md border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-sm">
            {CREDENTIAL_HELP[provider]}
          </p>
        {/if}
        <div class="grid gap-4 sm:grid-cols-2">
          {#each secretNames as c (c)}
            <div class="space-y-1.5">
              <Label for={`${uid}-cred-${c}`}>{credentialLabel(c)}</Label>
              <Input
                id={`${uid}-cred-${c}`}
                type="password"
                autocomplete="off"
                class="font-mono"
                value={credentials[c] ?? ''}
                disabled={discover.isPending}
                oninput={(e) => (credentials = { ...credentials, [c]: e.currentTarget.value })}
              />
              <p class="text-muted-foreground text-xs">Write only: it is never shown again.</p>
            </div>
          {/each}
          {#each fieldsFor(provider, 'credentials') as f (f.key)}
            {@render settingField(f)}
          {/each}
        </div>
        {#if unfit(provider)}
          <p class="text-destructive text-sm" role="alert">
            {providerLabel(provider)} cannot carry this node's transports. Pick another provider.
          </p>
        {/if}
        {#if triedNext && credentialIssues.length > 0}
          <ul class="text-destructive list-disc space-y-0.5 ps-5 text-sm" role="alert">
            {#each credentialIssues as i (i)}<li>{i}</li>{/each}
          </ul>
        {/if}
        <div aria-live="polite">
          {#if discover.isPending}
            <p class="text-muted-foreground text-sm" role="status">
              Asking {providerLabel(provider)} what these credentials can see.
            </p>
          {:else if discover.isError}
            {@const issue = edgeErrorIssue(discover.error)}
            {#if issue}<CodeNote {issue} />{:else}<InlineError
                message={edgeErrorMessage(discover.error)}
              />{/if}
            <p class="text-muted-foreground mt-1 text-sm">
              Nothing was saved. Check the credentials and connect again.
            </p>
          {/if}
        </div>
        <div class="flex gap-2">
          <Button
            class="h-11 sm:h-8"
            onclick={connect}
            disabled={providers.isPending || discover.isPending}
          >
            {discover.isPending ? 'Connecting' : 'Connect'}
          </Button>
          {#if onCancel}<Button variant="outline" class="h-11 sm:h-8" onclick={onCancel}
              >Cancel</Button
            >{/if}
        </div>
      </div>
    {:else}
      <div class="space-y-4">
        <div class="space-y-2" aria-live="polite">
          {#if connected}
            <p class="flex items-center gap-2 text-sm font-medium">
              <CircleCheck
                class="size-4 text-emerald-600 dark:text-emerald-400"
                aria-hidden="true"
              />
              Connected. The provider answered with these credentials.
            </p>
          {/if}
          {#if discoveredLists.length > 0}
            <ul class="text-sm">
              {#each discoveredLists as l (l.label)}
                <li>
                  <span class="text-muted-foreground">{l.label}:</span>
                  {l.count === 0 ? 'none visible' : `${l.count} visible`}
                </li>
              {/each}
            </ul>
          {/if}
          {#each discoverErrors as [list, code] (list)}
            <CodeNote
              tone="warning"
              issue={{
                code,
                subject: list,
                detail: 'This list could not be read. Type the id below instead.',
              }}
            />
            <ProviderAnswer detail={discovered?.errorDetails?.[list]} />
          {/each}
          {#if discover.isError}
            {@const issue = edgeErrorIssue(discover.error)}
            {#if issue}<CodeNote {issue} />{:else}<InlineError
                message={edgeErrorMessage(discover.error)}
              />{/if}
          {/if}
          {#if !locked}
            <Button
              variant="ghost"
              size="sm"
              class="h-11 sm:h-7"
              disabled={discover.isPending}
              onclick={() => discover.mutate(snapshot())}
            >
              {discover.isPending ? 'Connecting' : 'Connect again'}
            </Button>
          {/if}
        </div>
        {#if needsDnsFirst}
          <CodeNote
            issue={{
              code: 'dns_account_missing',
              detail:
                'This provider keeps its hostnames in a zone of a DNS account. Add that account first.',
            }}
          >
            {#snippet actions()}
              {#if dnsProviders.length > 0 && !locked}
                <Button size="sm" variant="outline" onclick={addDnsAccountFirst}>
                  Add a DNS account
                </Button>
              {/if}
            {/snippet}
          </CodeNote>
        {/if}
        <div class="grid gap-4 sm:grid-cols-2">
          {#each fieldsFor(provider, 'placement').filter((f) => !f.advanced) as f (f.key)}
            {@render settingField(f)}
          {/each}
        </div>
        {#if fieldsFor(provider, 'placement').some((f) => f.advanced)}
          <Button variant="ghost" size="sm" onclick={() => (showAdvanced = !showAdvanced)}>
            {showAdvanced ? 'Hide optional placement' : 'Show optional placement'}
          </Button>
          {#if showAdvanced}
            <div class="grid gap-4 sm:grid-cols-2">
              {#each fieldsFor(provider, 'placement').filter((f) => f.advanced) as f (f.key)}
                {@render settingField(f)}
              {/each}
            </div>
          {/if}
        {/if}
        <div class="grid gap-4 sm:grid-cols-3" class:hidden={compact}>
          <NumberField
            bind:value={maxLiveEdges}
            bind:invalid={limitsInvalid.max}
            label="Live edges at most"
            unit="edges"
            min={1}
            max={100}
            helper="Provisioning stops at this many resources on the account."
            disabled={locked}
          />
          <NumberField
            bind:value={dailyAllocationBudget}
            bind:invalid={limitsInvalid.budget}
            label="New edges per day"
            unit="edges"
            min={1}
            max={100}
            helper="A daily cap on allocations, so a block storm cannot run up a bill."
            disabled={locked}
          />
          <NumberField
            bind:value={priority}
            bind:invalid={limitsInvalid.priority}
            label="Priority"
            min={0}
            max={1000}
            helper="Lower numbers are tried first."
            disabled={locked}
          />
        </div>
        {#if triedNext && placementMissing.length > 0}
          <p class="text-destructive text-sm" role="alert">
            Still needed: {placementMissing.join(', ')}.
          </p>
        {/if}
        {#if createRefusal}
          <CodeNote issue={createRefusal} />
        {:else if create.error}
          <InlineError message={edgeErrorMessage(create.error)} />
        {/if}
        {#if createdId && testOutcome && !testOutcome.ok}
          <CodeNote
            issue={{
              code: testOutcome.code ?? 'credentials_failed',
              subject: name,
              detail:
                'The account was saved, but its credential test failed. Nothing can be provisioned from it until a test passes.',
            }}
          />
          <ProviderAnswer detail={testOutcome.detail} />
          {#if CREDENTIAL_HELP[provider]}
            <p class="text-muted-foreground text-xs">{CREDENTIAL_HELP[provider]}</p>
          {/if}
          {#if retest.error}<InlineError message={edgeErrorMessage(retest.error)} />{/if}
          <div class="flex gap-2">
            <Button disabled={retest.isPending} onclick={() => retest.mutate()}>
              {retest.isPending ? 'Testing' : 'Test again'}
            </Button>
            <Button variant="outline" onclick={() => onCreated(createdId!)}>Continue anyway</Button>
          </div>
        {:else}
          <div class="flex flex-wrap gap-2">
            <Button
              disabled={create.isPending || limitsBad || needsDnsFirst}
              onclick={() => {
                triedNext = true;
                if (placementMissing.length === 0) create.mutate();
              }}
            >
              {create.isPending ? 'Adding and testing' : 'Add account and test it'}
            </Button>
            <Button
              variant="ghost"
              disabled={create.isPending}
              onclick={() => (step = 'credentials')}
            >
              Back
            </Button>
          </div>
          <p class="text-muted-foreground text-xs">
            {#if compact}
              The account keeps the default limits (4 addresses at most, 6 new per day). Change them
              later from Providers.
            {:else}
              A new account is tested but not trusted: it can only be used for a test edge until one
              of its addresses is confirmed with a real session, or you trust it by hand.
            {/if}
          </p>
        {/if}
      </div>
    {/if}
  {/snippet}
</Stepper>
