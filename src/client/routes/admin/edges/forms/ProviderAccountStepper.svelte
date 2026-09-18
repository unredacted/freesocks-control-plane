<script lang="ts">
  /**
   * Add a provider account in three steps:
   *   1. Credentials        provider, a name, the write-only secrets and the public identifiers
   *                         the provider needs on every request
   *   2. Connect            lists what the credentials can see (projects, regions or zones,
   *                         networks); nothing is stored yet, the lists stay in form state
   *   3. Placement, limits  where edges are created (picked from those lists, or the DNS
   *                         account for a provider that needs one) and the spending limits
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
    type EdgeProviderId,
  } from '@shared/contracts/edges';
  import {
    createProvider,
    discoverProviderOptions,
    invalidateProviders,
    providersQuery,
    testProviderCredentials,
  } from '@client/lib/edgesApi';
  import { EDGE_PROVIDER_META } from '@client/lib/edgeProviderMeta';
  import AdminListState from '../../AdminListState.svelte';
  import Stepper from '../components/Stepper.svelte';
  import NumberField from '../components/NumberField.svelte';
  import LayerBadge from '../components/LayerBadge.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import { providerLabel } from '../lib/format';
  import type { StepperStep } from '../lib/types';
  import {
    CREDENTIAL_HELP,
    DEFAULT_SETTINGS,
    applyDiscovery,
    credentialLabel,
    fieldsFor,
    missingRequired,
    optionsFor,
    settingsBody,
    type ProviderField,
  } from './providerFields';

  interface Props {
    onCreated: (accountId: string) => void;
    onCancel?: () => void;
    provider?: EdgeProviderId;
    compact?: boolean;
  }
  let { onCreated, onCancel, provider: presetProvider, compact = false }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const providers = providersQuery();

  type StepId = 'credentials' | 'connect' | 'placement';
  let step = $state<StepId>('credentials');
  const initialProvider = untrack(() => presetProvider ?? 'gcore');
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

  const cleanCredentials = () =>
    Object.fromEntries(
      Object.entries(credentials)
        .map(([k, v]) => [k, v.trim()] as const)
        .filter(([, v]) => v !== ''),
    );

  const discover = createMutation(() => ({
    mutationFn: () =>
      discoverProviderOptions({
        provider,
        credentials: cleanCredentials(),
        settings: settingsBody(provider, values),
      }),
    onSuccess: (r) => {
      discovered = r;
      values = applyDiscovery(provider, values, { discovered: r, accounts });
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
    if (f.from === 'projects' || f.from === 'regions') discover.mutate();
  }

  let testOutcome = $state<{ ok: boolean; code: string | null } | null>(null);
  let createdId = $state<string | null>(null);
  const create = createMutation(() => ({
    mutationFn: async () => {
      const { id } = await createProvider({
        provider,
        name: name.trim(),
        settings: settingsBody(provider, values),
        credentials: cleanCredentials(),
        maxLiveEdges,
        dailyAllocationBudget,
        priority,
      });
      createdId = id;
      // The account exists from here on: a failed test is reported, never thrown away.
      try {
        const t = await testProviderCredentials(id);
        testOutcome = { ok: t.ok, code: t.code };
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
      testOutcome = { ok: t.ok, code: t.code };
      invalidateProviders(qc);
      if (t.ok) {
        toast.success('Credentials work');
        onCreated(createdId!);
      }
    },
  }));
  const createRefusal = $derived(create.error ? edgeErrorIssue(create.error) : null);

  const limitsBad = $derived(limitsInvalid.max || limitsInvalid.budget || limitsInvalid.priority);

  const ORDER: StepId[] = ['credentials', 'connect', 'placement'];
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
        description: 'Which provider, and the secrets FCP uses to call it.',
        status: status('credentials'),
      },
      {
        id: 'connect',
        title: 'Connect',
        description: 'List what these credentials can see. Nothing is saved yet.',
        status: status('connect'),
        ...(step === 'credentials' ? { note: 'after the credentials' } : {}),
      },
      {
        id: 'placement',
        title: compact ? 'Placement' : 'Placement and limits',
        description: compact
          ? 'Where addresses are created.'
          : 'Where edges are created, and how many this account may run.',
        status: status('placement'),
        ...(step !== 'placement' ? { note: 'after connecting' } : {}),
      },
    ];
  });

  function next() {
    triedNext = true;
    if (step === 'credentials') {
      if (credentialIssues.length > 0) return;
      step = 'connect';
      triedNext = false;
      if (!discovered) discover.mutate();
    } else if (step === 'connect') {
      step = 'placement';
      triedNext = false;
    }
  }
  const locked = $derived(create.isPending || createdId !== null);
</script>

{#snippet settingField(f: ProviderField)}
  {@const opts = optionsFor(f, ctx)}
  {@const current = values[f.key] ?? ''}
  <div class="space-y-1.5">
    <Label for={`${uid}-${f.key}`}>{f.label}{f.required ? '' : ' (optional)'}</Label>
    {#if f.kind === 'select' && opts.length > 0}
      <Select.Root
        type="single"
        value={current}
        onValueChange={(v: string) => onFieldChange(f, v === '__none' ? '' : v)}
        disabled={locked}
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
        emptyText="No account that can host DNS exists yet. Add that account first, then add this one."
      />
    {:else}
      <Input
        id={`${uid}-${f.key}`}
        class="font-mono"
        value={current}
        placeholder={f.placeholder}
        readonly={f.readOnly === true && (discovered?.zones?.length ?? 0) > 0}
        disabled={locked}
        oninput={(e) => onFieldChange(f, e.currentTarget.value)}
      />
      {#if f.kind === 'select' && f.from !== 'subnets'}
        <p class="text-muted-foreground text-xs">
          The provider returned no list for this, so type the id.
        </p>
      {/if}
    {/if}
    {#if f.help}<p class="text-muted-foreground text-xs">{f.help}</p>{/if}
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
            >
              <Select.Trigger id={`${uid}-provider`} class="w-full">
                {providerLabel(provider)}
              </Select.Trigger>
              <Select.Content>
                {#each EDGE_PROVIDER_IDS as p (p)}
                  <Select.Item value={p} label={providerLabel(p)}>
                    {providerLabel(p)}
                    <span class="text-muted-foreground text-xs">
                      {EDGE_PROVIDER_META[p].layer === 'l7'
                        ? 'CDN front (L7)'
                        : 'load balancer (L4)'}
                    </span>
                  </Select.Item>
                {/each}
              </Select.Content>
            </Select.Root>
            <p class="text-muted-foreground flex items-center gap-1.5 text-xs">
              <LayerBadge layer={meta.layer} />
              {meta.layer === 'l7'
                ? 'Fronts HTTP transports by hostname.'
                : 'Forwards connections to the origin by address.'}
            </p>
          </div>
          <div class="space-y-1.5">
            <Label for={`${uid}-name`}>Account name</Label>
            <Input id={`${uid}-name`} bind:value={name} placeholder="Main account" />
            <p class="text-muted-foreground text-xs">Only shown to admins.</p>
          </div>
        </div>
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
                oninput={(e) => (credentials = { ...credentials, [c]: e.currentTarget.value })}
              />
              <p class="text-muted-foreground text-xs">Write only: it is never shown again.</p>
            </div>
          {/each}
          {#each fieldsFor(provider, 'credentials') as f (f.key)}
            {@render settingField(f)}
          {/each}
        </div>
        {#if triedNext && credentialIssues.length > 0}
          <ul class="text-destructive list-disc space-y-0.5 ps-5 text-sm" role="alert">
            {#each credentialIssues as i (i)}<li>{i}</li>{/each}
          </ul>
        {/if}
        <div class="flex gap-2">
          <Button onclick={next} disabled={providers.isPending}>Continue</Button>
          {#if onCancel}<Button variant="outline" onclick={onCancel}>Cancel</Button>{/if}
        </div>
      </div>
    {:else if s.id === 'connect'}
      <div class="space-y-3" aria-live="polite">
        {#if discover.isPending}
          <p class="text-muted-foreground text-sm" role="status">
            Asking {providerLabel(provider)} what these credentials can see.
          </p>
        {:else if discover.isError}
          {@const issue = edgeErrorIssue(discover.error)}
          {#if issue}<CodeNote {issue} />{:else}<InlineError
              message={edgeErrorMessage(discover.error)}
            />{/if}
          <p class="text-muted-foreground text-sm">
            Nothing was saved. Check the credentials and try again.
          </p>
        {:else if discovered}
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
                detail:
                  'This list could not be read. You can type the id on the next step instead.',
              }}
            />
          {/each}
          {#if discoveredLists.length === 0 && discoverErrors.length === 0}
            <p class="text-muted-foreground text-sm">
              This provider has nothing to list at this point. Continue to the placement.
            </p>
          {/if}
        {/if}
        <div class="flex flex-wrap gap-2">
          <Button
            onclick={next}
            disabled={discover.isPending || (!discovered && !discover.isError)}
          >
            Continue
          </Button>
          <Button variant="outline" disabled={discover.isPending} onclick={() => discover.mutate()}>
            {discover.isPending ? 'Connecting' : 'Connect again'}
          </Button>
          <Button variant="ghost" onclick={() => (step = 'credentials')}>Back</Button>
        </div>
      </div>
    {:else}
      <div class="space-y-4">
        {#if needsDnsFirst}
          <CodeNote
            issue={{
              code: 'dns_account_missing',
              detail:
                'This provider keeps its hostnames in a zone of another account. Add that account first.',
            }}
          />
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
            <Button variant="ghost" disabled={create.isPending} onclick={() => (step = 'connect')}>
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
