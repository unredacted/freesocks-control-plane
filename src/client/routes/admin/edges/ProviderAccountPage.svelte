<script lang="ts">
  /**
   * One provider account (`/admin/edges/providers/:id`; URL state `?tab` =
   * overview | inventory | templates). The overview's Countries card grades
   * each location from each checked country, with the location marks.
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Label } from '@client/components/ui/label';
  import { Skeleton } from '@client/components/ui/skeleton';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import * as Select from '@client/components/ui/select';
  import * as Table from '@client/components/ui/table';
  import * as Tabs from '@client/components/ui/tabs';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '../../../lib/api';
  import {
    DNS_ACCOUNT_BLURB,
    DNS_ACCOUNT_USES,
    EDGE_PROVIDER_META,
  } from '../../../lib/edgeProviderMeta';
  import { router } from '../../../stores/router.svelte';
  import { searchParam } from '../../../lib/urlState.svelte';
  import {
    deleteProvider,
    invalidateProviders,
    providerQuery,
    providersQuery,
    providersUsageQuery,
    templatesQuery,
    updateProvider,
  } from '../../../lib/edgesApi';
  import AdminListState from '../AdminListState.svelte';
  import ConfirmDialog from './components/ConfirmDialog.svelte';
  import ProviderAnswer from './components/ProviderAnswer.svelte';
  import FakeBadge from './components/FakeBadge.svelte';
  import KeyValue from './components/KeyValue.svelte';
  import LayerBadge from './components/LayerBadge.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import { credentialLabel } from './forms/providerFields';
  import { providerLabel } from './lib/format';
  import { edgesPaths } from './lib/routes';
  import { relativeTime } from './lib/time';
  import type { KeyValueRow } from './lib/types';
  import CountriesCard from './providers/CountriesCard.svelte';
  import DeleteDialog from './providers/DeleteDialog.svelte';
  import InventoryTab from './providers/InventoryTab.svelte';
  import LimitsCard from './providers/LimitsCard.svelte';
  import LocationsCard from './providers/LocationsCard.svelte';
  import OptionDefaultsCard from './providers/OptionDefaultsCard.svelte';
  import ReachCard from './providers/ReachCard.svelte';
  import QualifyDialog from './providers/QualifyDialog.svelte';
  import RenameDialog from './providers/RenameDialog.svelte';
  import RotateCredentialsDialog from './providers/RotateCredentialsDialog.svelte';
  import {
    isTested,
    observedRows as observedRowsOf,
    settingRows,
    testWords,
  } from './providers/accountWords';
  import { useAccountActions } from './providers/useAccountActions.svelte';
  import { asParams, changedKeys, effectiveTemplate, qualificationState } from './templates/params';

  interface Props {
    /** The provider account id from the route (`/admin/edges/providers/:id`). */
    id: string;
  }
  let { id }: Props = $props();

  const TABS = ['overview', 'inventory', 'templates'] as const;
  type Tab = (typeof TABS)[number];

  const qc = useQueryClient();
  const account = providerQuery(() => id);
  const providers = providersQuery();
  const usage = providersUsageQuery();
  const templates = templatesQuery();
  const acct = useAccountActions();
  const tabParam = searchParam('tab', 'overview');
  const tab = $derived<Tab>(
    (TABS as readonly string[]).includes(tabParam.value) ? (tabParam.value as Tab) : 'overview',
  );

  const a = $derived(account.data ?? null);
  const u = $derived(usage.data?.accounts.find((x) => x.id === id));
  const tplList = $derived(templates.data?.templates ?? []);
  const others = $derived((providers.data?.accounts ?? []).filter((x) => x.id !== id));
  const notFound = $derived(account.error instanceof ApiCallError && account.error.status === 404);

  const tested = $derived(a ? testWords(a) : null);
  const q = $derived(a ? qualificationState(a, tplList) : null);
  const tpl = $derived(a ? effectiveTemplate(tplList, a) : null);
  const myTemplates = $derived(
    a
      ? tplList.filter(
          (t) => t.provider === a.provider && (t.accountId === null || t.accountId === a.id),
        )
      : [],
  );

  // --- settings in words ---------------------------------------------------------------------------
  const accountNames = $derived(
    Object.fromEntries((providers.data?.accounts ?? []).map((x) => [x.id, x.name])),
  );
  const settingsRows = $derived<KeyValueRow[]>(a ? settingRows(a.settings, accountNames) : []);
  const observedRows = $derived<KeyValueRow[]>(
    a?.observedSettings ? observedRowsOf(a.observedSettings) : [],
  );
  const credentialRows = $derived<KeyValueRow[]>(
    a
      ? Object.entries(a.credentialsSet).map(([k, set]) => ({
          label: credentialLabel(k),
          value: set ? 'Stored, never shown' : 'Missing',
          tone: set ? 'success' : 'danger',
        }))
      : [],
  );
  const credentialFields = $derived(
    a ? (providers.data?.credentialFields[a.provider] ?? Object.keys(a.credentialsSet)) : [],
  );

  // --- DNS accounts (a front writes its records through one) ---------------------------------------
  const needsDns = $derived(a ? EDGE_PROVIDER_META[a.provider].needsDnsAccount : false);
  const dnsAccountsExist = $derived(others.some((x) => EDGE_PROVIDER_META[x.provider].providesDns));

  // --- certificates (a provider whose fronts can share one wildcard) ---------------------------------
  const sharesCertificates = $derived(
    a ? EDGE_PROVIDER_META[a.provider].sharedCertificates : false,
  );
  // The provider's certificate options (the account's defaults for its nodes).
  const certificateFields = $derived(
    a
      ? (providers.data?.optionSchemas[a.provider]?.fields ?? []).filter(
          (f) => f.kind === 'certificate',
        )
      : [],
  );
  // How a new front's name is attached to its service (absent = its own domain).
  const domainsNow = $derived(
    a && a.settings.domainModel === 'classic' ? 'classic' : 'versionless',
  );
  const DOMAIN_WORDS: Record<string, string> = {
    versionless: 'Its own domain, linked to the service',
    classic: 'A domain on the service version (classic)',
  };
  let domainsChoice = $state<string | null>(null);
  let domainsOpen = $state(false);
  async function saveDomains() {
    if (!a || !domainsChoice) return;
    await updateProvider(a.id, { settings: { ...a.settings, domainModel: domainsChoice } });
    invalidateProviders(qc);
    toast.success('Domains changed');
    domainsChoice = null;
  }

  // --- what a DNS account does (DNS only, or DNS and fronting) ------------------------------------------
  const isDnsAccount = $derived(a ? EDGE_PROVIDER_META[a.provider].role === 'dns' : false);
  const useNow = $derived<'dns' | 'front'>(a?.frontsTraffic ? 'front' : 'dns');
  let useChoice = $state<'dns' | 'front' | null>(null);
  let useOpen = $state(false);
  async function saveUse() {
    if (!a || !useChoice) return;
    const fronts = useChoice === 'front';
    await updateProvider(a.id, { frontsTraffic: fronts });
    invalidateProviders(qc);
    toast.success(fronts ? 'This account now fronts traffic too' : 'This account is DNS only now');
    useChoice = null;
    // The fronting checks of its zones (certificate, CAA, encryption mode) run with a test.
    if (fronts) acct.test.mutate(a.id);
  }

  // --- dialogs ---------------------------------------------------------------------------------------
  let qualifyOpen = $state(false);
  let rotateOpen = $state(false);
  let renameOpen = $state(false);
  let deleteOpen = $state(false);
</script>

{#if account.isPending}
  <SectionHeader
    title="Provider account"
    back={{ href: edgesPaths.providers(), label: 'Providers' }}
  />
  <div class="space-y-3" role="status">
    <span class="sr-only">Loading the account</span>
    <Skeleton class="h-24 w-full" />
    <Skeleton class="h-40 w-full" />
  </div>
{:else if notFound}
  <SectionHeader
    title="Provider account"
    back={{ href: edgesPaths.providers(), label: 'Providers' }}
  />
  <AdminListState
    emptyText="This account does not exist any more. Go back to Providers to pick another one or add it again."
  />
{:else if account.isError || !a}
  <SectionHeader
    title="Provider account"
    back={{ href: edgesPaths.providers(), label: 'Providers' }}
  />
  <AdminListState error={account.error} onRetry={() => void account.refetch()} />
{:else}
  <SectionHeader
    title={a.name}
    description={EDGE_PROVIDER_META[a.provider].role === 'dns'
      ? `${providerLabel(a.provider)} account: ${DNS_ACCOUNT_USES[useNow].label}. ${DNS_ACCOUNT_BLURB}`
      : `${providerLabel(a.provider)} account. Credentials, settings, inventory and qualification.`}
    back={{ href: edgesPaths.providers(), label: 'Providers' }}
  >
    {#snippet badges()}
      <FakeBadge fake={a.fake} />
      <LayerBadge
        layer={EDGE_PROVIDER_META[a.provider].role === 'dns'
          ? 'dns'
          : (u?.layer ?? EDGE_PROVIDER_META[a.provider].layer)}
      />
      <Badge variant={a.enabled ? 'success' : 'muted'}>{a.enabled ? 'Enabled' : 'Disabled'}</Badge>
    {/snippet}
    {#snippet actions()}
      <Button
        size="sm"
        variant="outline"
        disabled={acct.test.isPending}
        onclick={() => acct.test.mutate(a.id)}
      >
        {acct.test.isPending ? 'Testing' : 'Test credentials'}
      </Button>
      <Button size="sm" variant="outline" onclick={() => (renameOpen = true)}>Rename</Button>
      <Button size="sm" variant="outline" onclick={() => (rotateOpen = true)}>
        Rotate credentials
      </Button>
      {#if a.locations.length <= 1}
        <Button size="sm" onclick={() => (qualifyOpen = true)}>
          {a.qualified ? 'Remove trust' : 'Trust override'}
        </Button>
      {/if}
    {/snippet}
  </SectionHeader>

  <Tabs.Root value={tab} onValueChange={(v) => (tabParam.value = v)}>
    <Tabs.List>
      <Tabs.Trigger value="overview">Overview</Tabs.Trigger>
      <Tabs.Trigger value="inventory">Inventory</Tabs.Trigger>
      <Tabs.Trigger value="templates">Templates</Tabs.Trigger>
    </Tabs.List>

    <Tabs.Content value="overview" class="space-y-6 pt-4">
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Readiness</CardTitle>
          <CardDescription>
            FCP provisions automatically only in accounts that are enabled and tested, and only in
            their trusted locations.
          </CardDescription>
        </CardHeader>
        <CardContent class="grid gap-4 sm:grid-cols-3">
          <div>
            <div class="text-xs text-muted-foreground">Credentials</div>
            {#if tested}
              <Badge variant={tested.tone} class="mt-1">{tested.label}</Badge>
              <p class="mt-1 text-xs text-muted-foreground">{tested.detail}</p>
              <ProviderAnswer detail={a.lastTestErrorDetail} />
            {/if}
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Qualification</div>
            {#if q}
              <Badge
                variant={q.state === 'qualified'
                  ? 'success'
                  : q.state === 'stale'
                    ? 'warning'
                    : 'muted'}
                class="mt-1"
              >
                {q.state === 'qualified'
                  ? 'Qualified'
                  : q.state === 'stale'
                    ? 'Qualified, out of date'
                    : 'Not qualified'}
              </Badge>
              <p class="mt-1 text-xs text-muted-foreground">{q.words}</p>
            {/if}
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Capacity</div>
            <p class="mt-1 text-sm tabular-nums">
              {u?.liveEdges ?? 0} of {a.maxLiveEdges} live edges
            </p>
            <p class="text-xs text-muted-foreground tabular-nums">
              {#if u}{u.published} published, {u.standby} standby, {u.draining} draining.{/if}
              {a.allocationsToday} of {a.dailyAllocationBudget} allocations used today.
            </p>
          </div>
        </CardContent>
      </Card>

      <div class="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardContent class="space-y-6 pt-6">
            <KeyValue
              title="Settings"
              description={settingsRows.length > 0
                ? 'The settings of the account itself. Where its edges are created is a location (below).'
                : 'This account is its credentials. Where its edges are created is a location (below).'}
              rows={settingsRows}
              columns={1}
            />
            {#if observedRows.length > 0}
              <KeyValue
                title="Seen at the provider"
                description={a.observedAt
                  ? `What the last credential test observed, ${relativeTime(a.observedAt)}.`
                  : 'What the last credential test observed.'}
                rows={observedRows}
                columns={1}
              />
            {/if}
          </CardContent>
        </Card>
        <Card>
          <CardContent class="space-y-6 pt-6">
            <KeyValue
              title="Credentials"
              description="Write-only. Use Rotate credentials to replace them without losing the qualification."
              rows={credentialRows}
              columns={1}
            />
            <KeyValue
              title="Record"
              rows={[
                { label: 'Account ID', value: a.id, mono: true, copy: true },
                { label: 'Added', value: relativeTime(a.createdAt) },
                { label: 'Last changed', value: relativeTime(a.updatedAt) },
                {
                  label: 'Template in use',
                  value: tpl ? tpl.name : 'None yet',
                  hint:
                    tpl && a.defaultTemplateId === null
                      ? 'The default of this provider'
                      : undefined,
                },
              ]}
              columns={1}
            />
          </CardContent>
        </Card>
      </div>

      <ReachCard account={a} dnsAccountsExist={!needsDns || dnsAccountsExist} />

      {#if isDnsAccount}
        <Card>
          <CardHeader>
            <CardTitle class="text-base">What this account does</CardTitle>
            <CardDescription>
              A DNS account holds the records FCP writes for other fronts. It can also front member
              traffic itself, through its zones.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-4">
            <div class="flex flex-wrap items-end gap-3">
              <div class="max-w-md flex-1 space-y-1.5">
                <Label for="acct-dns-use">This account is</Label>
                <Select.Root
                  type="single"
                  value={useChoice ?? useNow}
                  onValueChange={(v) => {
                    const next = v === 'front' ? 'front' : 'dns';
                    useChoice = next === useNow ? null : next;
                  }}
                >
                  <Select.Trigger id="acct-dns-use" class="w-full">
                    {DNS_ACCOUNT_USES[useChoice ?? useNow].label}
                  </Select.Trigger>
                  <Select.Content>
                    <Select.Item value="dns" label={DNS_ACCOUNT_USES.dns.label}>
                      {DNS_ACCOUNT_USES.dns.label}
                    </Select.Item>
                    <Select.Item value="front" label={DNS_ACCOUNT_USES.front.label}>
                      {DNS_ACCOUNT_USES.front.label}
                    </Select.Item>
                  </Select.Content>
                </Select.Root>
              </div>
              <Button disabled={useChoice === null} onclick={() => (useOpen = true)}>Change</Button>
            </div>
            <p class="text-xs text-muted-foreground">
              {DNS_ACCOUNT_USES[useChoice ?? useNow].detail}
            </p>
            {#if useNow === 'front' || useChoice === 'front'}
              <p class="text-xs text-muted-foreground">
                The CDN still sends the member's address to the node in X-Forwarded-For, which no
                rule can remove there: the node removes it before the proxy sees the request.
              </p>
            {/if}
          </CardContent>
        </Card>
      {/if}

      {#if certificateFields.length > 0}
        <OptionDefaultsCard account={a} fields={certificateFields}>
          {#if sharesCertificates}
            <p class="text-xs text-muted-foreground">
              Each zone has its own shared certificate, shown with the zone under Locations. It is
              read at the provider when the account is tested, and ordered by the first new front
              there.
            </p>
          {/if}
        </OptionDefaultsCard>
      {/if}

      {#if sharesCertificates}
        <Card>
          <CardHeader>
            <CardTitle class="text-base">Domains</CardTitle>
            <CardDescription>
              How a new front's name is attached to its service. Fronts that exist keep theirs.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-4">
            <div class="flex flex-wrap items-end gap-3">
              <div class="max-w-md flex-1 space-y-1.5">
                <Label for="acct-domains">A new front's name is</Label>
                <Select.Root
                  type="single"
                  value={domainsChoice ?? domainsNow}
                  onValueChange={(v) => (domainsChoice = v === domainsNow ? null : v)}
                >
                  <Select.Trigger id="acct-domains" class="w-full">
                    {DOMAIN_WORDS[domainsChoice ?? domainsNow]}
                  </Select.Trigger>
                  <Select.Content>
                    <Select.Item value="versionless"
                      >{DOMAIN_WORDS.versionless} (recommended)</Select.Item
                    >
                    <Select.Item value="classic">{DOMAIN_WORDS.classic}</Select.Item>
                  </Select.Content>
                </Select.Root>
              </div>
              <Button disabled={domainsChoice === null} onclick={() => (domainsOpen = true)}>
                Change domains
              </Button>
            </div>
            <p class="text-xs text-muted-foreground">
              Classic domains exist only on accounts created before September 2025. Pick them if the
              provider refuses to link a front's own domain to its service.
            </p>
          </CardContent>
        </Card>
      {/if}

      <LocationsCard account={a} {accountNames} />

      <CountriesCard account={a} />

      {#key a.id}
        <LimitsCard account={a} templates={tplList} />
      {/key}

      <Card>
        <CardHeader>
          <CardTitle class="text-base">Availability</CardTitle>
          <CardDescription>
            A disabled account gets no new edges. Its existing edges keep working and can still be
            rotated away or destroyed.
          </CardDescription>
        </CardHeader>
        <CardContent class="flex flex-wrap items-center justify-between gap-3">
          <Button
            variant="outline"
            disabled={acct.setEnabled.isPending}
            onclick={() => acct.setEnabled.mutate({ id: a.id, enabled: !a.enabled })}
          >
            {a.enabled ? 'Disable account' : 'Enable account'}
          </Button>
          <Button variant="ghost" class="text-destructive" onclick={() => (deleteOpen = true)}>
            Delete account
          </Button>
        </CardContent>
      </Card>
    </Tabs.Content>

    <Tabs.Content value="inventory" class="pt-4">
      {#if tab === 'inventory'}<InventoryTab accountId={a.id} locations={a.locations} />{/if}
    </Tabs.Content>

    <Tabs.Content value="templates" class="space-y-4 pt-4">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <p class="text-sm text-muted-foreground">
          Templates this account can provision from: its own and the ones shared by every
          {providerLabel(a.provider)} account.
        </p>
        <Button
          size="sm"
          variant="outline"
          onclick={() =>
            router.navigate(edgesPaths.templates({ template: 'new', provider: a.provider }))}
        >
          New template
        </Button>
      </div>
      {#if templates.isPending}
        <Skeleton class="h-16 w-full" />
      {:else if templates.isError}
        <AdminListState error={templates.error} onRetry={() => void templates.refetch()} />
      {:else if myTemplates.length === 0}
        <AdminListState
          emptyText="No template for this provider yet. Open Templates and use Seed defaults, or write a new one."
        />
      {:else}
        <Table.Root>
          <Table.Header>
            <Table.Row>
              <Table.Head>Name</Table.Head>
              <Table.Head>Available to</Table.Head>
              <Table.Head>Parameters</Table.Head>
              <Table.Head>Role here</Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {#each myTemplates as t (t.id)}
              {@const schema = templates.data?.schemas[a.provider]}
              {@const diff = schema
                ? changedKeys(asParams(t.params), schema.defaults, schema.fields).length
                : 0}
              <Table.Row>
                <Table.Cell>
                  <Link
                    href={edgesPaths.templates({ template: t.id })}
                    class="font-medium hover:underline">{t.name}</Link
                  >
                  {#if t.isDefault}<Badge variant="info" class="ms-2">Default</Badge>{/if}
                </Table.Cell>
                <Table.Cell
                  >{t.accountId === null ? 'Every account' : 'Only this account'}</Table.Cell
                >
                <Table.Cell>
                  {diff === 0
                    ? 'Provider defaults'
                    : `${diff} differ${diff === 1 ? 's' : ''} from default`}
                </Table.Cell>
                <Table.Cell>
                  {#if tpl?.id === t.id}
                    <Badge variant="success">In use</Badge>
                    {#if q?.state === 'stale'}
                      <span class="ms-1 text-xs text-muted-foreground"
                        >changed since qualification</span
                      >
                    {/if}
                  {:else}
                    <span class="text-muted-foreground">Available</span>
                  {/if}
                </Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      {/if}
      <p class="text-sm">
        <Link href={edgesPaths.templates({ provider: a.provider })} class="underline"
          >Open all {providerLabel(a.provider)} templates</Link
        >
      </p>
    </Tabs.Content>
  </Tabs.Root>

  <QualifyDialog
    bind:open={qualifyOpen}
    account={a}
    tested={isTested(a)}
    onQualify={acct.qualify}
  />
  <RenameDialog bind:open={renameOpen} account={a} taken={others.map((x) => x.name)} />
  <RotateCredentialsDialog bind:open={rotateOpen} account={a} {credentialFields} />
  <ConfirmDialog
    bind:open={useOpen}
    title={useChoice === 'front'
      ? 'Let this account front traffic?'
      : 'Make this account DNS only?'}
    body={useChoice === 'front'
      ? 'Nodes can then be protected through its zones. Its zones are checked with a credential test right away, and its locations are trusted again by their first proven front. Fronts it already has are kept.'
      : 'It gets no new fronts and its spares do not go live. Fronts that carry members now are kept until they are replaced or deleted. The records it holds for other fronts are not touched.'}
    confirmLabel={useChoice === 'front' ? 'Front traffic too' : 'DNS only'}
    onConfirm={saveUse}
  />
  <ConfirmDialog
    bind:open={domainsOpen}
    title="Change how fronts get their names?"
    body="New fronts of this account get their name the new way; fronts that exist keep theirs. Like any settings change, the account loses its trust: test it again, and its next proven front trusts it."
    confirmLabel="Change domains"
    onConfirm={saveDomains}
  />
  <DeleteDialog
    bind:open={deleteOpen}
    kind="account"
    name={a.name}
    body="The stored credentials and settings are removed. FCP refuses while edges still live in the account or another account writes DNS through it. Nothing at the provider is touched."
    run={() => deleteProvider(a.id)}
    ondeleted={() => {
      invalidateProviders(qc);
      toast.success('Account deleted');
      router.navigate(edgesPaths.providers(), { replace: true });
    }}
  />
{/if}
