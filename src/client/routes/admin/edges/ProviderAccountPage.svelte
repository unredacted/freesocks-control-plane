<script lang="ts">
  /**
   * One provider account (`/admin/edges/providers/:id`; URL state `?tab` =
   * overview | inventory | templates).
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
  import { EDGE_PROVIDER_META } from '../../../lib/edgeProviderMeta';
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
  import FakeBadge from './components/FakeBadge.svelte';
  import KeyValue from './components/KeyValue.svelte';
  import LayerBadge from './components/LayerBadge.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import { credentialLabel } from './forms/providerFields';
  import { providerLabel } from './lib/format';
  import { edgesPaths } from './lib/routes';
  import { relativeTime } from './lib/time';
  import type { KeyValueRow } from './lib/types';
  import DeleteDialog from './providers/DeleteDialog.svelte';
  import InventoryTab from './providers/InventoryTab.svelte';
  import LimitsCard from './providers/LimitsCard.svelte';
  import QualifyDialog from './providers/QualifyDialog.svelte';
  import RotateCredentialsDialog from './providers/RotateCredentialsDialog.svelte';
  import { isTested, settingLabel, settingRows, testWords } from './providers/accountWords';
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
    a?.observedSettings
      ? Object.entries(a.observedSettings).map(([k, v]) => ({ label: settingLabel(k), value: v }))
      : [],
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

  // --- DNS account -----------------------------------------------------------------------------------
  const needsDns = $derived(a ? EDGE_PROVIDER_META[a.provider].needsDnsAccount : false);
  const dnsCandidates = $derived(others.filter((x) => EDGE_PROVIDER_META[x.provider].providesDns));
  const currentDns = $derived(
    a && typeof a.settings.dnsAccountId === 'string' ? a.settings.dnsAccountId : null,
  );
  let dnsChoice = $state<string | null>(null);
  let dnsOpen = $state(false);
  async function saveDns() {
    if (!a || !dnsChoice) return;
    await updateProvider(a.id, { settings: { ...a.settings, dnsAccountId: dnsChoice } });
    invalidateProviders(qc);
    toast.success('DNS account changed');
    dnsChoice = null;
  }

  // --- dialogs ---------------------------------------------------------------------------------------
  let qualifyOpen = $state(false);
  let rotateOpen = $state(false);
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
    description={`${providerLabel(a.provider)} account. Credentials, settings, inventory and qualification.`}
    back={{ href: edgesPaths.providers(), label: 'Providers' }}
  >
    {#snippet badges()}
      <FakeBadge fake={a.fake} />
      <LayerBadge layer={u?.layer ?? EDGE_PROVIDER_META[a.provider].layer} />
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
      <Button size="sm" variant="outline" onclick={() => (rotateOpen = true)}>
        Rotate credentials
      </Button>
      <Button size="sm" onclick={() => (qualifyOpen = true)}>
        {a.qualified ? 'Remove trust' : 'Trust override'}
      </Button>
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
            FCP provisions automatically only in accounts that are enabled, tested and qualified.
          </CardDescription>
        </CardHeader>
        <CardContent class="grid gap-4 sm:grid-cols-3">
          <div>
            <div class="text-xs text-muted-foreground">Credentials</div>
            {#if tested}
              <Badge variant={tested.tone} class="mt-1">{tested.label}</Badge>
              <p class="mt-1 text-xs text-muted-foreground">{tested.detail}</p>
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
              description="Where FCP creates edges. Changing these would move the account, so they are fixed once edges exist. Add a second account for another location."
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

      {#if needsDns}
        <Card>
          <CardHeader>
            <CardTitle class="text-base">DNS account</CardTitle>
            <CardDescription>
              The hostnames of this provider's edges are written through another account that hosts
              the DNS zone.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-3">
            {#if dnsCandidates.length === 0}
              <AdminListState
                emptyText="No account that can host DNS records exists yet. Add one on the Providers page first."
              />
            {:else}
              <div class="max-w-md space-y-1.5">
                <Label for="acct-dns">Writes DNS through</Label>
                <Select.Root
                  type="single"
                  value={dnsChoice ?? currentDns ?? ''}
                  onValueChange={(v) => (dnsChoice = v === currentDns ? null : v)}
                >
                  <Select.Trigger id="acct-dns" class="w-full">
                    {dnsCandidates.find((x) => x.id === (dnsChoice ?? currentDns))?.name ??
                      (currentDns ? 'An account that was removed' : 'Choose an account')}
                  </Select.Trigger>
                  <Select.Content>
                    {#each dnsCandidates as d (d.id)}
                      <Select.Item value={d.id}>{d.name} ({providerLabel(d.provider)})</Select.Item>
                    {/each}
                  </Select.Content>
                </Select.Root>
              </div>
              <div class="flex justify-end">
                <Button disabled={dnsChoice === null} onclick={() => (dnsOpen = true)}>
                  Change DNS account
                </Button>
              </div>
            {/if}
          </CardContent>
        </Card>
      {/if}

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
      {#if tab === 'inventory'}<InventoryTab accountId={a.id} />{/if}
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
  <RotateCredentialsDialog bind:open={rotateOpen} account={a} {credentialFields} />
  <ConfirmDialog
    bind:open={dnsOpen}
    title="Change the DNS account?"
    body="New edges of this account will get their DNS records through the account you picked. The account loses its qualification and must be tested and qualified again. Existing edges keep the records they have."
    confirmLabel="Change DNS account"
    onConfirm={saveDns}
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
