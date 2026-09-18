<script lang="ts">
  /**
   * Provider accounts (`/admin/edges/providers`; `?edit=new` opens the add-account flow).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Ellipsis from '@lucide/svelte/icons/ellipsis';
  import { Badge } from '@client/components/ui/badge';
  import { Button, buttonVariants } from '@client/components/ui/button';
  import { Progress } from '@client/components/ui/progress';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import * as Sheet from '@client/components/ui/sheet';
  import * as Table from '@client/components/ui/table';
  import Link from '@client/components/Link.svelte';
  import type { EdgeProviderAccountAdmin } from '../../../../shared/contracts/edges';
  import { router } from '../../../stores/router.svelte';
  import { searchParam } from '../../../lib/urlState.svelte';
  import {
    deleteProvider,
    invalidateProviders,
    providersQuery,
    providersUsageQuery,
    templatesQuery,
  } from '../../../lib/edgesApi';
  import AdminListState from '../AdminListState.svelte';
  import FakeBadge from './components/FakeBadge.svelte';
  import LayerBadge from './components/LayerBadge.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import ProviderAccountStepper from './forms/ProviderAccountStepper.svelte';
  import { providerLabel } from './lib/format';
  import { edgesPaths } from './lib/routes';
  import DeleteDialog from './providers/DeleteDialog.svelte';
  import QualifyDialog from './providers/QualifyDialog.svelte';
  import UsageHeader from './providers/UsageHeader.svelte';
  import { isTested, testWords } from './providers/accountWords';
  import { useAccountActions } from './providers/useAccountActions.svelte';
  import { effectiveTemplate, qualificationState } from './templates/params';

  const qc = useQueryClient();
  const providers = providersQuery();
  const usage = providersUsageQuery();
  const templates = templatesQuery();
  const acct = useAccountActions();
  const edit = searchParam('edit');

  const accounts = $derived(
    [...(providers.data?.accounts ?? [])].sort(
      (a, b) => b.priority - a.priority || a.name.localeCompare(b.name),
    ),
  );
  const usageOf = (id: string) => usage.data?.accounts.find((u) => u.id === id);
  const tplList = $derived(templates.data?.templates ?? []);

  let qualifyOpen = $state(false);
  let qualifying = $state<EdgeProviderAccountAdmin | null>(null);
  let deleteOpen = $state(false);
  let deleting = $state<EdgeProviderAccountAdmin | null>(null);

  function onCreated(accountId: string) {
    invalidateProviders(qc);
    router.navigate(edgesPaths.provider(accountId));
  }
</script>

<SectionHeader
  title="Providers"
  description="The cloud and CDN accounts edges are provisioned in, with their capacity and budgets."
>
  {#snippet actions()}
    <Button size="sm" onclick={() => (edit.value = 'new')}>Add account</Button>
  {/snippet}
</SectionHeader>

<div class="space-y-6">
  {#if usage.data}
    <UsageHeader usage={usage.data} />
  {:else if usage.isError}
    <AdminListState error={usage.error} onRetry={() => void usage.refetch()} />
  {/if}

  {#if providers.isPending}
    <div class="space-y-2" role="status">
      <span class="sr-only">Loading provider accounts</span>
      <Skeleton class="h-10 w-full" />
      <Skeleton class="h-10 w-full" />
    </div>
  {:else if providers.isError}
    <AdminListState error={providers.error} onRetry={() => void providers.refetch()} />
  {:else if accounts.length === 0}
    <div class="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
      <p class="mx-auto max-w-prose">
        A provider account is one set of credentials at a cloud or CDN provider, plus the project,
        region or zone FCP creates edges in. Qualification is your confirmation that an edge from
        that account really carried a client session. Until an account is qualified, FCP uses it
        only when you provision a test edge by hand, never automatically.
      </p>
      <Button class="mt-4" size="sm" onclick={() => (edit.value = 'new')}>Add account</Button>
    </div>
  {:else}
    <Table.Root>
      <Table.Header>
        <Table.Row>
          <Table.Head>Account</Table.Head>
          <Table.Head>Provider</Table.Head>
          <Table.Head>State</Table.Head>
          <Table.Head>Credentials</Table.Head>
          <Table.Head>Qualification</Table.Head>
          <Table.Head>Live edges</Table.Head>
          <Table.Head>Allocations today</Table.Head>
          <Table.Head>Priority</Table.Head>
          <Table.Head>Template</Table.Head>
          <Table.Head><span class="sr-only">Actions</span></Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {#each accounts as a (a.id)}
          {@const u = usageOf(a.id)}
          {@const live = u?.liveEdges ?? 0}
          {@const tested = testWords(a)}
          {@const q = qualificationState(a, tplList)}
          {@const tpl = effectiveTemplate(tplList, a)}
          <Table.Row class={a.enabled ? '' : 'opacity-75'}>
            <Table.Cell>
              <Link href={edgesPaths.provider(a.id)} class="font-medium hover:underline"
                >{a.name}</Link
              >
              <FakeBadge fake={a.fake} />
            </Table.Cell>
            <Table.Cell>
              <span class="me-1">{providerLabel(a.provider)}</span>
              {#if u}<LayerBadge layer={u.layer} />{/if}
            </Table.Cell>
            <Table.Cell>
              <Badge variant={a.enabled ? 'success' : 'muted'}
                >{a.enabled ? 'Enabled' : 'Disabled'}</Badge
              >
            </Table.Cell>
            <Table.Cell>
              <Badge variant={tested.tone}>{tested.label}</Badge>
              <div class="mt-0.5 text-xs text-muted-foreground">{tested.detail}</div>
            </Table.Cell>
            <Table.Cell>
              <Badge
                variant={q.state === 'qualified'
                  ? 'success'
                  : q.state === 'stale'
                    ? 'warning'
                    : 'muted'}
              >
                {q.state === 'qualified'
                  ? 'Qualified'
                  : q.state === 'stale'
                    ? 'Qualified, out of date'
                    : 'Not qualified'}
              </Badge>
              {#if q.state === 'stale'}
                <div class="mt-0.5 max-w-56 text-xs whitespace-normal text-muted-foreground">
                  {q.words}
                </div>
              {/if}
            </Table.Cell>
            <Table.Cell>
              <div class="w-28">
                <div class="text-xs tabular-nums">{live} of {a.maxLiveEdges}</div>
                <Progress
                  value={Math.min(live, a.maxLiveEdges)}
                  max={Math.max(a.maxLiveEdges, 1)}
                  class="mt-1 h-1.5"
                  aria-label={`Live edges in ${a.name}`}
                />
              </div>
            </Table.Cell>
            <Table.Cell class="tabular-nums">
              {a.allocationsToday} of {a.dailyAllocationBudget}
            </Table.Cell>
            <Table.Cell class="tabular-nums">{a.priority}</Table.Cell>
            <Table.Cell>
              {#if tpl}
                <Link href={edgesPaths.templates({ template: tpl.id })} class="hover:underline"
                  >{tpl.name}</Link
                >
                {#if a.defaultTemplateId === null}
                  <div class="text-xs text-muted-foreground">Provider default</div>
                {/if}
              {:else}
                <span class="text-amber-700 dark:text-amber-300">None yet</span>
              {/if}
            </Table.Cell>
            <Table.Cell class="text-right">
              <DropdownMenu.Root>
                <DropdownMenu.Trigger
                  class={buttonVariants({ variant: 'ghost', size: 'icon-sm' })}
                  aria-label={`Actions for account ${a.name}`}
                >
                  <Ellipsis aria-hidden="true" />
                </DropdownMenu.Trigger>
                <DropdownMenu.Content align="end" class="w-56">
                  <DropdownMenu.Item onSelect={() => router.navigate(edgesPaths.provider(a.id))}>
                    Open
                  </DropdownMenu.Item>
                  <DropdownMenu.Item
                    disabled={acct.test.isPending}
                    onSelect={() => {
                      toast.message(`Testing the credentials of ${a.name}`);
                      acct.test.mutate(a.id);
                    }}
                  >
                    Test credentials
                  </DropdownMenu.Item>
                  <DropdownMenu.Item
                    onSelect={() => {
                      qualifying = a;
                      qualifyOpen = true;
                    }}
                  >
                    {a.qualified ? 'Remove qualification' : 'Mark qualified'}
                  </DropdownMenu.Item>
                  <DropdownMenu.Item
                    onSelect={() => acct.setEnabled.mutate({ id: a.id, enabled: !a.enabled })}
                  >
                    {a.enabled ? 'Disable' : 'Enable'}
                  </DropdownMenu.Item>
                  <DropdownMenu.Separator />
                  <DropdownMenu.Item
                    class="text-destructive"
                    onSelect={() => {
                      deleting = a;
                      deleteOpen = true;
                    }}
                  >
                    Delete
                  </DropdownMenu.Item>
                </DropdownMenu.Content>
              </DropdownMenu.Root>
            </Table.Cell>
          </Table.Row>
        {/each}
      </Table.Body>
    </Table.Root>
  {/if}
</div>

<Sheet.Root
  open={edit.value === 'new'}
  onOpenChange={(o) => {
    if (!o) edit.value = null;
  }}
>
  <Sheet.Content side="right" class="gap-0 sm:max-w-2xl">
    <Sheet.Header class="border-b">
      <Sheet.Title>Add a provider account</Sheet.Title>
      <Sheet.Description>
        Credentials are stored write-only: FCP never shows them again, here or anywhere else.
      </Sheet.Description>
    </Sheet.Header>
    <div class="flex-1 overflow-y-auto p-4">
      {#if edit.value === 'new'}
        <ProviderAccountStepper {onCreated} onCancel={() => (edit.value = null)} />
      {/if}
    </div>
  </Sheet.Content>
</Sheet.Root>

<QualifyDialog
  bind:open={qualifyOpen}
  account={qualifying}
  tested={qualifying ? isTested(qualifying) : false}
  onQualify={acct.qualify}
/>

<DeleteDialog
  bind:open={deleteOpen}
  kind="account"
  name={deleting?.name ?? ''}
  body="The stored credentials and settings are removed. FCP refuses while edges still live in the account or another account writes DNS through it. Nothing at the provider is touched."
  run={() => deleteProvider(deleting!.id)}
  ondeleted={() => {
    invalidateProviders(qc);
    toast.success('Account deleted');
    deleting = null;
  }}
/>
