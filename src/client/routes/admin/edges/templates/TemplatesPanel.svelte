<script lang="ts">
  /**
   * The templates tables, their editor (a Sheet) and the delete dialog, shared
   * by "All templates" (`/admin/servers/providers/templates`) and an account's
   * Templates tab (`/admin/servers/providers/:id?tab=templates`).
   *
   * URL state: `?template=<id>` opens the editor, `?template=new` starts a new
   * one (on All templates with `&provider=<id>`; on an account, for its
   * provider).
   *
   * Props:
   *   account?: EdgeProviderAccountAdmin | null   an account's tab: only the templates it can
   *                                               use, with the one in use ("Role here")
   *   provider?: EdgeProviderId | null            All templates: show one provider only
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import * as Sheet from '@client/components/ui/sheet';
  import * as Table from '@client/components/ui/table';
  import Link from '@client/components/Link.svelte';
  import {
    EDGE_PROVIDER_IDS,
    type EdgeProviderAccountAdmin,
    type EdgeProviderId,
    type EdgeTemplateAdmin,
  } from '../../../../../shared/contracts/edges';
  import {
    deleteTemplate,
    invalidateProviders,
    providersQuery,
    templatesQuery,
  } from '../../../../lib/edgesApi';
  import { searchParam, setSearchParams } from '../../../../lib/urlState.svelte';
  import AdminListState from '../../AdminListState.svelte';
  import { providerLabel } from '../lib/format';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';
  import DeleteDialog from '../providers/DeleteDialog.svelte';
  import TemplateEditor from './TemplateEditor.svelte';
  import { availableTo } from './list';
  import { asParams, changedKeys, effectiveTemplate, qualificationState } from './params';

  interface Props {
    account?: EdgeProviderAccountAdmin | null;
    provider?: EdgeProviderId | null;
  }
  let { account = null, provider = null }: Props = $props();

  const qc = useQueryClient();
  const templates = templatesQuery();
  const providers = providersQuery();
  const templateParam = searchParam('template');
  const providerParam = searchParam('provider');

  const isProvider = (v: string): v is EdgeProviderId =>
    (EDGE_PROVIDER_IDS as readonly string[]).includes(v);

  const all = $derived(templates.data?.templates ?? []);
  const schemas = $derived(templates.data?.schemas ?? {});
  const accounts = $derived(providers.data?.accounts ?? []);
  const accountName = (id: string | null) =>
    id === null ? null : (accounts.find((a) => a.id === id)?.name ?? 'an account that was removed');

  /** One group per provider (All templates), or the account's provider with what it can use. */
  const groups = $derived(
    account
      ? [
          {
            provider: account.provider,
            templates: availableTo(all, account),
            accounts: accounts.filter((a) => a.provider === account.provider),
          },
        ]
      : EDGE_PROVIDER_IDS.filter((p) => schemas[p] !== undefined)
          .filter((p) => !provider || provider === p)
          .map((p) => ({
            provider: p,
            templates: all.filter((t) => t.provider === p),
            accounts: accounts.filter((a) => a.provider === p),
          })),
  );

  // --- the account's template in use ----------------------------------------------------------------
  const inUse = $derived(account ? effectiveTemplate(all, account) : null);
  const stale = $derived(account ? qualificationState(account, all).state === 'stale' : false);

  const hrefOf = (id: string) =>
    account
      ? edgesPaths.provider(account.id, { tab: 'templates', template: id })
      : edgesPaths.templates({ template: id });

  // --- editor (Sheet) ------------------------------------------------------------------------------
  const editing = $derived<EdgeTemplateAdmin | null>(
    all.find((t) => t.id === templateParam.value) ?? null,
  );
  const newProvider = $derived<EdgeProviderId | null>(
    account ? account.provider : isProvider(providerParam.value) ? providerParam.value : null,
  );
  const creating = $derived(templateParam.value === 'new' && newProvider !== null);
  const editorProvider = $derived<EdgeProviderId | null>(
    editing ? editing.provider : creating ? newProvider : null,
  );
  const editorSchema = $derived(editorProvider ? (schemas[editorProvider] ?? null) : null);
  const sheetOpen = $derived(templateParam.value !== '');
  const openEditor = (id: string) => (templateParam.value = id);
  const openNew = (p: EdgeProviderId) =>
    account ? (templateParam.value = 'new') : setSearchParams({ template: 'new', provider: p });
  function closeEditor() {
    if (account) templateParam.value = null;
    else setSearchParams({ template: null, provider: creating ? null : providerParam.value });
  }

  // --- usage of a template ------------------------------------------------------------------------
  const namedBy = (t: EdgeTemplateAdmin) => accounts.filter((a) => a.defaultTemplateId === t.id);

  let deleting = $state<EdgeTemplateAdmin | null>(null);
  let deleteOpen = $state(false);
  function askDelete(t: EdgeTemplateAdmin) {
    deleting = t;
    deleteOpen = true;
  }
  function afterDelete() {
    invalidateProviders(qc);
    toast.success('Template deleted');
    if (deleting && templateParam.value === deleting.id) closeEditor();
    deleting = null;
  }
  const deletingUsers = $derived(deleting ? namedBy(deleting) : []);
</script>

{#if templates.isPending}
  <div class="space-y-3" role="status">
    <span class="sr-only">Loading templates</span>
    <Skeleton class="h-32 w-full" />
    {#if !account}<Skeleton class="h-32 w-full" />{/if}
  </div>
{:else if templates.isError}
  <AdminListState error={templates.error} onRetry={() => void templates.refetch()} />
{:else if all.length === 0 && !account}
  <AdminListState
    emptyText="No templates yet. Use Seed defaults to create one per provider from the built-in parameters, then adjust them here."
  />
{:else}
  <div class="space-y-6">
    {#each groups as g (g.provider)}
      <Card>
        <CardHeader>
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle class="text-base">
                {account ? 'Templates' : providerLabel(g.provider)}
              </CardTitle>
              <CardDescription>
                {#if account}
                  The templates this account can make addresses from: its own, and the ones every
                  {providerLabel(g.provider)} account shares.
                {:else}
                  {g.accounts.length === 0
                    ? 'No account of this provider yet.'
                    : `${g.accounts.length} account${g.accounts.length === 1 ? '' : 's'} can use these.`}
                {/if}
              </CardDescription>
            </div>
            <Button size="sm" variant="outline" onclick={() => openNew(g.provider)}>
              New template
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {#if g.templates.length === 0}
            <AdminListState
              emptyText={account
                ? 'No template for this provider yet. Use Seed defaults on All templates, or New template to write one.'
                : 'No template for this provider. Use Seed defaults, or New template to write one.'}
            />
          {:else}
            <Table.Root>
              <Table.Header>
                <Table.Row>
                  <Table.Head>Name</Table.Head>
                  <Table.Head>Available to</Table.Head>
                  <Table.Head>Parameters</Table.Head>
                  <Table.Head>{account ? 'Role here' : 'Used by'}</Table.Head>
                  <Table.Head>Changed</Table.Head>
                  <Table.Head><span class="sr-only">Actions</span></Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#each g.templates as t (t.id)}
                  {@const schema = schemas[g.provider]}
                  {@const diff = schema
                    ? changedKeys(asParams(t.params), schema.defaults, schema.fields).length
                    : 0}
                  {@const users = namedBy(t)}
                  <Table.Row>
                    <Table.Cell>
                      <Link href={hrefOf(t.id)} class="font-medium hover:underline">{t.name}</Link>
                      {#if t.isDefault}<Badge variant="info" class="ms-2">Default</Badge>{/if}
                    </Table.Cell>
                    <Table.Cell>
                      {#if t.accountId === null}
                        Every account
                      {:else if account && t.accountId === account.id}
                        Only this account
                      {:else}
                        Only {accountName(t.accountId)}
                      {/if}
                    </Table.Cell>
                    <Table.Cell>
                      {#if diff === 0}
                        <span class="text-muted-foreground">Provider defaults</span>
                      {:else}
                        <Badge variant="neutral"
                          >{diff} differ{diff === 1 ? 's' : ''} from default</Badge
                        >
                      {/if}
                    </Table.Cell>
                    <Table.Cell>
                      {#if account}
                        {#if inUse?.id === t.id}
                          <Badge variant="success">In use</Badge>
                          {#if stale}
                            <span class="ms-1 text-xs text-muted-foreground"
                              >changed since qualification</span
                            >
                          {/if}
                        {:else}
                          <span class="text-muted-foreground">Available</span>
                        {/if}
                      {:else if users.length > 0}
                        {users.map((a) => a.name).join(', ')}
                      {:else if t.isDefault}
                        <span class="text-muted-foreground">Accounts that name no template</span>
                      {:else}
                        <span class="text-muted-foreground">No account names it</span>
                      {/if}
                    </Table.Cell>
                    <Table.Cell class="whitespace-nowrap text-muted-foreground" title={t.updatedAt}>
                      {relativeTime(t.updatedAt)}
                    </Table.Cell>
                    <Table.Cell class="text-right">
                      <DropdownMenu.Root>
                        <DropdownMenu.Trigger>
                          {#snippet child({ props })}
                            <Button {...props} variant="ghost" size="sm" class="h-7 px-2">
                              Actions<span class="sr-only"> for {t.name}</span>
                            </Button>
                          {/snippet}
                        </DropdownMenu.Trigger>
                        <DropdownMenu.Content align="end">
                          <DropdownMenu.Item onSelect={() => openEditor(t.id)}
                            >Edit</DropdownMenu.Item
                          >
                          <DropdownMenu.Separator />
                          <DropdownMenu.Item class="text-destructive" onSelect={() => askDelete(t)}>
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
        </CardContent>
      </Card>
    {/each}
  </div>
{/if}

<Sheet.Root
  open={sheetOpen}
  onOpenChange={(o) => {
    if (!o) closeEditor();
  }}
>
  <Sheet.Content side="right" class="gap-0 sm:max-w-2xl">
    <Sheet.Header class="border-b">
      <Sheet.Title>
        {editing ? `Template ${editing.name}` : 'New template'}
      </Sheet.Title>
      <Sheet.Description>
        {editorProvider
          ? `${providerLabel(editorProvider)} parameters. A save that changes an account's template in use clears its qualification.`
          : 'Template parameters.'}
      </Sheet.Description>
    </Sheet.Header>
    <div class="flex-1 overflow-y-auto p-4">
      {#if templates.isPending}
        <Skeleton class="h-40 w-full" />
      {:else if editorProvider && editorSchema}
        {#key templateParam.value}
          <TemplateEditor
            template={editing}
            provider={editorProvider}
            schema={editorSchema}
            accounts={accounts
              .filter((a) => a.provider === editorProvider)
              .map((a) => ({ id: a.id, name: a.name }))}
            onsaved={() => closeEditor()}
            ondelete={editing ? () => askDelete(editing) : undefined}
            oncancel={closeEditor}
          />
        {/key}
      {:else}
        <AdminListState
          emptyText="This template no longer exists. Close this panel and pick another."
        />
      {/if}
    </div>
  </Sheet.Content>
</Sheet.Root>

<DeleteDialog
  bind:open={deleteOpen}
  kind="template"
  name={deleting?.name ?? ''}
  body="Existing edges keep their parameters. New edges use another template."
  run={() => deleteTemplate(deleting!.id)}
  ondeleted={afterDelete}
>
  {#if deletingUsers.length > 0}
    <p>
      {deletingUsers.map((a) => a.name).join(', ')}
      {deletingUsers.length === 1 ? 'names' : 'name'} this template. After the delete
      {deletingUsers.length === 1 ? 'it falls' : 'they fall'} back to the provider default and must be
      qualified again.
    </p>
  {/if}
</DeleteDialog>
