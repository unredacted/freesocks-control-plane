<script lang="ts">
  /**
   * Templates (`/admin/edges/templates`).
   * URL state: `?template=<id>` opens the editor, `?template=new&provider=<id>`
   * starts a new one, `?provider=<id>` alone filters the list to one provider.
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
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
    type EdgeProviderId,
    type EdgeTemplateAdmin,
  } from '../../../../shared/contracts/edges';
  import {
    deleteTemplate,
    ensureDefaultTemplates,
    invalidateProviders,
    providersQuery,
    templatesQuery,
  } from '../../../lib/edgesApi';
  import { searchParam, setSearchParams } from '../../../lib/urlState.svelte';
  import AdminListState from '../AdminListState.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import { edgeErrorMessage } from './lib/edgeErrors';
  import { providerLabel } from './lib/format';
  import { edgesPaths } from './lib/routes';
  import { relativeTime } from './lib/time';
  import DeleteDialog from './providers/DeleteDialog.svelte';
  import TemplateEditor from './templates/TemplateEditor.svelte';
  import { asParams, changedKeys } from './templates/params';

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

  /** Providers that have a schema, in the catalogue order, filtered by `?provider`. */
  const groups = $derived(
    EDGE_PROVIDER_IDS.filter((p) => schemas[p] !== undefined)
      .filter(
        (p) => templateParam.value !== '' || !providerParam.value || providerParam.value === p,
      )
      .map((p) => ({
        provider: p,
        templates: all.filter((t) => t.provider === p),
        accounts: accounts.filter((a) => a.provider === p),
      })),
  );

  // --- editor (Sheet) ------------------------------------------------------------------------------
  const editing = $derived<EdgeTemplateAdmin | null>(
    all.find((t) => t.id === templateParam.value) ?? null,
  );
  const creating = $derived(templateParam.value === 'new' && isProvider(providerParam.value));
  const editorProvider = $derived<EdgeProviderId | null>(
    editing ? editing.provider : creating ? (providerParam.value as EdgeProviderId) : null,
  );
  const editorSchema = $derived(editorProvider ? (schemas[editorProvider] ?? null) : null);
  const sheetOpen = $derived(templateParam.value !== '');
  const openEditor = (id: string) => (templateParam.value = id);
  const openNew = (provider: EdgeProviderId) => setSearchParams({ template: 'new', provider });
  function closeEditor() {
    setSearchParams({ template: null, provider: creating ? null : providerParam.value });
  }

  // --- usage of a template ------------------------------------------------------------------------
  const namedBy = (t: EdgeTemplateAdmin) => accounts.filter((a) => a.defaultTemplateId === t.id);

  // --- actions ---------------------------------------------------------------------------------------
  const seed = createMutation(() => ({
    mutationFn: ensureDefaultTemplates,
    onSuccess: (r) => {
      invalidateProviders(qc);
      toast.success(
        r.created === 0
          ? 'Every provider already has a default template'
          : `${r.created} default template${r.created === 1 ? '' : 's'} created`,
      );
    },
    onError: (err: unknown) =>
      toast.error('Could not seed the defaults', { description: edgeErrorMessage(err) }),
  }));

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

<SectionHeader
  title="Templates"
  description="The parameters an edge is created with at a provider: plan or size, timeouts, health checks. An account provisions from the template it names, or from the default of its provider."
>
  {#snippet actions()}
    <Button variant="outline" size="sm" disabled={seed.isPending} onclick={() => seed.mutate()}>
      {seed.isPending ? 'Seeding' : 'Seed defaults'}
    </Button>
  {/snippet}
</SectionHeader>

{#if providerParam.value && templateParam.value === '' && isProvider(providerParam.value)}
  <p class="mb-4 text-sm text-muted-foreground">
    Showing {providerLabel(providerParam.value)} only.
    <button class="underline" onclick={() => (providerParam.value = null)}
      >Show every provider</button
    >
  </p>
{/if}

{#if templates.isPending}
  <div class="space-y-3" role="status">
    <span class="sr-only">Loading templates</span>
    <Skeleton class="h-32 w-full" />
    <Skeleton class="h-32 w-full" />
  </div>
{:else if templates.isError}
  <AdminListState error={templates.error} onRetry={() => void templates.refetch()} />
{:else if all.length === 0}
  <AdminListState
    emptyText="No templates yet. Use Seed defaults to create one default template per provider from the built-in parameters, then adjust them here."
  />
{:else}
  <div class="space-y-6">
    {#each groups as g (g.provider)}
      <Card>
        <CardHeader>
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle class="text-base">{providerLabel(g.provider)}</CardTitle>
              <CardDescription>
                {g.accounts.length === 0
                  ? 'No account of this provider yet.'
                  : `${g.accounts.length} account${g.accounts.length === 1 ? '' : 's'} can use these.`}
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
              emptyText="No template for this provider. Use Seed defaults, or New template to write one."
            />
          {:else}
            <Table.Root>
              <Table.Header>
                <Table.Row>
                  <Table.Head>Name</Table.Head>
                  <Table.Head>Available to</Table.Head>
                  <Table.Head>Parameters</Table.Head>
                  <Table.Head>Used by</Table.Head>
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
                      <Link
                        href={edgesPaths.templates({ template: t.id })}
                        class="font-medium hover:underline">{t.name}</Link
                      >
                      {#if t.isDefault}<Badge variant="info" class="ms-2">Default</Badge>{/if}
                    </Table.Cell>
                    <Table.Cell>
                      {t.accountId === null ? 'Every account' : `Only ${accountName(t.accountId)}`}
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
                      {#if users.length > 0}
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
          ? `${providerLabel(editorProvider)} parameters. Saving a change that moves an account's effective template clears that account's qualification.`
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
          emptyText="This template no longer exists. Close this panel and pick one from the list."
        />
      {/if}
    </div>
  </Sheet.Content>
</Sheet.Root>

<DeleteDialog
  bind:open={deleteOpen}
  kind="template"
  name={deleting?.name ?? ''}
  body="Edges that already exist keep the parameters they were created with. New edges use another template."
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
