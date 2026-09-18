<script lang="ts">
  /**
   * Provider accounts (`/admin/edges/providers`) as cards: state, addresses
   * used, the trust line. A card opens the account page (the table with every
   * column lives there). `?edit=new` opens the add-account flow.
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as Sheet from '@client/components/ui/sheet';
  import { router } from '../../../stores/router.svelte';
  import { searchParam } from '../../../lib/urlState.svelte';
  import { invalidateProviders, providersQuery, providersUsageQuery } from '../../../lib/edgesApi';
  import AdminListState from '../AdminListState.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import ProviderAccountStepper from './forms/ProviderAccountStepper.svelte';
  import { edgesPaths } from './lib/routes';
  import ProviderCard from './simple/ProviderCard.svelte';

  const qc = useQueryClient();
  const providers = providersQuery();
  const usage = providersUsageQuery();
  const edit = searchParam('edit');

  const accounts = $derived(
    [...(providers.data?.accounts ?? [])].sort(
      (a, b) => Number(!a.enabled) - Number(!b.enabled) || a.name.localeCompare(b.name),
    ),
  );
  const usageOf = (id: string) => usage.data?.accounts.find((u) => u.id === id) ?? null;
  const used = $derived(usage.data?.totals.liveEdges ?? null);
  const capacity = $derived(
    usage.data
      ? usage.data.accounts.reduce((n, a) => n + (a.enabled ? a.maxLiveEdges : 0), 0)
      : null,
  );

  function onCreated(accountId: string) {
    invalidateProviders(qc);
    router.navigate(edgesPaths.provider(accountId));
  }
</script>

<SectionHeader
  title="Providers"
  description={used !== null && capacity !== null
    ? `${used} of ${capacity} addresses used across your accounts.`
    : 'The accounts FCP creates addresses in.'}
>
  {#snippet actions()}
    <Button size="sm" onclick={() => (edit.value = 'new')}>Add account</Button>
  {/snippet}
</SectionHeader>

{#if providers.isPending}
  <div class="space-y-2" role="status">
    <span class="sr-only">Loading provider accounts</span>
    <Skeleton class="h-16 w-full" />
    <Skeleton class="h-16 w-full" />
  </div>
{:else if providers.isError}
  <AdminListState error={providers.error} onRetry={() => void providers.refetch()} />
{:else if accounts.length === 0}
  <div class="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
    <p class="mx-auto max-w-prose">
      A provider account is one set of credentials at a cloud or CDN provider, plus the place FCP
      creates addresses in. An account becomes trusted the first time one of its addresses is tried
      with a real session.
    </p>
    <Button class="mt-4" size="sm" onclick={() => (edit.value = 'new')}>Add account</Button>
  </div>
{:else}
  <ul class="space-y-2" aria-label="Provider accounts">
    {#each accounts as a (a.id)}
      <li><ProviderCard account={a} usage={usageOf(a.id)} /></li>
    {/each}
  </ul>
{/if}

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
