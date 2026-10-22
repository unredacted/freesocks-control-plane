<script lang="ts">
  /**
   * What an account's credentials reach at the provider, as last listed (its
   * catalog: DNS zones, regions, projects, TLS configurations): the menu the
   * location pickers offer when a node is protected, an address added or
   * replaced. Listed after a passing credential test, on Refresh, and when a
   * picker finds it old. A front that writes its records through a DNS account
   * is told where to add one when none exists.
   *
   * Props:
   *   account: EdgeProviderAccountAdmin
   *   dnsAccountsExist: boolean    (a front provider only) whether any DNS account exists
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Link from '@client/components/Link.svelte';
  import { Button } from '@client/components/ui/button';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import InlineError from '@client/components/InlineError.svelte';
  import {
    EDGE_PROVIDER_IDS,
    type EdgeCatalogEntry,
    type EdgeProviderAccountAdmin,
  } from '@shared/contracts/edges';
  import { edgeKeys, providerCatalogQuery, refreshProviderCatalog } from '@client/lib/edgesApi';
  import { EDGE_PROVIDER_META, providerGroups } from '@client/lib/edgeProviderMeta';
  import CodeNote from '../components/CodeNote.svelte';
  import ProviderAnswer from '../components/ProviderAnswer.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';
  import { catalogAge, zoneChoices } from '../forms/zones';

  interface Props {
    account: EdgeProviderAccountAdmin;
    dnsAccountsExist?: boolean;
  }
  let { account, dnsAccountsExist = true }: Props = $props();

  const qc = useQueryClient();
  const meta = $derived(EDGE_PROVIDER_META[account.provider]);
  const catalog = providerCatalogQuery(() => account.id);
  const firstDnsProvider = providerGroups(EDGE_PROVIDER_IDS).find((g) => g.id === 'dns')
    ?.providers[0];

  const LABELS: Record<string, string> = {
    zones: 'DNS zones',
    regions: 'Regions',
    projects: 'Projects',
    tlsConfigurations: 'TLS configurations',
  };
  const kinds = $derived(
    Object.entries(catalog.data?.kinds ?? {}).filter(
      (e): e is [string, EdgeCatalogEntry] => e[1] !== undefined,
    ),
  );
  const zones = $derived(zoneChoices(catalog.data, account.locations));
  const at = $derived(catalogAge(catalog.data));

  const refresh = createMutation(() => ({
    mutationFn: () => refreshProviderCatalog(account.id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: edgeKeys.providerCatalog(account.id) });
      toast.success('Listed again');
    },
  }));
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">What this account reaches</CardTitle>
    <CardDescription>
      {meta.layer === 'l7' || meta.providesDns
        ? 'The zones and configurations these credentials reach. Any of them can be picked when you protect a node; a zone becomes a location the first time it is picked.'
        : 'What these credentials can use at the provider. A region becomes a location the first time it is picked for a node, or when you add it here.'}
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-3">
    {#if meta.needsDnsAccount && !dnsAccountsExist}
      <p class="text-sm">
        Its fronts write their names into a zone of a DNS account, and none exists yet.
        <Link
          href={edgesPaths.providers({ edit: 'new', provider: firstDnsProvider })}
          class="text-primary underline underline-offset-4">Add a DNS account</Link
        >.
      </p>
    {/if}
    {#if catalog.isPending}
      <p class="text-muted-foreground text-sm" role="status">Reading the stored lists.</p>
    {:else if catalog.isError}
      <InlineError message={edgeErrorMessage(catalog.error)} />
    {:else if kinds.length === 0}
      <p class="text-muted-foreground text-sm">
        Nothing is listed yet. Refresh, or test the credentials, to list it.
      </p>
    {:else}
      <ul class="text-sm">
        {#each kinds as [kind, entry] (kind)}
          <li>
            <span class="text-muted-foreground">{LABELS[kind] ?? kind}:</span>
            {entry.items.length === 0 ? 'none' : entry.items.length}{entry.truncated
              ? ' (more exist than are listed)'
              : ''}
          </li>
        {/each}
      </ul>
      {#if zones.length > 0}
        <p class="text-muted-foreground font-mono text-xs">
          {zones
            .slice(0, 12)
            .map((z) => (z.status && z.status !== 'active' ? `${z.name} (${z.status})` : z.name))
            .join(', ')}{zones.length > 12 ? ', ...' : ''}
        </p>
      {/if}
      {#each kinds.filter(([, e]) => e.error) as [kind, entry] (kind)}
        <CodeNote
          tone="warning"
          issue={{
            code: entry.error!,
            subject: LABELS[kind] ?? kind,
            detail: 'The last listing failed; the list above is from before.',
          }}
        />
        <ProviderAnswer detail={entry.errorDetail ?? undefined} />
      {/each}
    {/if}
    <div class="flex flex-wrap items-center gap-2">
      <Button
        size="sm"
        variant="outline"
        class="h-11 sm:h-8"
        disabled={refresh.isPending}
        onclick={() => refresh.mutate()}
      >
        {refresh.isPending ? 'Listing' : 'Refresh'}
      </Button>
      {#if at}
        <span class="text-muted-foreground text-xs">Listed {relativeTime(at)}.</span>
      {/if}
    </div>
    {#if refresh.isError}<InlineError message={edgeErrorMessage(refresh.error)} />{/if}
  </CardContent>
</Card>
