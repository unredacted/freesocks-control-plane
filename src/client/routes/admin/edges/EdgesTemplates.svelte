<script lang="ts">
  /**
   * All templates (`/admin/servers/providers/templates`). Each provider account
   * also lists the templates it can use on its own Templates tab.
   * URL state: `?template=<id>` opens the editor, `?template=new&provider=<id>`
   * starts a new one. `?provider=<id>` (alone or with `?template=<id>`, the old
   * provider-filtered view) lands on that provider's first account, Templates
   * tab (templates/list.ts `templateRedirect`); with no account of that
   * provider the page stays and shows that provider only.
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { EDGE_PROVIDER_IDS, type EdgeProviderId } from '../../../../shared/contracts/edges';
  import {
    ensureDefaultTemplates,
    invalidateProviders,
    providersQuery,
    templatesQuery,
  } from '../../../lib/edgesApi';
  import { searchParam } from '../../../lib/urlState.svelte';
  import { router } from '../../../stores/router.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import { edgeErrorMessage } from './lib/edgeErrors';
  import { providerLabel } from './lib/format';
  import { edgesPaths } from './lib/routes';
  import TemplatesPanel from './templates/TemplatesPanel.svelte';
  import { templateRedirect } from './templates/list';

  const qc = useQueryClient();
  const templates = templatesQuery();
  const providers = providersQuery();
  const templateParam = searchParam('template');
  const providerParam = searchParam('provider');

  const isProvider = (v: string): v is EdgeProviderId =>
    (EDGE_PROVIDER_IDS as readonly string[]).includes(v);

  // The old provider filter is the account's Templates tab now. It needs the
  // accounts (and, for a template only one account uses, the templates).
  $effect(() => {
    if (!providerParam.value || !providers.data) return;
    if (templateParam.value && templates.isPending) return;
    const to = templateRedirect(
      { provider: providerParam.value, template: templateParam.value },
      providers.data.accounts,
      templates.data?.templates ?? null,
    );
    if (to) router.navigate(to, { replace: true });
  });

  /** Show one provider only (no account of it to land on). */
  const filter = $derived<EdgeProviderId | null>(
    templateParam.value === '' && isProvider(providerParam.value) ? providerParam.value : null,
  );

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
</script>

<SectionHeader
  title="All templates"
  back={{ href: edgesPaths.providers(), label: 'Providers' }}
  description="The parameters an edge is created with at a provider, like plan, timeouts and health checks. An account uses the template it names, or its provider's default. Each account also lists its own on its Templates tab."
>
  {#snippet actions()}
    <Button variant="outline" size="sm" disabled={seed.isPending} onclick={() => seed.mutate()}>
      {seed.isPending ? 'Seeding' : 'Seed defaults'}
    </Button>
  {/snippet}
</SectionHeader>

{#if filter}
  <p class="mb-4 text-sm text-muted-foreground">
    Showing {providerLabel(filter)} only.
    <button class="underline" onclick={() => (providerParam.value = null)}
      >Show every provider</button
    >
  </p>
{/if}

<TemplatesPanel provider={filter} />
