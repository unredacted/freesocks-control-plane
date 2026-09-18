<script lang="ts">
  /**
   * Step 3, template. Seed the compiled defaults as editable rows, or review
   * them on the Templates page.
   *
   * Props: StepBodyProps
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button, buttonVariants } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import {
    ensureDefaultTemplates,
    invalidateProviders,
    templatesQuery,
  } from '@client/lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { providerLabel } from '../lib/format';
  import { edgesPaths } from '../lib/routes';
  import StepIssues from './StepIssues.svelte';
  import { factString, type StepBodyProps } from './types';

  let { step, linkCtx }: StepBodyProps = $props();

  const qc = useQueryClient();
  const templates = templatesQuery();
  const provider = $derived(factString(step.facts, 'provider'));
  const templateId = $derived(factString(step.facts, 'templateId'));
  const template = $derived(
    templateId ? (templates.data?.templates.find((t) => t.id === templateId) ?? null) : null,
  );
  const providerTemplates = $derived(
    provider ? (templates.data?.templates ?? []).filter((t) => t.provider === provider) : [],
  );

  const seed = createMutation(() => ({
    mutationFn: ensureDefaultTemplates,
    onSuccess: (r) => {
      invalidateProviders(qc);
      toast.success(
        r.created === 0
          ? 'Every provider already has its default template'
          : `${r.created} default ${r.created === 1 ? 'template' : 'templates'} added`,
      );
    },
    onError: (err: unknown) =>
      toast.error('Could not seed the defaults', { description: edgeErrorMessage(err) }),
  }));
</script>

<div class="space-y-4">
  <StepIssues {step} ctx={linkCtx} />

  <p class="text-sm">
    A template holds the resource settings every new edge is built from (size, health check,
    timeouts). Each provider ships compiled defaults, so an edge can be built without any row.
    Seeding turns those defaults into rows you can read and edit.
  </p>

  {#if provider}
    <p class="text-sm">
      {#if template}
        The chosen account uses the template <span class="font-medium">{template.name}</span>.
      {:else if providerTemplates.length > 0}
        {providerLabel(provider)} has {providerTemplates.length}
        {providerTemplates.length === 1 ? 'template' : 'templates'}; the account uses the provider
        default.
      {:else}
        {providerLabel(provider)} has no template row yet, so the compiled defaults apply.
      {/if}
    </p>
  {/if}

  <div class="flex flex-wrap gap-2">
    <Button disabled={seed.isPending} onclick={() => seed.mutate()}>
      {seed.isPending ? 'Seeding' : 'Seed defaults'}
    </Button>
    <Link
      href={edgesPaths.templates(provider ? { provider } : undefined)}
      class={buttonVariants({ variant: 'outline' })}
    >
      Review differences
    </Link>
  </div>
  <p class="text-muted-foreground text-xs">
    Changing the template an account uses clears its qualification, because new edges would no
    longer match what was proven.
  </p>
</div>
