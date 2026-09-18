<script lang="ts">
  /**
   * Step 2, provider account. No account yet: the account stepper inline. An
   * untested or failed one: "Test again" right here.
   *
   * Props: StepBodyProps
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button, buttonVariants } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import {
    invalidateProviders,
    providersQuery,
    testProviderCredentials,
  } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import LayerBadge from '../components/LayerBadge.svelte';
  import FakeBadge from '../components/FakeBadge.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import ProviderAccountStepper from '../forms/ProviderAccountStepper.svelte';
  import { EDGE_PROVIDER_META } from '@client/lib/edgeProviderMeta';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { providerLabel } from '../lib/format';
  import { relativeTime } from '../lib/time';
  import { edgesPaths } from '../lib/routes';
  import StepIssues from './StepIssues.svelte';
  import { factString, type StepBodyProps } from './types';

  let { step, linkCtx }: StepBodyProps = $props();

  const qc = useQueryClient();
  const providers = providersQuery();
  const accounts = $derived((providers.data?.accounts ?? []).filter((a) => a.enabled));
  const chosen = $derived(factString(step.facts, 'chosen'));
  let adding = $state(false);

  let lastResult = $state<Record<string, { ok: boolean; code: string | null }>>({});
  const test = createMutation(() => ({
    mutationFn: (accountId: string) => testProviderCredentials(accountId),
    onSuccess: (r, accountId) => {
      lastResult = { ...lastResult, [accountId]: { ok: r.ok, code: r.code } };
      invalidateProviders(qc);
      if (r.ok) toast.success('Credentials work');
      else toast.error('The credential test failed');
    },
    onError: (err: unknown) =>
      toast.error('The test could not run', { description: edgeErrorMessage(err) }),
  }));
</script>

<div class="space-y-4">
  <StepIssues {step} ctx={linkCtx} hide={accounts.length === 0 ? ['no_provider_account'] : []} />

  {#if providers.isError}
    <AdminListState error={providers.error} onRetry={() => void providers.refetch()} />
  {:else if !providers.isPending && accounts.length === 0}
    <p class="text-sm">
      No provider account exists yet. Add the cloud or CDN account the edges will be created in.
    </p>
    <ProviderAccountStepper onCreated={() => invalidateProviders(qc)} />
  {:else}
    <ul class="divide-y rounded-lg border">
      {#each accounts as a (a.id)}
        {@const failed = a.lastTestOkAt === null && a.lastTestError !== null}
        {@const result = lastResult[a.id]}
        <li class="space-y-2 p-3">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-medium">{a.name}</span>
            <span class="text-muted-foreground text-sm">{providerLabel(a.provider)}</span>
            <LayerBadge layer={EDGE_PROVIDER_META[a.provider].layer} />
            <FakeBadge fake={a.fake} />
            {#if a.lastTestOkAt}
              <StatusBadge
                kind="setup"
                value="done"
                label={`Tested ${relativeTime(a.lastTestOkAt)}`}
              />
            {:else}
              <StatusBadge
                kind="setup"
                value="blocked"
                label={failed ? 'Last test failed' : 'Never tested'}
              />
            {/if}
            {#if a.qualified}<StatusBadge kind="setup" value="done" label="Qualified" />{/if}
            {#if chosen === a.name}
              <span class="text-muted-foreground text-xs">used for this setup</span>
            {/if}
            <span class="ms-auto flex gap-1.5">
              <Button
                size="sm"
                variant={a.lastTestOkAt ? 'outline' : 'default'}
                disabled={test.isPending}
                onclick={() => test.mutate(a.id)}
              >
                {test.isPending && test.variables === a.id
                  ? 'Testing'
                  : a.lastTestOkAt
                    ? 'Test again'
                    : failed
                      ? 'Test again'
                      : 'Test credentials'}
              </Button>
              <Link
                href={edgesPaths.provider(a.id)}
                class={buttonVariants({ size: 'sm', variant: 'ghost' })}
              >
                Open
              </Link>
            </span>
          </div>
          {#if result && !result.ok}
            <CodeNote
              compact
              issue={{ code: result.code ?? 'credentials_failed', subject: a.name }}
            />
          {/if}
        </li>
      {/each}
    </ul>
    {#if adding}
      <div class="rounded-lg border p-3">
        <ProviderAccountStepper
          onCreated={() => {
            adding = false;
            invalidateProviders(qc);
          }}
          onCancel={() => (adding = false)}
        />
      </div>
    {:else}
      <Button variant="outline" size="sm" onclick={() => (adding = true)}
        >Add another account</Button
      >
    {/if}
  {/if}
</div>
