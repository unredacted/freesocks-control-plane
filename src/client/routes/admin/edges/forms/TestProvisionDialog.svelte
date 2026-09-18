<script lang="ts">
  /**
   * Provision a TEST edge: the bootstrap path for an account that is tested but
   * not yet qualified (ordinary selection skips such accounts, so a fresh
   * account could never get its first edge). The result is always unpublished.
   * The dry run is shown before the start button.
   *
   * Props:
   *   open: boolean (bindable)
   *   relayId: string
   *   relaySlug: string
   *   accountId?: string | null          preselect (the guided setup's chosen account)
   *   listenerKey?: string | null        preselect
   *   onStarted: (rotationId: string) => void
   */
  import { untrack } from 'svelte';
  import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import * as Dialog from '@client/components/ui/dialog';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import Link from '@client/components/Link.svelte';
  import {
    edgeKeys,
    invalidateProviders,
    invalidateRelay,
    preflightRelay,
    providersQuery,
    relayListenersQuery,
    templatesQuery,
    testProvisionRelay,
  } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import PreflightPanel from '../components/PreflightPanel.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import { protocolLine, providerLabel } from '../lib/format';
  import { edgesPaths } from '../lib/routes';

  interface Props {
    open: boolean;
    relayId: string;
    relaySlug: string;
    accountId?: string | null;
    listenerKey?: string | null;
    onStarted: (rotationId: string) => void;
  }
  let {
    open = $bindable(false),
    relayId,
    relaySlug,
    accountId: accountPreset = null,
    listenerKey: listenerPreset = null,
    onStarted,
  }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const providers = providersQuery();
  const templates = templatesQuery();
  const listeners = relayListenersQuery({
    slug: () => (open ? relaySlug : null),
    id: () => (open && relayId ? relayId : null),
  });

  let accountId = $state('');
  let listenerKey = $state('');
  let templateId = $state('');

  // Tested accounts only: an unqualified one is fine here, an untested one never is.
  const accounts = $derived(
    (providers.data?.accounts ?? []).filter((a) => a.enabled && a.lastTestOkAt !== null),
  );
  const untestedCount = $derived(
    (providers.data?.accounts ?? []).filter((a) => a.enabled && a.lastTestOkAt === null).length,
  );
  const account = $derived(accounts.find((a) => a.id === accountId) ?? null);
  const usableListeners = $derived(
    (listeners.data?.listeners ?? []).filter((l) => !l.retired && l.enabled && l.deployed),
  );
  const listener = $derived(usableListeners.find((l) => l.listenerKey === listenerKey) ?? null);
  const accountTemplates = $derived(
    account
      ? (templates.data?.templates ?? []).filter(
          (t) =>
            t.provider === account.provider && (t.accountId === null || t.accountId === account.id),
        )
      : [],
  );
  const template = $derived(accountTemplates.find((t) => t.id === templateId) ?? null);

  let seeded = false;
  $effect(() => {
    if (!open) {
      seeded = false;
      untrack(() => start.reset());
      return;
    }
    if (seeded) return;
    seeded = true;
    accountId = accountPreset ?? '';
    listenerKey = listenerPreset ?? '';
    templateId = '';
  });
  // Pick the only choice (or drop a stale one) once the lists arrive.
  $effect(() => {
    if (!open) return;
    if (accountId && accounts.length > 0 && !account) accountId = '';
    if (!accountId && accounts.length === 1) accountId = accounts[0]!.id;
    if (listenerKey && usableListeners.length > 0 && !listener) listenerKey = '';
    if (!listenerKey && usableListeners.length === 1) listenerKey = usableListeners[0]!.listenerKey;
    if (templateId && !template) templateId = '';
  });

  const ready = $derived(accountId !== '' && listenerKey !== '');
  const preflight = createQuery(() => ({
    queryKey: [
      ...edgeKeys.relay(relaySlug),
      'preflight',
      'test-provision',
      accountId,
      listenerKey,
      templateId,
    ] as const,
    queryFn: () =>
      preflightRelay(relayId, {
        kind: 'test-provision',
        accountId,
        listenerKey,
        ...(templateId ? { templateId } : {}),
      }),
    enabled: open && ready,
    staleTime: 0,
    gcTime: 0,
    retry: false,
  }));

  const start = createMutation(() => ({
    mutationFn: () =>
      testProvisionRelay(relayId, {
        accountId,
        listenerKey,
        ...(templateId ? { templateId } : {}),
      }),
    onSuccess: (r) => {
      invalidateRelay(qc, relaySlug);
      invalidateProviders(qc);
      toast.success('Test provision started');
      open = false;
      onStarted(r.rotationId);
    },
  }));
  const refusal = $derived(start.error ? edgeErrorIssue(start.error) : null);
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-xl">
    <Dialog.Header>
      <Dialog.Title>Provision a test edge</Dialog.Title>
      <Dialog.Description>
        Creates one real resource at the provider (it is billed like any other) and leaves it
        unpublished, so you can try a session through it before members depend on it.
      </Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4">
      {#if providers.isError}
        <AdminListState error={providers.error} onRetry={() => void providers.refetch()} />
      {:else if !providers.isPending && accounts.length === 0}
        <AdminListState
          emptyText={untestedCount > 0
            ? 'No account has passed a credential test yet. Test an account on the Providers page, then come back.'
            : 'No provider account exists yet. Add one on the Providers page, then come back.'}
        />
        <Link class="text-sm underline underline-offset-2" href={edgesPaths.providers()}>
          Open Providers
        </Link>
      {:else}
        <div class="space-y-1.5">
          <Label for={`${uid}-account`}>Account</Label>
          <Select.Root type="single" bind:value={accountId}>
            <Select.Trigger id={`${uid}-account`} class="w-full">
              {account
                ? `${account.name} (${providerLabel(account.provider)})`
                : 'Choose an account'}
            </Select.Trigger>
            <Select.Content>
              {#each accounts as a (a.id)}
                <Select.Item value={a.id} label={a.name}>
                  {a.name}
                  <span class="text-muted-foreground text-xs">
                    {providerLabel(a.provider)}, {a.qualified
                      ? 'qualified'
                      : 'tested, not qualified'}
                  </span>
                </Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
          <p class="text-muted-foreground text-xs">
            Accounts that passed a credential test. One that is not qualified yet is allowed here.
          </p>
        </div>

        <div class="space-y-1.5">
          <Label for={`${uid}-listener`}>Listener</Label>
          {#if listeners.isError}
            <AdminListState error={listeners.error} onRetry={() => void listeners.refetch()} />
          {:else if !listeners.isPending && usableListeners.length === 0}
            <AdminListState
              emptyText="This relay has no deployed, enabled listener. Add one (or let the node role register it) first."
            />
          {:else}
            <Select.Root type="single" bind:value={listenerKey}>
              <Select.Trigger id={`${uid}-listener`} class="w-full">
                {listener
                  ? `${listener.listenerKey}: ${protocolLine(listener)}`
                  : 'Choose a listener'}
              </Select.Trigger>
              <Select.Content>
                {#each usableListeners as l (l.id)}
                  <Select.Item value={l.listenerKey} label={l.listenerKey}>
                    <span class="font-mono">{l.listenerKey}</span>
                    <span class="text-muted-foreground text-xs">{protocolLine(l)}</span>
                  </Select.Item>
                {/each}
              </Select.Content>
            </Select.Root>
          {/if}
        </div>

        <div class="space-y-1.5">
          <Label for={`${uid}-template`}>Template (optional)</Label>
          <Select.Root
            type="single"
            value={templateId || 'default'}
            onValueChange={(v: string) => (templateId = v === 'default' ? '' : v)}
            disabled={!account}
          >
            <Select.Trigger id={`${uid}-template`} class="w-full">
              {template ? template.name : "The account's default"}
            </Select.Trigger>
            <Select.Content>
              <Select.Item value="default" label="The account's default">
                The account's default
              </Select.Item>
              {#each accountTemplates as t (t.id)}
                <Select.Item value={t.id} label={t.name}>
                  {t.name}
                  {#if t.isDefault}<span class="text-muted-foreground text-xs"
                      >provider default</span
                    >{/if}
                </Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        </div>

        {#if ready}
          <PreflightPanel
            kind="test-provision"
            result={preflight.data}
            pending={preflight.isFetching}
            error={preflight.isError ? preflight.error : undefined}
            onRetry={() => void preflight.refetch()}
          />
        {:else}
          <p class="text-muted-foreground text-sm">
            Choose an account and a listener to see whether the provision can start.
          </p>
        {/if}
      {/if}

      {#if refusal}
        <CodeNote issue={refusal} />
      {:else if start.error}
        <InlineError message={edgeErrorMessage(start.error)} />
      {/if}
    </div>

    <Dialog.Footer>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button
        disabled={!ready || !preflight.data?.ok || preflight.isFetching || start.isPending}
        onclick={() => start.mutate()}
      >
        {start.isPending ? 'Starting' : 'Provision test edge'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
