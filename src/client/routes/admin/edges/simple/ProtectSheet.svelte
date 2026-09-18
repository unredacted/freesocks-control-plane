<script lang="ts">
  /**
   * "Protect a node": a sheet with three questions and then the progress.
   *   1. Which node?     a panel, then one of its nodes (already protected ones greyed);
   *                      picking one fetches the plan and shows the inbounds in words
   *   2. Which account?  the plan's compatible accounts as radio cards; "Add account"
   *                      renders the provider stepper inline (compact)
   *   3. Review          one sentence, the consent for unsupported hosts, one button
   * A created run hands over to ProtectProgress (`runId`), which the URL keeps.
   *
   * Props:
   *   open: boolean
   *   runId: string | null              show a run's progress instead of the questions
   *   startAtAccount?: boolean          no provider account exists yet: open on the account step
   *   onRunCreated: (runId: string) => void
   *   onClose: () => void
   */
  import { untrack } from 'svelte';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Sheet from '@client/components/ui/sheet';
  import * as Select from '@client/components/ui/select';
  import * as Collapsible from '@client/components/ui/collapsible';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { adminBackendServersQuery } from '@client/lib/queries';
  import { createSetupRun, nodeCandidatesQuery, planSetupRun } from '@client/lib/edgesApi';
  import { countryName } from '@client/lib/countries';
  import { SETUP_ACCOUNT_REASON_COPY, inboundUnsupportedCopy } from '@client/lib/edgeCodes';
  import type { SetupPlanResponse } from '@shared/contracts/edges';
  import { ListenerSpec } from '@shared/contracts/edges';
  import type { SetupAccountReason } from '@shared/contracts/edgeCodes';
  import AdminListState from '../../AdminListState.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import ProviderAccountStepper from '../forms/ProviderAccountStepper.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import { protocolLine, providerLabel } from '../lib/format';
  import { edgesPaths } from '../lib/routes';
  import { router } from '@client/stores/router.svelte';
  import ProtectProgress from './ProtectProgress.svelte';
  import { planWords } from './runWords';

  interface Props {
    open: boolean;
    runId: string | null;
    startAtAccount?: boolean;
    onRunCreated: (runId: string) => void;
    onClose: () => void;
  }
  let { open, runId, startAtAccount = false, onRunCreated, onClose }: Props = $props();

  type Step = 'node' | 'account' | 'review';
  // With no provider account at all the flow opens on the account step (adding one).
  const noAccountYet = untrack(() => startAtAccount);
  let step = $state<Step>(noAccountYet ? 'account' : 'node');
  let addingAccount = $state(noAccountYet);

  // 1. Which node?
  const servers = adminBackendServersQuery();
  const panels = $derived((servers.data ?? []).filter((s) => s.config.type === 'remnawave'));
  let serverId = $state('');
  $effect(() => {
    if (serverId === '' && panels.length === 1) serverId = panels[0]!.id;
  });
  const candidates = nodeCandidatesQuery(() => serverId || null);
  const nodes = $derived(
    [...(candidates.data?.nodes ?? [])].sort((a, b) => a.name.localeCompare(b.name)),
  );
  let nodeUuid = $state('');
  let plan = $state<SetupPlanResponse | null>(null);
  const planM = createMutation(() => ({
    mutationFn: (uuid: string) => planSetupRun(serverId, uuid),
    onSuccess: (p) => {
      plan = p;
      if (p.activeRunId) onRunCreated(p.activeRunId);
    },
  }));
  function pickNode(uuid: string) {
    nodeUuid = uuid;
    plan = null;
    accountId = '';
    planM.mutate(uuid);
  }
  const planIssue = $derived(planM.error ? edgeErrorIssue(planM.error) : null);
  const inboundLine = (i: SetupPlanResponse['inbounds'][number]): string => {
    const parsed = ListenerSpec.safeParse(i.listenerSpec);
    return parsed.success ? protocolLine(parsed.data) : i.sourceTag;
  };
  const supported = $derived(plan?.inbounds.filter((i) => i.frontable) ?? []);
  const unsupported = $derived(plan?.inbounds.filter((i) => !i.frontable) ?? []);

  // 2. Which account?
  let accountId = $state('');
  const accounts = $derived(plan?.accounts ?? []);
  const compatible = $derived(accounts.filter((a) => a.compatible));
  const reasonWords = (reasons: string[]): string =>
    reasons
      .map(
        (r) =>
          (SETUP_ACCOUNT_REASON_COPY as Record<string, { label: string }>)[r as SetupAccountReason]
            ?.label ?? r,
      )
      .join(', ');
  function onAccountCreated(id: string) {
    addingAccount = false;
    accountId = id;
    // The plan judges accounts: re-read it so the new one appears with its verdict.
    if (nodeUuid) planM.mutate(nodeUuid);
    else step = 'node';
  }

  // 3. Review
  const account = $derived(accounts.find((a) => a.id === accountId) ?? null);
  const words = $derived(plan && account ? planWords(plan, account.name) : null);
  const create = createMutation(() => ({
    mutationFn: (keepDirect: boolean) =>
      createSetupRun({
        backendServerId: plan!.backendServerId,
        nodeUuid: plan!.nodeUuid,
        accountId,
        planHash: plan!.planHash,
        approvedHideUuids: keepDirect ? [] : (words?.uncovered?.uuids ?? []),
        ...(keepDirect ? { keepDirect: true } : {}),
      }),
    onSuccess: (r) => {
      toast.success('Protecting the node.');
      onRunCreated(r.runId);
    },
    onError: (e) => toast.error(edgeErrorMessage(e)),
  }));

  const canContinue = $derived(
    step === 'node'
      ? plan !== null && !plan.tooManyInbounds
      : step === 'account'
        ? !!account
        : false,
  );
  function next() {
    if (step === 'node') step = 'account';
    else if (step === 'account') step = 'review';
  }
  function back() {
    if (step === 'review') step = 'account';
    else if (step === 'account') step = 'node';
  }
  const TITLES: Record<Step, string> = {
    node: 'Which node?',
    account: 'Which account?',
    review: 'Review',
  };
  const CARD =
    'has-[:checked]:border-primary has-[:checked]:bg-primary/5 flex cursor-pointer items-start gap-3 rounded-md border p-3 has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-60';
</script>

<Sheet.Root
  {open}
  onOpenChange={(o) => {
    if (!o) onClose();
  }}
>
  <Sheet.Content side="right" class="gap-0 sm:max-w-xl">
    <Sheet.Header class="border-b">
      <Sheet.Title>{runId ? 'Protecting the node' : TITLES[step]}</Sheet.Title>
      <Sheet.Description>
        {#if runId}
          You can close this. It keeps going.
        {:else if step === 'node'}
          Pick the node members should reach through a provider address instead of its own.
        {:else if step === 'account'}
          The provider account the address is created in. Only accounts that can carry every inbound
          are offered.
        {:else}
          One last look before anything is created.
        {/if}
      </Sheet.Description>
    </Sheet.Header>

    <div class="flex-1 space-y-4 overflow-y-auto p-4">
      {#if runId}
        <ProtectProgress {runId} {onClose} />
      {:else if step === 'node'}
        {#if servers.isPending}
          <Skeleton class="h-10 w-full" />
        {:else if servers.isError}
          <AdminListState error={servers.error} onRetry={() => void servers.refetch()} />
        {:else if panels.length === 0}
          <AdminListState
            emptyText="No panel is registered yet. Add a Remnawave backend server first, under Servers."
          />
        {:else}
          {#if panels.length > 1}
            <div class="space-y-1.5">
              <span class="text-sm font-medium">Panel</span>
              <Select.Root
                type="single"
                value={serverId}
                onValueChange={(v) => {
                  serverId = v;
                  nodeUuid = '';
                  plan = null;
                }}
              >
                <Select.Trigger class="w-full">
                  {panels.find((p) => p.id === serverId)?.name ?? 'Choose a panel'}
                </Select.Trigger>
                <Select.Content>
                  {#each panels as p (p.id)}
                    <Select.Item value={p.id} label={p.name}>{p.name}</Select.Item>
                  {/each}
                </Select.Content>
              </Select.Root>
            </div>
          {/if}
          {#if serverId}
            {#if candidates.isPending}
              <Skeleton class="h-24 w-full" />
            {:else if candidates.isError}
              <AdminListState error={candidates.error} onRetry={() => void candidates.refetch()} />
            {:else if nodes.length === 0}
              <AdminListState emptyText="This panel has no nodes yet." />
            {:else}
              <fieldset class="space-y-2">
                <legend class="sr-only">Node</legend>
                {#each nodes as n (n.nodeUuid)}
                  {@const taken = n.relaySlug !== null}
                  <label class={CARD}>
                    <input
                      type="radio"
                      name="protect-node"
                      class="accent-primary mt-1"
                      value={n.nodeUuid}
                      checked={nodeUuid === n.nodeUuid}
                      disabled={taken}
                      onchange={() => pickNode(n.nodeUuid)}
                    />
                    <span class="min-w-0 flex-1">
                      <span class="block font-medium">{n.name}</span>
                      <span class="text-muted-foreground block text-xs">
                        {n.countryCode ? countryName(n.countryCode, 'en') : 'Country unknown'}
                        {#if taken}
                          <span class="mx-1" aria-hidden="true">·</span>Already protected
                        {:else if !n.online}
                          <span class="mx-1" aria-hidden="true">·</span>Offline
                        {/if}
                      </span>
                    </span>
                  </label>
                {/each}
              </fieldset>
            {/if}
          {/if}
          {#if planM.isPending}
            <p class="text-muted-foreground text-sm" role="status">Looking at the node.</p>
          {:else if planIssue}
            <CodeNote issue={planIssue} />
          {:else if planM.isError}
            <AdminListState error={planM.error} onRetry={() => planM.mutate(nodeUuid)} />
          {:else if plan}
            <div class="space-y-3 rounded-md border p-3 text-sm">
              {#if plan.tooManyInbounds}
                <CodeNote issue={{ code: 'too_many_inbounds' }} />
              {:else if supported.length === 0}
                <p>
                  No inbound on this node can be carried by a provider address yet. It cannot be
                  protected this way.
                </p>
              {:else}
                <p class="font-medium">
                  {supported.length === 1 ? 'This inbound gets' : 'These inbounds get'} a protected address
                </p>
                <ul class="space-y-1">
                  {#each supported as i (i.listenerKey)}
                    <li>
                      <span class="font-medium">{i.listenerKey}</span>
                      <span class="text-muted-foreground">{inboundLine(i)}</span>
                    </li>
                  {/each}
                </ul>
                <p class="text-muted-foreground text-xs">
                  {planWords(plan, '').formats}
                </p>
              {/if}
              {#if unsupported.length > 0}
                <Collapsible.Root>
                  <Collapsible.Trigger
                    class="group text-muted-foreground hover:text-foreground flex items-center gap-1 text-sm"
                  >
                    <ChevronRight
                      class="size-4 transition-transform group-data-[state=open]:rotate-90"
                      aria-hidden="true"
                    />
                    Not supported yet ({unsupported.length})
                  </Collapsible.Trigger>
                  <Collapsible.Content class="space-y-2 pt-2">
                    {#each unsupported as i (i.listenerKey)}
                      {@const copy = inboundUnsupportedCopy(i.reason ?? 'invalid')}
                      <p>
                        <span class="font-medium">{i.sourceTag}</span>: {copy.label}.
                        <span class="text-muted-foreground">{copy.explain}</span>
                      </p>
                    {/each}
                  </Collapsible.Content>
                </Collapsible.Root>
              {/if}
            </div>
          {/if}
        {/if}
      {:else if step === 'account'}
        {#if addingAccount}
          <ProviderAccountStepper
            compact
            onCreated={onAccountCreated}
            onCancel={accounts.length > 0 ? () => (addingAccount = false) : undefined}
          />
        {:else}
          {#if accounts.length === 0}
            <p class="text-muted-foreground text-sm">
              No provider account yet. Add one: FCP creates the addresses in it.
            </p>
          {:else}
            <fieldset class="space-y-2">
              <legend class="sr-only">Provider account</legend>
              {#each accounts as a (a.id)}
                <label class={CARD}>
                  <input
                    type="radio"
                    name="protect-account"
                    class="accent-primary mt-1"
                    value={a.id}
                    checked={accountId === a.id}
                    disabled={!a.compatible}
                    onchange={() => (accountId = a.id)}
                  />
                  <span class="min-w-0 flex-1">
                    <span class="block font-medium">{a.name}</span>
                    <span class="text-muted-foreground block text-xs">
                      {providerLabel(a.provider)}
                      {#if !a.compatible}
                        <span class="mx-1" aria-hidden="true">·</span>{reasonWords(a.reasons)}
                      {/if}
                    </span>
                  </span>
                </label>
              {/each}
            </fieldset>
            {#if compatible.length === 0}
              <p class="text-muted-foreground text-xs">
                No account can carry this node's inbounds as it is. Fix one above or add another.
              </p>
            {/if}
          {/if}
          <Button variant="outline" size="sm" onclick={() => (addingAccount = true)}>
            Add account
          </Button>
        {/if}
      {:else if words && plan}
        <p class="text-sm">{words.sentence}</p>
        {#if words.uncovered}
          <div class="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
            <p>{words.uncovered.statement}</p>
            <p class="text-muted-foreground mt-1 text-xs">{words.uncovered.remarks.join(', ')}</p>
          </div>
        {/if}
        {#if words.renderGlobal}
          <p class="text-muted-foreground text-sm">{words.renderGlobal}</p>
        {/if}
        {#if plan.familiesDisabled.length > 0}
          <p class="text-muted-foreground text-sm">
            Protected delivery is off for {plan.familiesDisabled.join(', ')} clients. The run asks you
            to turn it on before going live.
          </p>
        {/if}
        {#if plan.existingRelay}
          <p class="text-muted-foreground text-sm">
            An earlier attempt left this node half set up. The run picks up where it stopped.
          </p>
        {/if}
      {/if}
    </div>

    {#if !runId}
      <Sheet.Footer class="flex-row flex-wrap items-center gap-2 border-t">
        {#if step === 'review' && words}
          <Button disabled={create.isPending} onclick={() => create.mutate(false)}>
            {create.isPending ? 'Starting' : words.button}
          </Button>
          {#if words.uncovered}
            <Button variant="ghost" disabled={create.isPending} onclick={() => create.mutate(true)}>
              Keep those members on the direct address
            </Button>
          {/if}
        {:else if !(step === 'account' && addingAccount)}
          <Button disabled={!canContinue} onclick={next}>Continue</Button>
        {/if}
        {#if step !== 'node' && !(step === 'account' && addingAccount)}
          <Button variant="ghost" onclick={back}>Back</Button>
        {/if}
        {#if plan?.tooManyInbounds}
          <Button variant="outline" onclick={() => router.navigate(edgesPaths.setup())}>
            Use manual setup
          </Button>
        {/if}
      </Sheet.Footer>
    {/if}
  </Sheet.Content>
</Sheet.Root>
