<script lang="ts">
  /**
   * A guided run's progress: four plain stages, the elapsed time, one live line
   * from the latest event, and the interruption card (one sentence, one button,
   * at most one secondary) when the run needs you. Polls the run every 3 s.
   *
   * Props: runId; onClose()
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Check from '@lucide/svelte/icons/check';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as Select from '@client/components/ui/select';
  import { router } from '@client/stores/router.svelte';
  import { adminConnectionModesQuery } from '@client/lib/queries';
  import {
    cancelSetupRun,
    continueSetupRun,
    edgeConfigQuery,
    invalidateConfig,
    invalidateOverview,
    patchEdgeConfig,
    retrySetupRun,
    setupRunQuery,
    testProviderCredentials,
    thawMaintenance,
    updateRelay,
  } from '@client/lib/edgesApi';
  import { codeLabel, plainWords, setupRunNeedCopy } from '@client/lib/edgeCodes';
  import type { SetupRunContinueBody, SetupRunRetryBody } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import { durationLabel } from '../lib/time';
  import { cn } from '@client/lib/utils';
  import TestCard from './TestCard.svelte';
  import { PLAIN_STAGES, plainStage, runIsLive } from './nodeStatus';
  import { needButtons, runTestItems, type NeedAction, type TestItem } from './runWords';

  interface Props {
    runId: string;
    onClose: () => void;
  }
  let { runId, onClose }: Props = $props();

  const qc = useQueryClient();
  const runQ = setupRunQuery(() => runId);
  const run = $derived(runQ.data ?? null);
  const live = $derived(run ? runIsLive(run) : false);
  const step = $derived(run ? plainStage(run.stage) : 1);
  const need = $derived(run?.state === 'needs_you' && run.need ? run.need : null);
  const needCopy = $derived(need ? setupRunNeedCopy(need.code) : null);
  const buttons = $derived(need ? needButtons(need.code) : null);
  const latest = $derived(run?.events.at(-1) ?? null);

  // Elapsed, ticking while live.
  let now = $state(Date.now());
  $effect(() => {
    if (!live) return;
    const t = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(t);
  });
  const elapsed = $derived(
    run
      ? durationLabel(
          (run.finishedAt ? new Date(run.finishedAt).getTime() : now) -
            new Date(run.startedAt).getTime(),
        )
      : '',
  );

  const refresh = () => {
    void runQ.refetch();
    invalidateOverview(qc);
  };
  const act = createMutation(() => ({
    mutationFn: (job: () => Promise<unknown>) => job(),
    onSuccess: refresh,
    onError: (e) => toast.error(edgeErrorMessage(e)),
  }));
  const retry = (body: SetupRunRetryBody = {}) => act.mutate(() => retrySetupRun(runId, body));
  const cont = (body: SetupRunContinueBody = {}) => act.mutate(() => continueSetupRun(runId, body));

  // try_it: the ticks are collected here and sent together with Continue.
  const items = $derived<TestItem[]>(run ? runTestItems(run) : []);
  let ticked = $state(new Map<string, TestItem>());
  const allTicked = $derived(items.length > 0 && items.every((i) => ticked.has(i.edgeId)));
  $effect(() => {
    // A new card (new generation or rebuilt links) starts blank.
    void run?.generation;
    void run?.testLinks;
    ticked = new Map();
  });

  // Secondary pickers.
  let choosingAccount = $state(false);
  let choosingMode = $state(false);
  let modeSlug = $state('');
  const modes = adminConnectionModesQuery();
  const config = edgeConfigQuery();
  const family = $derived(need?.detail ?? run?.plan.familiesDisabled[0] ?? null);

  function perform(action: NeedAction) {
    switch (action) {
      case 'retry':
        return retry();
      case 'retry_another_address':
        return retry({ tryAnotherAddress: true });
      case 'accept_partial':
        return retry({ acceptPartial: true });
      case 'choose_account':
        choosingAccount = true;
        return;
      case 'test_account':
        return act.mutate(async () => {
          const t = await testProviderCredentials(run!.accountId);
          if (!t.ok) throw new Error(t.code ? codeLabel(t.code) : 'The credential test failed.');
          await retrySetupRun(runId, {});
        });
      case 'thaw':
        return act.mutate(async () => {
          await thawMaintenance();
          invalidateConfig(qc);
          await retrySetupRun(runId, {});
        });
      case 'manual_setup':
        router.navigate(edgesPaths.setup({ relay: run?.relaySlug ?? null }));
        return;
      case 'choose_mode':
        choosingMode = true;
        return;
      case 'continue':
        return cont({
          confirmations: [...ticked.values()].map((t) => ({
            edgeId: t.edgeId,
            endpoint: t.endpoint,
            listenerRevision: t.listenerRevision,
            configHash: t.configHash,
          })),
        });
      case 'review':
        // The review re-opens below (the delta); nothing to call yet.
        return;
      case 'family':
        return act.mutate(async () => {
          const fam = family;
          const rule = fam ? config.data?.config.render.clients[fam] : undefined;
          if (!fam || !rule) throw new Error('Which client family is off is not known yet.');
          await patchEdgeConfig({ [`render.clients.${fam}`]: { ...rule, enabled: true } });
          invalidateConfig(qc);
          await continueSetupRun(runId, {});
        });
      case 'quarantine':
        if (run?.relaySlug) router.navigate(edgesPaths.relay(run.relaySlug, { tab: 'rotations' }));
        return;
    }
  }
  const cancel = () =>
    act.mutate(async () => {
      const r = await cancelSetupRun(runId);
      toast.message(
        r.disposition === 'deleted'
          ? 'Cancelled. Nothing was changed for members.'
          : r.disposition === 'restore'
            ? 'Cancelled. The direct address is being put back.'
            : 'Cancelled.',
      );
    });
</script>

{#if runQ.isPending}
  <Skeleton class="h-40 w-full" />
{:else if runQ.isError || !run}
  <AdminListState error={runQ.error} onRetry={() => void runQ.refetch()} />
{:else}
  <ol class="space-y-2" aria-label="Progress">
    {#each PLAIN_STAGES as label, i (label)}
      {@const n = i + 1}
      {@const state = n < step ? 'done' : n === step && live ? 'now' : 'todo'}
      <li class="flex items-center gap-3 text-sm">
        <span
          class={cn(
            'flex size-6 shrink-0 items-center justify-center rounded-full border text-xs',
            state === 'done' && 'border-emerald-500 bg-emerald-500 text-white',
            state === 'now' && 'border-primary text-primary',
            state === 'todo' && 'text-muted-foreground',
          )}
          aria-hidden="true"
        >
          {#if state === 'done'}<Check class="size-3.5" />{:else}{n}{/if}
        </span>
        <span
          class={cn(state === 'now' && 'font-medium', state === 'todo' && 'text-muted-foreground')}
        >
          {label}
          {#if state === 'now'}<span class="sr-only"> (now)</span>{/if}
        </span>
      </li>
    {/each}
  </ol>

  <p class="text-muted-foreground text-sm" aria-live="polite">
    {#if run.state === 'done'}
      Live after {elapsed}.
    {:else if run.state === 'done_unbound'}
      Finished after {elapsed}. Members keep the direct address; go live from the node page when you
      are ready.
    {:else if run.state === 'failed'}
      Stopped after {elapsed}.
    {:else if run.state === 'cancelled'}
      Cancelled after {elapsed}.
    {:else}
      {elapsed} so far.
      {#if latest}{plainWords(codeLabel(latest.code))}{#if latest.detail}: {latest.detail}{/if}.{/if}
    {/if}
  </p>

  {#if run.state === 'done'}
    <div class="rounded-md border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm">
      New subscription downloads on {run.nodeName} use the protected address. A configuration someone
      copied by hand keeps working until they re-import it.
    </div>
  {:else if run.state === 'failed'}
    <CodeNote issue={{ code: run.need?.code ?? 'provider_failed' }} />
    {#if run.need?.detail}
      <CodeNote compact tone="warning" issue={{ code: run.need.detail }} />
    {/if}
    <div class="flex gap-2">
      <Button disabled={act.isPending} onclick={() => retry()}>Try again</Button>
    </div>
  {:else if need && needCopy && buttons}
    <div class="space-y-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
      <p class="font-medium">{needCopy.label}</p>
      <!-- The test card carries its own instruction line. -->
      {#if need.code !== 'try_it'}<p>{needCopy.explain}</p>{/if}
      {#if need.code === 'provider_failed' && need.detail}
        <CodeNote compact tone="warning" issue={{ code: need.detail }} />
      {/if}

      {#if need.code === 'try_it'}
        <TestCard
          {items}
          done={new Set(ticked.keys())}
          onWorks={(item) => (ticked = new Map([...ticked, [item.edgeId, item]]))}
        />
      {:else if need.code === 'review_changed'}
        <p>
          {run.reviewDelta.length === 1
            ? 'One more host in the panel uses an inbound the address cannot carry:'
            : `${run.reviewDelta.length} more hosts in the panel use an inbound the address cannot carry:`}
          <span class="text-muted-foreground"
            >{run.reviewDelta.map((d) => d.remark).join(', ')}</span
          >
        </p>
      {/if}

      {#if choosingAccount}
        <fieldset class="space-y-2">
          <legend class="text-xs font-medium">Another account</legend>
          {#each run.plan.accounts.filter((a) => a.compatible) as a (a.id)}
            <Button
              size="sm"
              variant="outline"
              disabled={act.isPending || a.id === run.accountId}
              onclick={() => {
                choosingAccount = false;
                retry({ accountId: a.id });
              }}
            >
              {a.name}
            </Button>
          {/each}
        </fieldset>
      {:else if choosingMode}
        <div class="space-y-2">
          <Select.Root type="single" value={modeSlug} onValueChange={(v) => (modeSlug = v)}>
            <Select.Trigger class="w-full">
              {(modes.data?.modes ?? []).find((m) => m.id === modeSlug)?.label ??
                'Choose a connection mode'}
            </Select.Trigger>
            <Select.Content>
              {#each modes.data?.modes ?? [] as m (m.id)}
                <Select.Item value={m.id} label={m.label ?? m.id}>{m.label ?? m.id}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
          <Button
            size="sm"
            disabled={!modeSlug || !run.relayId || act.isPending}
            onclick={() =>
              act.mutate(async () => {
                await updateRelay(run.relayId!, { qualificationModeSlug: modeSlug });
                choosingMode = false;
                await retrySetupRun(runId, {});
              })}
          >
            Use this mode
          </Button>
        </div>
      {:else if need.code === 'review_changed'}
        <div class="flex flex-wrap gap-2">
          <Button
            size="sm"
            disabled={act.isPending}
            onclick={() =>
              cont({
                approvedHideUuids: [
                  ...run.approvedHideUuids,
                  ...run.reviewDelta.map((d) => d.uuid),
                ],
              })}
          >
            Protect and hide {run.reviewDelta.length} unsupported {run.reviewDelta.length === 1
              ? 'host'
              : 'hosts'}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={act.isPending}
            onclick={() => cont({ keepDirect: true })}
          >
            Keep those members on the direct address
          </Button>
        </div>
      {:else}
        <div class="flex flex-wrap gap-2">
          <Button
            size="sm"
            disabled={act.isPending || (need.code === 'try_it' && !allTicked)}
            onclick={() => perform(buttons.primary.action)}
          >
            {need.code === 'family_disabled' && family
              ? `Turn on for ${family}`
              : buttons.primary.label}
          </Button>
          {#if buttons.secondary}
            <Button
              size="sm"
              variant="ghost"
              disabled={act.isPending}
              onclick={() => perform(buttons.secondary!.action)}
            >
              {buttons.secondary.label}
            </Button>
          {/if}
        </div>
        {#if buttons.hint}<p class="text-muted-foreground text-xs">{buttons.hint}</p>{/if}
      {/if}
    </div>
  {/if}

  <div class="flex flex-wrap gap-2 pt-2">
    {#if live}
      <Button variant="outline" size="sm" onclick={onClose}>Close</Button>
      <Button variant="ghost" size="sm" disabled={act.isPending} onclick={cancel}>
        Cancel protection
      </Button>
    {:else}
      <Button size="sm" onclick={() => router.navigate(edgesPaths.node(run.relaySlug))}>
        Open the node
      </Button>
      <Button variant="ghost" size="sm" onclick={onClose}>Close</Button>
    {/if}
  </div>
{/if}
