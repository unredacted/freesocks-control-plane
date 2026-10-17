<script lang="ts">
  /**
   * A guided run's progress: four plain stages, the elapsed time, one live line
   * from the latest event, and the interruption card (one sentence, one button,
   * at most one secondary) when the run needs you. Polls the run every 3 s.
   *
   * An enrolled node's run parks at publish (`node_not_approved`) until its
   * go-live is approved: the card then holds the node's approval card
   * (NodeApprovalCard, the same one the Servers node page shows), and the run
   * carries on by itself once the approval lands.
   *
   * At `try_it` each tick is saved on its own (`continue` with that one
   * confirmation) and "Doesn't work" replaces that one address (`retry
   * {tryAnotherAddress, edgeId}`); the run moves on once every line works. A
   * paused (quarantined) node shows the plain PausedCard; the Live card offers
   * automatic protection while it is off.
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
    automationOn,
    hideButton,
    moreDirectWords,
    needButtons,
    runTestLines,
    type NeedAction,
    type TestItem,
  } from './runWords';
  import {
    cancelSetupRun,
    continueSetupRun,
    edgeConfigQuery,
    invalidateConfig,
    invalidateOverview,
    patchEdgeConfig,
    relayLookupQuery,
    retrySetupRun,
    setEdgeAutomation,
    setupRunQuery,
    testProviderCredentials,
    thawMaintenance,
    updateRelay,
  } from '@client/lib/edgesApi';
  import { codeLabel, plainWords, setupRunNeedCopy } from '@client/lib/edgeCodes';
  import type { SetupRunContinueBody, SetupRunRetryBody } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import NodeApprovalCard from '../../servers/components/NodeApprovalCard.svelte';
  import { serversPaths } from '../../servers/lib/routes';
  import CodeNote from '../components/CodeNote.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import { durationLabel } from '../lib/time';
  import { cn } from '@client/lib/utils';
  import PausedCard from './PausedCard.svelte';
  import TestCard from './TestCard.svelte';
  import { PLAIN_STAGES, plainStage, runIsLive } from './runStages';

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

  // try_it: every tick is saved on its own; the run rebuilds the card and moves
  // on once every line works. Between a tick and the rebuilt card (the run is
  // briefly `running` at try_it) the card stays up with its answers locked.
  const lines = $derived(run ? runTestLines(run) : { items: [], done: new Set<string>() });
  const testing = $derived(
    !!run &&
      run.stage === 'try_it' &&
      lines.items.length > 0 &&
      (need?.code === 'try_it' || run.state === 'running' || run.state === 'waiting'),
  );
  let busyLine = $state<string | null>(null);
  async function answer(item: TestItem, job: () => Promise<unknown>): Promise<void> {
    busyLine = item.edgeId;
    try {
      await job();
      refresh();
    } catch (e) {
      toast.error(edgeErrorMessage(e));
      // A stale binding: the run rebuilds the link, never stamped as shown.
      void runQ.refetch();
    } finally {
      busyLine = null;
    }
  }
  const works = (item: TestItem) =>
    answer(item, () =>
      continueSetupRun(runId, {
        confirmations: [
          {
            edgeId: item.edgeId,
            endpoint: item.endpoint,
            listenerRevision: item.listenerRevision,
            configHash: item.configHash,
          },
        ],
      }).then((r) => {
        if (r.accountTrusted) toast.success('Address tested. The provider account is now trusted.');
      }),
    );
  const fails = (item: TestItem) =>
    answer(item, () =>
      retrySetupRun(runId, { tryAnotherAddress: true, edgeId: item.edgeId }).then(() =>
        toast.message('Replacing that address. The new one comes back here to test.'),
      ),
    );

  // A paused node: its relay row for the plain resolver card.
  const pausedRelay = relayLookupQuery(() =>
    need?.code === 'quarantined' && run ? run.relaySlug : null,
  );

  // Live: offer automatic protection while it is off (`config` is read below).
  const turnOnAutomation = () =>
    act.mutate(async () => {
      await setEdgeAutomation(true);
      invalidateConfig(qc);
      toast.success('Automatic protection is on.');
    });

  // Secondary pickers.
  let choosingAccount = $state(false);
  let choosingMode = $state(false);
  let modeSlug = $state('');
  const modes = adminConnectionModesQuery();
  const config = edgeConfigQuery();
  const family = $derived(need?.detail ?? run?.plan.familiesDisabled[0] ?? null);
  const automation = $derived(config.data ? automationOn(config.data.config) : null);

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
        // Its origin's page: the first-edge card does it by hand.
        router.navigate(run?.relaySlug ? edgesPaths.relay(run.relaySlug) : edgesPaths.overview());
        return;
      case 'choose_mode':
        choosingMode = true;
        return;
      case 'continue':
        // The test card saves each tick itself.
        return;
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
      case 'approve':
        // Reached only without an enrolled node to approve here (an older server
        // answers no `enrolled`): the Servers page has the node's approval.
        router.navigate(serversPaths.home());
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
            : r.disposition === 'candidates'
              ? 'Cancelled. The new addresses are dropped; members keep what they have.'
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

  {#if run.kind === 'reprotect' && live}
    <p class="text-sm">
      Protecting {run.nodeName} again with new addresses. Members keep the addresses they have until the
      new ones go live.
    </p>
  {/if}

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
      <!-- While the run needs you, the card below says what; the raw event would repeat it.
           The event's detail is internal (keys, ids): Advanced shows it, this face does not. -->
      {#if latest && run.state !== 'needs_you'}{plainWords(codeLabel(latest.code))}.{/if}
    {/if}
  </p>

  {#if run.state === 'done'}
    <div class="space-y-3 rounded-md border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm">
      <p>
        New subscription downloads on {run.nodeName} use the protected address. A configuration someone
        copied by hand keeps working until they re-import it.
      </p>
      {#if automation === false}
        <div class="space-y-2 border-t border-emerald-500/30 pt-3">
          <p class="font-medium">Turn on automatic protection?</p>
          <p class="text-muted-foreground">
            FCP then watches every protected node and switches members to a tested spare address
            when one looks blocked. It keeps one spare per transport, which your provider bills.
          </p>
          <Button class="h-11 sm:h-8" disabled={act.isPending} onclick={turnOnAutomation}>
            Turn on
          </Button>
        </div>
      {/if}
    </div>
  {:else if run.state === 'failed'}
    <CodeNote issue={{ code: run.need?.code ?? 'provider_failed' }} />
    {#if run.need?.detail}
      <CodeNote compact tone="warning" issue={{ code: run.need.detail }} />
    {/if}
    <div class="flex gap-2">
      <Button disabled={act.isPending} onclick={() => retry()}>Try again</Button>
    </div>
  {:else if testing && need?.code !== 'try_it'}
    <!-- The tick just saved: the run is rebuilding the card. -->
    <div class="space-y-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
      <p class="font-medium">{setupRunNeedCopy('try_it').label}</p>
      <TestCard items={lines.items} done={lines.done} locked onWorks={() => {}} />
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
        {#if need.detail === 'reality_key_changed'}
          <CodeNote compact tone="warning" issue={{ code: 'reality_key_changed' }} />
        {/if}
        <TestCard
          items={lines.items}
          done={lines.done}
          busyId={busyLine}
          locked={act.isPending}
          onWorks={(item) => void works(item)}
          onFails={(item) => void fails(item)}
        />
        {#if buttons.hint}<p class="text-muted-foreground text-xs">{buttons.hint}</p>{/if}
      {:else if need.code === 'review_changed'}
        <p>
          {moreDirectWords(run.reviewDelta.length)}
          <span class="text-muted-foreground"
            >{run.reviewDelta.map((d) => d.remark).join(', ')}</span
          >
        </p>
      {:else if need.code === 'quarantined' && pausedRelay.data?.quarantine}
        <!-- Resolving the pause does not wake the run: it carries on through a retry. -->
        <PausedCard relay={pausedRelay.data} onResolved={() => retry()} />
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
            {hideButton(run.reviewDelta.length)}
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
      {:else if need.code === 'try_it' || (need.code === 'quarantined' && pausedRelay.data?.quarantine)}
        <!-- The card above carries its own answers. -->
      {:else if need.code === 'node_not_approved' && run.enrolled}
        {#if run.enrolled.stage === 'activating'}
          <!-- Approved: the run wakes in a moment and the card would only show a stage blocker. -->
          <p class="text-muted-foreground" role="status">
            Approved. The run carries on in a moment.
          </p>
        {:else}
          <NodeApprovalCard
            slug={run.enrolled.slug}
            intentId={run.enrolled.intentId}
            nodeName={run.nodeName}
            fronted
            onApproved={refresh}
          />
        {/if}
      {:else}
        <div class="flex flex-wrap gap-2">
          <Button
            size="sm"
            class="h-11 sm:h-7"
            disabled={act.isPending}
            onclick={() => perform(buttons.primary.action)}
          >
            {need.code === 'family_disabled' && family
              ? `Turn on for ${family}`
              : need.code === 'node_not_approved'
                ? 'Open Servers'
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
        {run.kind === 'reprotect' ? 'Cancel, drop the new addresses' : 'Cancel protection'}
      </Button>
    {:else}
      <Button size="sm" onclick={() => router.navigate(edgesPaths.node(run.relaySlug))}>
        Open the node
      </Button>
      <Button variant="ghost" size="sm" onclick={onClose}>Close</Button>
    {/if}
  </div>
{/if}
