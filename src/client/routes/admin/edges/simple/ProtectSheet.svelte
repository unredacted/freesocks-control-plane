<script lang="ts">
  /**
   * "Protect a node": a sheet with three questions and then the progress.
   *   1. Which node?     always first: a backend, then one of its nodes (already
   *                      protected ones greyed); picking one fetches the plan and
   *                      shows the transports in words. A node with more transports
   *                      than one run protects asks which ones (up to
   *                      SETUP_RUN_MAX_LISTENERS) and plans those.
   *   2. Where from?     the node's provider set: each account's locations as
   *                      checkboxes (an account that carries only some transports
   *                      says which; one that cannot carry the node says why, with
   *                      a link to where that is fixed). Each change plans again
   *                      with the picks, and the plan says what they make: the
   *                      addresses per location, a transport no pick carries, the
   *                      transports with no backup at another provider. Each
   *                      location says how it fares from each checked country
   *                      (Works, Blocked, Some addresses blocked, Not checked
   *                      yet, with age), read live. "Add a
   *                      location" renders LocationPicker and picks the new one;
   *                      "Add account" renders the provider stepper inline
   *                      (compact). With no account at all the stepper opens by
   *                      itself.
   *   3. Review          one sentence, the consent for unsupported addresses, one button
   * A created run hands over to ProtectProgress (`runId`), which the URL keeps.
   *
   * The node list is re-read from the backend once each time the sheet opens,
   * and on Refresh. A link from the Servers page names the node (`server` = the
   * backend's slug or id, `node` = its node uuid): it is picked for you, and
   * when the list does not have it yet the list is refreshed once. A plan with
   * exactly one usable location picks it.
   *
   * Props:
   *   open: boolean
   *   runId: string | null              show a run's progress instead of the questions
   *   server?: string | null            preselect this backend (slug or id; read once)
   *   node?: string | null              preselect this node uuid on it (read once)
   *   onRunCreated: (runId: string) => void
   *   onClose: () => void
   */
  import { untrack } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Sheet from '@client/components/ui/sheet';
  import * as Select from '@client/components/ui/select';
  import * as Collapsible from '@client/components/ui/collapsible';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Badge } from '@client/components/ui/badge';
  import Link from '@client/components/Link.svelte';
  import { countryName } from '@client/lib/countries';
  import { adminBackendServersQuery } from '@client/lib/queries';
  import {
    createSetupRun,
    edgeCountriesQuery,
    edgeKeys,
    nodeCandidatesQuery,
    planSetupRun,
    providersQuery,
    refreshNodeCandidates,
    templatesQuery,
  } from '@client/lib/edgesApi';
  import { adminModeName } from '@client/lib/connectionModeCopy';
  import { SETUP_ACCOUNT_REASON_COPY, inboundUnsupportedCopy } from '@client/lib/edgeCodes';
  import type { EdgeLayer, SetupPlanResponse } from '@shared/contracts/edges';
  import { ListenerSpec } from '@shared/contracts/edges';
  import { SETUP_RUN_MAX_LISTENERS, type SetupAccountReason } from '@shared/contracts/edgeCodes';
  import AdminListState from '../../AdminListState.svelte';
  import { serversPaths } from '../../servers/lib/routes';
  import CodeNote from '../components/CodeNote.svelte';
  import ProviderAccountStepper from '../forms/ProviderAccountStepper.svelte';
  import LocationPicker from '../forms/LocationPicker.svelte';
  import { hasLocations } from '../forms/providerFields';
  import { locationGrades, locationGroupKey } from '../lib/countryChecks';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import { gradeWords } from '../lib/statusWords';
  import { providerLabel, transportName } from '../lib/format';
  import { countryLabel } from '../../servers/lib/words';
  import { edgesPaths } from '../lib/routes';
  import { router } from '@client/stores/router.svelte';
  import ProtectProgress from './ProtectProgress.svelte';
  import PickOptions from './PickOptions.svelte';
  import { overrides, pickBase } from '../lib/options';
  import type { Params } from '../templates/params';
  import { planWords, setWords } from './runWords';

  interface Props {
    open: boolean;
    runId: string | null;
    server?: string | null;
    node?: string | null;
    onRunCreated: (runId: string) => void;
    onClose: () => void;
  }
  let { open, runId, server = null, node = null, onRunCreated, onClose }: Props = $props();
  const qc = useQueryClient();

  type Step = 'node' | 'account' | 'review';
  let step = $state<Step>('node');
  let addingAccount = $state(false);

  // 1. Which node?
  const servers = adminBackendServersQuery();
  const panels = $derived((servers.data ?? []).filter((s) => s.config.type === 'remnawave'));
  // The node a Servers link names, read once (the URL keeps it while the sheet is open).
  const preset = untrack(() => ({ server: server ?? '', node: node ?? '' }));
  let serverId = $state('');
  $effect(() => {
    if (serverId !== '') return;
    const named = preset.server
      ? panels.find((p) => p.slug === preset.server || p.id === preset.server)
      : undefined;
    if (named) serverId = named.id;
    else if (panels.length === 1) serverId = panels[0]!.id;
  });
  const serverSlug = $derived(panels.find((p) => p.id === serverId)?.slug ?? '');
  const candidates = nodeCandidatesQuery(() => serverId || null);
  const nodes = $derived(
    [...(candidates.data?.nodes ?? [])].sort((a, b) => a.name.localeCompare(b.name)),
  );
  let nodeUuid = $state('');
  let plan = $state<SetupPlanResponse | null>(null);
  const pickedNode = $derived(nodes.find((n) => n.nodeUuid === nodeUuid) ?? null);

  // The inventory is a cache: Refresh re-reads the backend (throttled server-side).
  const refresh = createMutation(() => ({
    mutationFn: (v: { id: string; manual: boolean }) => refreshNodeCandidates(v.id),
    onSuccess: (_r, v) => qc.invalidateQueries({ queryKey: edgeKeys.nodeCandidates(v.id) }),
    onError: (e, v) => {
      if (v.manual) toast.error(edgeErrorMessage(e));
    },
  }));

  // The inventory lags the backend: a node enrolled minutes ago reads "Offline"
  // until it is read again, so every opening re-reads it once (throttled server-side).
  let refreshedFor = $state<string | null>(null);
  $effect(() => {
    if (!open) {
      refreshedFor = null;
      return;
    }
    if (!serverId || runId || refreshedFor === serverId) return;
    refreshedFor = serverId;
    untrack(() => refresh.mutate({ id: serverId, manual: false }));
  });

  // Resolving the preset node: pick it, or say it is protected already, or (after one
  // refresh) that the list does not have it. Any choice by hand ends it.
  let presetPending = $state(preset.node !== '');
  let presetRefreshed = false;
  let presetTaken = $state<{ name: string; relaySlug: string } | null>(null);
  let presetMissing = $state(false);
  $effect(() => {
    if (!presetPending || !serverId || !candidates.data || refresh.isPending) return;
    const found = candidates.data.nodes.find((n) => n.nodeUuid === preset.node);
    if (found) {
      presetPending = false;
      if (found.relaySlug === null) untrack(() => pickNode(found.nodeUuid));
      else presetTaken = { name: found.name, relaySlug: found.relaySlug };
    } else if (!presetRefreshed) {
      presetRefreshed = true;
      untrack(() => refresh.mutate({ id: serverId, manual: false }));
    } else {
      presetPending = false;
      presetMissing = true;
    }
  });
  function endPreset() {
    presetPending = false;
    presetTaken = null;
    presetMissing = false;
  }

  // The transports the operator chose on a node with more than one run takes
  // (null: the plan's own set). The create sends the same choice.
  let chosenKeys = $state<string[] | null>(null);
  const planM = createMutation(() => ({
    mutationFn: (v: {
      uuid: string;
      keys: string[] | null;
      picks: string[];
      options: Record<string, Params>;
    }) => planSetupRun(serverId, v.uuid, v.keys ?? undefined, v.picks, v.options),
    onSuccess: (p, v) => {
      // A slower answer for a node, a choice or a set the operator has since
      // moved away from is dropped: the review and the run must never use
      // another plan.
      if (
        p.nodeUuid !== nodeUuid ||
        p.backendServerId !== serverId ||
        v.keys !== chosenKeys ||
        // By value: `picks` reads back as Svelte's proxy of the array sent.
        v.picks.join(',') !== picks.join(',') ||
        // What would be sent now (an emptied pick or one no longer chosen drops out).
        JSON.stringify(v.options) !== JSON.stringify(optionsSent())
      )
        return;
      plan = p;
      if (p.activeRunId) onRunCreated(p.activeRunId);
    },
  }));
  const replan = () =>
    planM.mutate({ uuid: nodeUuid, keys: chosenKeys, picks, options: optionsSent() });
  function pickNode(uuid: string) {
    nodeUuid = uuid;
    plan = null;
    chosenKeys = null;
    choosingTransports = false;
    picks = [];
    pickOptions = {};
    autoPicked = false;
    planM.mutate({ uuid, keys: null, picks: [], options: {} });
  }
  const planIssue = $derived(planM.error ? edgeErrorIssue(planM.error) : null);
  // A transport in words: never its internal key.
  const inboundLine = (i: SetupPlanResponse['inbounds'][number]): string => {
    const parsed = ListenerSpec.safeParse(i.listenerSpec);
    return parsed.success ? transportName(parsed.data) : i.sourceTag;
  };
  const required = $derived(
    plan ? plan.inbounds.filter((i) => plan!.requiredListeners.includes(i.listenerKey)) : [],
  );
  const frontable = $derived(plan?.inbounds.filter((i) => i.frontable) ?? []);
  const notChosen = $derived(
    chosenKeys ? frontable.filter((i) => !plan!.requiredListeners.includes(i.listenerKey)) : [],
  );
  const unsupported = $derived(plan?.inbounds.filter((i) => !i.frontable) ?? []);

  // Too many transports: the operator picks up to the run's limit, then re-plans.
  let picking = $state<string[]>([]);
  let choosingTransports = $state(false);
  $effect(() => {
    if (plan?.tooManyInbounds && chosenKeys === null && !choosingTransports) {
      picking = untrack(() =>
        frontable.slice(0, SETUP_RUN_MAX_LISTENERS).map((i) => i.listenerKey),
      );
      choosingTransports = true;
    }
  });
  function togglePick(key: string, on: boolean) {
    picking = on ? [...picking, key] : picking.filter((k) => k !== key);
  }
  function useChoice() {
    // Plan order, so the run's lines follow the backend's.
    chosenKeys = frontable.map((i) => i.listenerKey).filter((k) => picking.includes(k));
    choosingTransports = false;
    plan = null;
    replan();
  }
  function changeChoice() {
    picking = [...(chosenKeys ?? [])];
    choosingTransports = true;
  }

  // 2. Where the addresses come from: a set of locations (picks), in the
  // order they were picked. Each change plans again: the plan says what the
  // set makes (addresses per pick, transports with no backup elsewhere).
  let picks = $state<string[]>([]);
  let autoPicked = false;
  // The provider options chosen for each pick (only what differs from what the
  // location builds with anyway); the plan checks them where they build.
  let pickOptions = $state<Record<string, Params>>({});
  const optionsSent = (): Record<string, Params> =>
    Object.fromEntries(
      Object.entries($state.snapshot(pickOptions)).filter(
        ([id, v]) => picks.includes(id) && Object.keys(v).length > 0,
      ),
    );
  const providersQ = providersQuery();
  const templatesQ = templatesQuery();
  /** The pick's account and location rows (for what it builds with by default). */
  const pickRows = (locationId: string) => {
    for (const a of providersQ.data?.accounts ?? []) {
      const l = a.locations.find((x) => x.id === locationId);
      if (l) return { account: a, location: l };
    }
    return null;
  };
  function optionsOf(provider: string, locationId: string) {
    const schema = providersQ.data?.optionSchemas[provider];
    const rows = pickRows(locationId);
    if (!schema || !rows) return null;
    const base = pickBase(
      schema,
      templatesQ.data?.schemas[provider]?.defaults ?? {},
      templatesQ.data?.templates ?? [],
      rows.account,
      rows.location,
    );
    return { fields: schema.fields, base };
  }
  function setPickOptions(locationId: string, base: Params, values: Params) {
    const schema = providersQ.data?.optionSchemas[pickRows(locationId)?.account.provider ?? ''];
    pickOptions = { ...pickOptions, [locationId]: overrides(values, base, schema?.fields ?? []) };
    replan();
  }
  let addingLocationFor = $state<string | null>(null);
  // How each offered location fares from the checked countries (read live while open).
  const countriesQ = edgeCountriesQuery({ enabled: () => open && !runId });
  let now = $state(Date.now());
  $effect(() => {
    if (!open) return;
    const t = setInterval(() => (now = Date.now()), 30_000);
    return () => clearInterval(t);
  });
  // With the checks off, a location still shows what is on record for it: a
  // grade, or a mark (marks never expire).
  const gradesOf = (provider: string, layer: string, placeKey: string) => {
    const cells = locationGrades(countriesQ.data, locationGroupKey({ provider, placeKey, layer }));
    const shown = countriesQ.data?.enabled || cells.some((c) => c.grade || c.mark);
    return shown ? cells.map((c) => gradeWords(c, now)) : [];
  };
  const accounts = $derived(
    [...(plan?.accounts ?? [])].sort((a, b) => Number(b.compatible) - Number(a.compatible)),
  );
  const compatible = $derived(accounts.filter((a) => a.compatible));
  const offered = $derived(
    compatible.flatMap((a) => a.locations.filter((l) => l.compatible).map((l) => l.id)),
  );
  function setPicks(next: string[]) {
    picks = next;
    planM.mutate({ uuid: nodeUuid, keys: chosenKeys, picks: next, options: optionsSent() });
  }
  function toggleLocation(id: string, on: boolean) {
    setPicks(on ? [...picks.filter((x) => x !== id), id] : picks.filter((x) => x !== id));
  }
  // Exactly one place can carry the node: it is the answer, picked for you.
  $effect(() => {
    if (step !== 'account' || picks.length > 0 || autoPicked || !plan) return;
    if (offered.length === 1) {
      autoPicked = true;
      untrack(() => setPicks([offered[0]!]));
    }
  });
  // No account at all: adding one is the only way on.
  $effect(() => {
    if (step === 'account' && plan && plan.accounts.length === 0) addingAccount = true;
  });
  // The layers that carry at least one chosen transport: a pick of a set need
  // not carry them all, so a new account of either layer can be one of them.
  const neededLayers = $derived.by((): EdgeLayer[] | undefined => {
    if (required.length === 0) return undefined;
    return (['l4', 'l7'] as const).filter((l) => required.some((i) => i.layers.includes(l)));
  });
  // Remnawave's "XX" (no country set) names no country.
  const nodeCountry = $derived(countryLabel(pickedNode?.countryCode));
  /** Where an account's reason is fixed: its provider page, or nowhere (the transport). */
  function reasonLink(reason: string, id: string): string | null {
    switch (reason as SetupAccountReason) {
      case 'account_untested':
      case 'account_disabled':
      case 'account_capacity_reached':
      case 'account_budget_exhausted':
      case 'dns_zone_missing':
      case 'location_disabled':
      case 'location_capacity_reached':
        return edgesPaths.provider(id);
      case 'provider_mismatch':
        return plan?.existingRelay
          ? edgesPaths.relay(plan.existingRelay.slug, { tab: 'listeners' })
          : null;
      default:
        return null;
    }
  }
  const reasonLabel = (r: string): string =>
    (SETUP_ACCOUNT_REASON_COPY as Record<string, { label: string }>)[r]?.label ?? r;
  function onAccountCreated() {
    addingAccount = false;
    // The plan judges accounts: re-read it so the new one appears with its verdict.
    replan();
  }
  function onLocationCreated(id: string) {
    addingLocationFor = null;
    setPicks([...picks.filter((x) => x !== id), id]);
  }
  /** A transport in words, by its key. */
  const nameOf = (key: string): string => {
    const i = plan?.inbounds.find((x) => x.listenerKey === key);
    return i ? inboundLine(i) : key;
  };
  const accountNameOf = (id: string): string => accounts.find((a) => a.id === id)?.name ?? id;
  /** What the current picks make: the plan's answer for exactly these picks. */
  const set = $derived(
    plan?.set &&
      plan.set.picks.length === picks.length &&
      plan.set.picks.every((p, i) => p.locationId === picks[i])
      ? plan.set
      : null,
  );
  const setW = $derived(set ? setWords(set, nameOf, accountNameOf) : null);
  const setReady = $derived(
    !!set && set.uncovered.length === 0 && !set.tooLarge && set.problems.length === 0,
  );

  // 3. Review
  const words = $derived(
    plan && setW && set ? planWords(plan, setW.where, set.targets.length) : null,
  );
  const create = createMutation(() => ({
    mutationFn: (keepDirect: boolean) =>
      createSetupRun({
        backendServerId: plan!.backendServerId,
        nodeUuid: plan!.nodeUuid,
        picks,
        ...(Object.keys(optionsSent()).length > 0 ? { pickOptions: optionsSent() } : {}),
        planHash: plan!.planHash,
        approvedHideUuids: keepDirect ? [] : (words?.uncovered?.uuids ?? []),
        ...(keepDirect ? { keepDirect: true } : {}),
        ...(chosenKeys ? { listenerKeys: chosenKeys } : {}),
      }),
    onSuccess: (r) => {
      toast.success('Protecting the node.');
      onRunCreated(r.runId);
    },
    onError: (e) => toast.error(edgeErrorMessage(e)),
  }));

  const canContinue = $derived(
    step === 'node'
      ? plan !== null &&
          !plan.tooManyInbounds &&
          !choosingTransports &&
          plan.requiredListeners.length > 0
      : step === 'account'
        ? setReady && !planM.isPending
        : false,
  );
  function next() {
    if (step === 'node') step = 'account';
    else if (step === 'account') step = 'review';
  }
  function back() {
    addingAccount = false;
    addingLocationFor = null;
    if (step === 'review') step = 'account';
    else if (step === 'account') step = 'node';
  }
  const TITLES: Record<Step, string> = {
    node: 'Which node?',
    account: 'Where from?',
    review: 'Review',
  };
  const CARD =
    'has-[:checked]:border-primary has-[:checked]:bg-primary/5 flex cursor-pointer items-start gap-3 rounded-md border p-3 has-[:disabled]:cursor-not-allowed';
  const LINK = 'text-primary underline underline-offset-4';
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
          The locations the node's addresses come from. Pick locations at different providers so
          members get a backup elsewhere.
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
          <div class="text-muted-foreground space-y-2 rounded-md border border-dashed p-4 text-sm">
            <p>No panel is registered yet. Add a Remnawave backend server first.</p>
            <Link href={serversPaths.home()} class={LINK}>Open Servers</Link>
          </div>
        {:else}
          {#if panels.length > 1}
            <div class="space-y-1.5">
              <span class="text-sm font-medium">Backend</span>
              <Select.Root
                type="single"
                value={serverId}
                onValueChange={(v) => {
                  endPreset();
                  serverId = v;
                  nodeUuid = '';
                  plan = null;
                  chosenKeys = null;
                  choosingTransports = false;
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
            <div class="flex items-center justify-between gap-2">
              <span class="text-sm font-medium">Node</span>
              <Button
                variant="ghost"
                size="sm"
                class="h-11 sm:h-7"
                disabled={refresh.isPending}
                onclick={() => refresh.mutate({ id: serverId, manual: true })}
              >
                <RefreshCw
                  class={refresh.isPending ? 'animate-spin motion-reduce:animate-none' : ''}
                  aria-hidden="true"
                />
                {refresh.isPending ? 'Refreshing' : 'Refresh'}
              </Button>
            </div>
            {#if presetTaken}
              <div class="space-y-2 rounded-md border p-3 text-sm" role="status">
                <p>
                  {presetTaken.name} is already protected. To give it new addresses, use Protect again
                  on its page.
                </p>
                <Button
                  size="sm"
                  variant="outline"
                  onclick={() => router.navigate(edgesPaths.node(presetTaken!.relaySlug))}
                >
                  Open the node
                </Button>
              </div>
            {:else if presetMissing}
              <p class="text-muted-foreground text-sm" role="status">
                The node from Servers is not in this list yet. Refresh once it is online on the
                backend, or pick another node.
                <Link
                  href={serversPaths.node(preset.node, { instance: serverSlug || undefined })}
                  class={LINK}>Open it on Servers</Link
                >
              </p>
            {/if}
            {#if candidates.isPending || (presetPending && refresh.isPending)}
              <Skeleton class="h-24 w-full" />
            {:else if candidates.isError}
              <AdminListState error={candidates.error} onRetry={() => void candidates.refetch()} />
            {:else if nodes.length === 0}
              <div
                class="text-muted-foreground space-y-2 rounded-md border border-dashed p-4 text-sm"
              >
                <p>This panel has no nodes yet.</p>
                <Link href={serversPaths.home({ instance: serverSlug || undefined })} class={LINK}
                  >Add one under Servers</Link
                >
              </div>
            {:else}
              <fieldset class="space-y-2">
                <legend class="sr-only">Node</legend>
                {#each nodes as n (n.nodeUuid)}
                  {@const taken = n.relaySlug !== null}
                  <label class={[CARD, taken && 'opacity-60']}>
                    <input
                      type="radio"
                      name="protect-node"
                      class="accent-primary mt-1"
                      value={n.nodeUuid}
                      checked={nodeUuid === n.nodeUuid}
                      disabled={taken}
                      onchange={() => {
                        endPreset();
                        pickNode(n.nodeUuid);
                      }}
                    />
                    <span class="min-w-0 flex-1">
                      <span class="block font-medium">{n.name}</span>
                      <span class="text-muted-foreground block text-xs">
                        {countryLabel(n.countryCode) ?? 'No country set'}
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
            <AdminListState error={planM.error} onRetry={replan} />
          {:else if plan && choosingTransports}
            <fieldset class="space-y-3 rounded-md border p-3 text-sm">
              <legend class="px-1 font-medium">Which transports?</legend>
              <p>
                This node has {frontable.length} transports a provider address can carry. One run protects
                up to {SETUP_RUN_MAX_LISTENERS}: pick the ones members need most. The others keep
                the direct address, or are hidden if you consent on the review.
              </p>
              <ul class="space-y-1">
                {#each frontable as i (i.listenerKey)}
                  {@const on = picking.includes(i.listenerKey)}
                  <li>
                    <label class="flex min-h-11 cursor-pointer items-center gap-3 sm:min-h-8">
                      <input
                        type="checkbox"
                        class="accent-primary size-4"
                        checked={on}
                        disabled={!on && picking.length >= SETUP_RUN_MAX_LISTENERS}
                        onchange={(e) => togglePick(i.listenerKey, e.currentTarget.checked)}
                      />
                      <span class="min-w-0 font-medium">{inboundLine(i)}</span>
                    </label>
                  </li>
                {/each}
              </ul>
              <div class="flex flex-wrap items-center gap-3">
                <Button class="h-11 sm:h-8" disabled={picking.length === 0} onclick={useChoice}>
                  Use these {picking.length}
                </Button>
                <span class="text-muted-foreground text-xs" aria-live="polite">
                  {picking.length} of {SETUP_RUN_MAX_LISTENERS} chosen
                </span>
              </div>
            </fieldset>
          {:else if plan}
            <div class="space-y-3 rounded-md border p-3 text-sm">
              {#if required.length === 0}
                <p>
                  No transport on this node can be carried by a provider address yet. It cannot be
                  protected this way.
                </p>
              {:else}
                <p class="font-medium">
                  {required.length === 1 ? 'This transport gets' : 'These transports get'} a protected
                  address
                </p>
                <ul class="space-y-1">
                  {#each required as i (i.listenerKey)}
                    <li class="font-medium">{inboundLine(i)}</li>
                  {/each}
                </ul>
                <p class="text-muted-foreground text-xs">
                  {planWords(plan, '').formats}
                </p>
              {/if}
              {#if chosenKeys}
                <p class="text-muted-foreground text-xs">
                  {notChosen.length === 1
                    ? '1 more transport was not chosen.'
                    : `${notChosen.length} more transports were not chosen.`}
                  <button
                    type="button"
                    class={[LINK, 'min-h-11 sm:min-h-0']}
                    onclick={changeChoice}
                  >
                    Change the transports
                  </button>
                </p>
              {/if}
              {#if unsupported.length > 0}
                <Collapsible.Root>
                  <Collapsible.Trigger
                    class="group text-muted-foreground hover:text-foreground flex min-h-11 items-center gap-1 text-sm sm:min-h-0"
                  >
                    <ChevronRight
                      class="size-4 transition-transform group-data-[state=open]:rotate-90"
                      aria-hidden="true"
                    />
                    Not supported yet ({unsupported.length})
                  </Collapsible.Trigger>
                  <Collapsible.Content class="space-y-2 pt-2">
                    <!-- Unsupported transports have no listener key (the plan sends ''), so the
                         tag with its position is the key: two of them would otherwise collide
                         and Svelte refuses duplicate keys at render time. -->
                    {#each unsupported as i, idx (`${i.sourceTag}#${idx}`)}
                      {@const copy = inboundUnsupportedCopy(i.reason ?? 'invalid')}
                      <p>
                        <span class="font-medium">{i.sourceTag}</span>: {copy.label}.
                        <span class="text-muted-foreground">{copy.explain}</span>
                        {#if i.detail}
                          <!-- The mapper's own words for THIS inbound (a validator message or
                               a short code): without them "the detail names what" names nothing. -->
                          <span class="text-muted-foreground mt-0.5 block font-mono text-xs"
                            >{i.detail}</span
                          >
                        {/if}
                      </p>
                    {/each}
                    <p class="text-muted-foreground text-xs">
                      A node's transports are set on its panel.
                      <Link
                        href={serversPaths.node(nodeUuid, { instance: serverSlug || undefined })}
                        class={LINK}>Open the node on Servers</Link
                      >
                    </p>
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
            layers={neededLayers}
            {nodeCountry}
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
              <legend class="sr-only">Locations</legend>
              {#each accounts as a (a.id)}
                {@const partial = a.compatible && a.carries.length < required.length}
                <div class="rounded-md border">
                  <div class="p-3 pb-1">
                    <span class={['block font-medium', !a.compatible && 'opacity-60']}
                      >{a.name}</span
                    >
                    <span class="text-muted-foreground block text-xs">
                      {providerLabel(a.provider)}
                      <span class="mx-1" aria-hidden="true">·</span>{a.layer === 'l7'
                        ? 'CDN front'
                        : 'load balancer'}
                      {#if partial}
                        <span class="mx-1" aria-hidden="true">·</span>carries {a.carries
                          .map(nameOf)
                          .join(', ')}
                      {/if}
                    </span>
                  </div>
                  {#if !a.compatible}
                    <ul class="space-y-0.5 px-3 pb-3 text-xs">
                      {#each a.reasons as r (r)}
                        {@const href = reasonLink(r, a.id)}
                        <li>
                          {#if r === 'no_location' && hasLocations(a.provider)}
                            <button
                              type="button"
                              class={`${LINK} inline-flex min-h-11 items-center sm:min-h-0`}
                              onclick={() => (addingLocationFor = a.id)}>Add a location</button
                            >
                          {:else if href}
                            <Link
                              {href}
                              class={`${LINK} inline-flex min-h-11 items-center sm:min-h-0`}
                              >{reasonLabel(r)}</Link
                            >
                          {:else}
                            <span class="text-muted-foreground"
                              >{r === 'layer_mismatch'
                                ? 'Cannot carry any chosen transport'
                                : reasonLabel(r)}</span
                            >
                          {/if}
                        </li>
                      {/each}
                    </ul>
                  {:else}
                    <ul class="space-y-1.5 px-3 pb-3">
                      {#each a.locations as l (l.id)}
                        {@const grades = gradesOf(a.provider, a.layer, l.placeKey)}
                        <li>
                          <label
                            class="has-[:checked]:border-primary has-[:checked]:bg-primary/5 flex cursor-pointer items-start gap-2 rounded-md border px-2 py-1.5 has-[:disabled]:cursor-not-allowed"
                          >
                            <input
                              type="checkbox"
                              class="accent-primary mt-1"
                              checked={picks.includes(l.id)}
                              disabled={!l.compatible}
                              onchange={(e) => toggleLocation(l.id, e.currentTarget.checked)}
                            />
                            <span class="min-w-0 flex-1">
                              <span class={['block text-sm', !l.compatible && 'opacity-60']}
                                >{l.label}{l.isDefault && a.locations.length > 1
                                  ? ' (default)'
                                  : ''}</span
                              >
                              <span class="text-muted-foreground block text-xs">
                                {#if !l.compatible}
                                  {l.reasons.map(reasonLabel).join('. ')}.
                                {:else if l.qualified}
                                  Trusted.
                                {:else}
                                  Not trusted yet: the check before going live trusts it.
                                {/if}
                              </span>
                              {#if grades.length > 0}
                                <span
                                  class="mt-1 flex flex-wrap gap-1"
                                  aria-label={`${l.label} from each country`}
                                >
                                  {#each grades as g (g.country)}
                                    <!-- A mark wins over the checks: the chip says it. -->
                                    <Badge
                                      variant={g.markState === 'proven'
                                        ? 'success'
                                        : g.markState === 'blocked'
                                          ? 'danger'
                                          : g.tone}
                                      title={[
                                        countryName(g.country, 'en'),
                                        g.age,
                                        g.mark,
                                        g.conflict,
                                      ]
                                        .filter(Boolean)
                                        .join('. ')}
                                    >
                                      {g.country}: {g.markState
                                        ? `${g.markState === 'proven' ? 'works' : 'blocked'}, your mark`
                                        : g.label.toLowerCase()}
                                    </Badge>
                                  {/each}
                                </span>
                              {/if}
                            </span>
                          </label>
                          {#if picks.includes(l.id)}
                            {@const o = optionsOf(a.provider, l.id)}
                            {#if o}
                              <div class="pl-7">
                                <PickOptions
                                  accountId={a.id}
                                  locationId={l.id}
                                  fields={o.fields}
                                  base={o.base}
                                  values={pickOptions[l.id] ?? {}}
                                  onchange={(next) => setPickOptions(l.id, o.base, next)}
                                />
                              </div>
                            {/if}
                          {/if}
                        </li>
                      {/each}
                    </ul>
                    {#if hasLocations(a.provider) && addingLocationFor !== a.id}
                      <Button
                        variant="ghost"
                        size="sm"
                        class="mx-3 mb-3 h-11 sm:h-7"
                        onclick={() => (addingLocationFor = a.id)}
                      >
                        Add a location
                      </Button>
                    {/if}
                  {/if}
                  {#if addingLocationFor === a.id}
                    <div class="border-t p-3">
                      <LocationPicker
                        accountId={a.id}
                        provider={a.provider}
                        {nodeCountry}
                        onCreated={onLocationCreated}
                        onCancel={() => (addingLocationFor = null)}
                      />
                    </div>
                  {/if}
                </div>
              {/each}
            </fieldset>
            <!-- What the picks make: addresses per location, coverage, backups elsewhere. -->
            <div aria-live="polite">
              {#if picks.length === 0}
                <p class="text-muted-foreground text-xs">
                  Pick one location or more. Locations at different providers give members a backup
                  elsewhere.
                </p>
              {:else if planM.isPending || !setW}
                <p class="text-muted-foreground text-sm" role="status">
                  Working out what these locations need.
                </p>
              {:else}
                <div class="space-y-1 rounded-md border p-3 text-sm" role="status">
                  <p class="font-medium">FCP creates</p>
                  <ul class="space-y-0.5">
                    {#each setW.lines as line (line.locationId)}
                      <li>{line.text}</li>
                    {/each}
                  </ul>
                  {#if setW.uncovered}<p class="text-destructive">{setW.uncovered}</p>{/if}
                  {#if setW.tooLarge}<p class="text-destructive">{setW.tooLarge}</p>{/if}
                  {#each set?.problems ?? [] as pr (pr.locationId + pr.reason)}
                    <p class="text-destructive">
                      {set?.picks.find((x) => x.locationId === pr.locationId)?.label ?? ''}: {pr.detail ??
                        reasonLabel(pr.reason)}.
                    </p>
                  {/each}
                  {#if setW.reduced}<p class="text-muted-foreground">{setW.reduced}</p>{/if}
                </div>
              {/if}
              {#if planIssue && step === 'account'}<CodeNote issue={planIssue} />{/if}
            </div>
            {#if compatible.length === 0}
              <p class="text-muted-foreground text-xs">
                No account can carry this node's transports as it is. Follow a link above to fix
                one, or add another.
              </p>
            {/if}
          {/if}
          <Button
            variant="outline"
            size="sm"
            class="h-11 sm:h-7"
            onclick={() => (addingAccount = true)}
          >
            Add account
          </Button>
        {/if}
      {:else if words && plan}
        <p class="text-sm">{words.sentence}</p>
        {#if plan.modesOff.length > 0}
          <div
            class="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm"
            role="status"
          >
            <p>
              Members cannot pick {plan.modesOff
                .map((m) => adminModeName({ id: m.slug, label: m.label }))
                .join(', ')} yet: {plan.modesOff.length === 1 ? 'the mode is' : 'the modes are'} turned
              off. The node is protected, but nobody is given it until {plan.modesOff.length === 1
                ? 'it is'
                : 'they are'} on.
            </p>
            <Link href="/admin/connection-modes" class={`${LINK} mt-1 inline-block`}
              >Open Connection modes</Link
            >
          </div>
        {/if}
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
          <Button
            class="h-11 sm:h-8"
            disabled={create.isPending}
            onclick={() => create.mutate(false)}
          >
            {create.isPending ? 'Starting' : words.button}
          </Button>
          <!-- An enrolled node goes live through its approval only: it has no direct address to keep. -->
          {#if words.uncovered && !plan?.enrolled}
            <Button
              variant="ghost"
              class="h-11 sm:h-8"
              disabled={create.isPending}
              onclick={() => create.mutate(true)}
            >
              Keep those members on the direct address
            </Button>
          {/if}
        {:else if !(step === 'account' && addingAccount)}
          <Button class="h-11 sm:h-8" disabled={!canContinue} onclick={next}>Continue</Button>
        {/if}
        {#if step !== 'node'}
          <Button variant="ghost" class="h-11 sm:h-8" onclick={back}>Back</Button>
        {/if}
      </Sheet.Footer>
    {/if}
  </Sheet.Content>
</Sheet.Root>
