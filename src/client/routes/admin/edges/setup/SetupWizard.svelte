<script lang="ts">
  /**
   * The wizard proper: the server's nine steps on the left, the body of the
   * current step (or the one peeked at through `?step=`) on the right, and the
   * rotation drawer (`?rotation=`). No progress is kept here.
   *
   * Props:
   *   status: the setup-status query (relay scope, or draft scope)
   *   relay: RelayAdmin | null
   *   relaySlug: string | null
   *   draft: StoredDraft (bindable)
   *   draftMode: boolean
   *   onRelayCreated(slug), onWatchSlug(slug), onLeave()
   */
  import type { CreateQueryResult } from '@tanstack/svelte-query';
  import CircleCheck from '@lucide/svelte/icons/circle-check';
  import { Button, buttonVariants } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import type { RelayAdmin, SetupStatusResponse } from '@shared/contracts/edges';
  import { router } from '@client/stores/router.svelte';
  import { searchParam } from '@client/lib/urlState.svelte';
  import { SETUP_STEP_HINTS, SETUP_STEP_TITLES } from '@client/lib/edgeCodes';
  import AdminListState from '../../AdminListState.svelte';
  import Stepper from '../components/Stepper.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import RotationDrawer from '../components/RotationDrawer.svelte';
  import { edgesPaths } from '../lib/routes';
  import { resolveShownStep, stepperSteps } from './steps';
  import type { StoredDraft } from './draft';
  import type { IssueLinkContext } from './issueActions';
  import StepOrigin from './StepOrigin.svelte';
  import StepAccount from './StepAccount.svelte';
  import StepTemplate from './StepTemplate.svelte';
  import StepRelay from './StepRelay.svelte';
  import StepEdge from './StepEdge.svelte';
  import StepQualification from './StepQualification.svelte';
  import StepPublish from './StepPublish.svelte';
  import StepRendering from './StepRendering.svelte';
  import StepAutomation from './StepAutomation.svelte';

  interface Props {
    status: CreateQueryResult<SetupStatusResponse, Error>;
    relay: RelayAdmin | null;
    relaySlug: string | null;
    draft: StoredDraft;
    draftMode: boolean;
    onRelayCreated: (slug: string) => void;
    onWatchSlug: (slug: string) => void;
    onLeave: () => void;
  }
  let {
    status,
    relay,
    relaySlug,
    draft = $bindable(),
    draftMode,
    onRelayCreated,
    onWatchSlug,
    onLeave,
  }: Props = $props();

  const stepParam = searchParam('step');
  const rotationParam = searchParam('rotation');

  const data = $derived(status.data);
  const shownId = $derived(data ? resolveShownStep(data, stepParam.value) : null);
  // A finished setup still lets the operator open a step to look at it.
  const shown = $derived(
    data && shownId && !(data.complete && !stepParam.value)
      ? (data.steps.find((s) => s.id === shownId) ?? null)
      : null,
  );
  const peeking = $derived(!!data && !!shown && shown.id !== data.currentStep);

  function select(id: string) {
    stepParam.value = data && id === data.currentStep ? null : id;
  }

  const linkCtx = $derived<IssueLinkContext>({
    relaySlug,
    accountId: data?.context.accountId ?? null,
    returnTo: `${router.pathname}${router.search}`,
  });
  const base = $derived(data && shown ? { step: shown, status: data, relay, linkCtx } : null);
</script>

<div class="mb-4 flex flex-wrap items-center gap-2 text-sm">
  {#if relaySlug}
    <span class="text-muted-foreground">Setting up relay</span>
    <Link class="font-mono underline underline-offset-2" href={edgesPaths.relay(relaySlug)}>
      {relaySlug}
    </Link>
  {:else}
    <span class="text-muted-foreground"
      >Setting up a new relay from a draft kept in this browser</span
    >
  {/if}
  <Button size="sm" variant="ghost" class="ms-auto" onclick={onLeave}>Choose another relay</Button>
</div>

{#if status.isError && !data}
  <AdminListState error={status.error} onRetry={() => void status.refetch()} />
{:else if !data}
  <div class="grid gap-6 lg:grid-cols-[19rem_1fr]" role="status">
    <span class="sr-only">Loading the setup status</span>
    <Skeleton class="h-96 w-full" />
    <Skeleton class="h-64 w-full" />
  </div>
{:else}
  <div class="grid items-start gap-6 lg:grid-cols-[19rem_1fr]">
    <Stepper
      steps={stepperSteps(data.steps)}
      current={shown?.id ?? null}
      onSelect={select}
      label="Setup steps"
      class="lg:sticky lg:top-4"
    />

    <div class="min-w-0 space-y-4">
      {#if data.complete && !shown}
        <section
          class="space-y-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-4"
          aria-live="polite"
        >
          <h2 class="flex items-center gap-2 text-base font-semibold">
            <CircleCheck class="size-5 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
            This relay is set up
          </h2>
          <p class="text-sm">
            An edge is published and members are sent to it. Day to day work (rotating, standbys,
            probes, listeners) happens on the relay page. Pick any step on the left to look at it
            again.
          </p>
          <div class="flex flex-wrap gap-2">
            {#if relaySlug}
              <Link href={edgesPaths.relay(relaySlug)} class={buttonVariants({})}>
                Open the relay
              </Link>
            {/if}
            <Link href={edgesPaths.overview()} class={buttonVariants({ variant: 'outline' })}>
              Edges overview
            </Link>
          </div>
        </section>
      {:else if shown && base}
        <section class="space-y-4 rounded-lg border p-4" aria-labelledby="setup-step-title">
          <header class="space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <h2 id="setup-step-title" class="text-base font-semibold">
                {SETUP_STEP_TITLES[shown.id]}
              </h2>
              <StatusBadge kind="setup" value={shown.status} />
              {#if peeking}
                <span class="text-muted-foreground text-xs"> You are looking ahead or back. </span>
                {#if data.currentStep}
                  <Button size="sm" variant="ghost" onclick={() => (stepParam.value = null)}>
                    Back to the current step
                  </Button>
                {/if}
              {/if}
            </div>
            <p class="text-muted-foreground text-sm">{SETUP_STEP_HINTS[shown.id]}</p>
          </header>

          {#if shown.id === 'origin'}
            <StepOrigin
              {...base}
              bind:draft={() => (draftMode ? draft : null), (v) => v && (draft = v)}
            />
          {:else if shown.id === 'account'}
            <StepAccount {...base} />
          {:else if shown.id === 'template'}
            <StepTemplate {...base} />
          {:else if shown.id === 'relay'}
            <StepRelay {...base} draft={draftMode ? draft : null} {onRelayCreated} {onWatchSlug} />
          {:else if shown.id === 'edge'}
            <StepEdge {...base} onRotation={(id) => (rotationParam.value = id)} />
          {:else if shown.id === 'qualification'}
            <StepQualification {...base} />
          {:else if shown.id === 'publish'}
            <StepPublish {...base} onRotation={(id) => (rotationParam.value = id)} />
          {:else if shown.id === 'rendering'}
            <StepRendering {...base} />
          {:else}
            <StepAutomation {...base} />
          {/if}
        </section>
        {#if status.isError}
          <AdminListState error={status.error} onRetry={() => void status.refetch()} />
        {/if}
      {/if}
    </div>
  </div>
{/if}

{#if relay}
  <RotationDrawer
    rotationId={rotationParam.value || null}
    relaySlug={relay.slug}
    relayId={relay.id}
    onClose={() => (rotationParam.value = null)}
    onOpenEdge={(edgeId) =>
      router.navigate(edgesPaths.relay(relay.slug, { tab: 'edges', edge: edgeId }))}
  />
{/if}
