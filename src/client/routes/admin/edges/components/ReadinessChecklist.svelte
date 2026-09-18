<script lang="ts">
  /**
   * The guided setup as a checklist: each step with its status, its blockers and
   * warnings in words, and a link into the wizard at that step. In fleet scope it
   * also lists the relays whose setup can be resumed.
   *
   * Props:
   *   status: SetupStatusResponse           from setupStatusQuery (relay or fleet scope)
   *   relaySlug?: string | null             overrides status.context.relaySlug for the links
   *   compact?: boolean                     one line per step, blockers collapsed to a count
   *   showResume?: boolean                  list `status.resume` relays (default true)
   *   class?: string
   */
  import type { SetupStatusResponse } from '@shared/contracts/edges';
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import { SETUP_STEP_HINTS, SETUP_STEP_TITLES } from '@client/lib/edgeCodes';
  import StatusBadge from './StatusBadge.svelte';
  import CodeNote from './CodeNote.svelte';
  import { edgesPaths } from '../lib/routes';

  interface Props {
    status: SetupStatusResponse;
    relaySlug?: string | null;
    compact?: boolean;
    showResume?: boolean;
    class?: string;
  }
  let { status, relaySlug, compact = false, showResume = true, class: className }: Props = $props();

  const slug = $derived(relaySlug ?? status.context.relaySlug);
  const doneCount = $derived(
    status.steps.filter((s) => s.status === 'done' || s.status === 'skipped').length,
  );
  const resumable = $derived(status.resume.filter((r) => !r.complete));
  const LINK =
    'text-primary focus-visible:ring-ring/50 rounded-sm text-sm underline underline-offset-4 outline-none focus-visible:ring-3';
</script>

<div class={cn('space-y-4', className)}>
  <div class="flex flex-wrap items-center justify-between gap-2">
    <p class="text-sm">
      {#if status.complete}
        Setup is complete.
      {:else}
        {doneCount} of {status.steps.length} steps done.
        {#if status.currentStep}
          Next: <span class="font-medium">{SETUP_STEP_TITLES[status.currentStep]}</span>.
        {/if}
      {/if}
    </p>
    {#if !status.complete}
      <Link href={edgesPaths.setup({ relay: slug, step: status.currentStep })} class={LINK}>
        {slug ? 'Resume setup' : 'Start setup'}
      </Link>
    {/if}
  </div>

  <ol class="divide-border divide-y rounded-lg border" aria-label="Setup steps">
    {#each status.steps as step, i (step.id)}
      {@const open = step.status === 'ready' || step.status === 'blocked'}
      <li class="px-3 py-2.5">
        <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span class="text-muted-foreground w-5 text-xs tabular-nums" aria-hidden="true"
            >{i + 1}</span
          >
          <span class="min-w-0 flex-1 basis-40">
            <span class="text-sm font-medium">{SETUP_STEP_TITLES[step.id]}</span>
            {#if !compact}
              <span class="text-muted-foreground block text-xs">{SETUP_STEP_HINTS[step.id]}</span>
            {/if}
          </span>
          {#if compact && step.blockers.length > 0}
            <span class="text-muted-foreground text-xs">
              {step.blockers.length}
              {step.blockers.length === 1 ? 'blocker' : 'blockers'}
            </span>
          {/if}
          <StatusBadge kind="setup" value={step.status} />
          {#if open}
            <Link
              href={edgesPaths.setup({ relay: slug, step: step.id })}
              class={LINK}
              aria-label={`${step.status === 'ready' ? 'Continue' : 'Open'} step ${i + 1}, ${SETUP_STEP_TITLES[step.id]}`}
            >
              {step.status === 'ready' ? 'Continue' : 'Open'}
            </Link>
          {/if}
        </div>
        {#if !compact && (step.blockers.length > 0 || step.warnings.length > 0)}
          <div class="mt-2 space-y-1.5 ps-8">
            {#each step.blockers as b, bi (`${b.code}:${b.subject ?? ''}:${bi}`)}
              <CodeNote issue={b} tone="blocker" />
            {/each}
            {#each step.warnings as w, wi (`${w.code}:${w.subject ?? ''}:${wi}`)}
              <CodeNote issue={w} tone="warning" />
            {/each}
          </div>
        {/if}
      </li>
    {/each}
  </ol>

  {#if showResume && status.scope === 'fleet' && resumable.length > 0}
    <div>
      <h3 class="mb-1.5 text-sm font-semibold">Relays with unfinished setup</h3>
      <ul class="space-y-1">
        {#each resumable as r (r.relayId)}
          <li class="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span>
              <span class="font-mono text-xs">{r.relaySlug}</span>
              {#if r.currentStep}
                <span class="text-muted-foreground">
                  stopped at {SETUP_STEP_TITLES[r.currentStep]}</span
                >
              {/if}
            </span>
            <Link
              href={edgesPaths.setup({ relay: r.relaySlug, step: r.currentStep })}
              class={LINK}
              aria-label={`Resume setup of relay ${r.relaySlug}`}
            >
              Resume setup
            </Link>
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</div>
