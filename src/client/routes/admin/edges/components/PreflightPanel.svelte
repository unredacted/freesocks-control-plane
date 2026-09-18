<script lang="ts">
  /**
   * The result of a preflight (a dry run that writes nothing): whether the
   * operation would start, what blocks it, what to know first, and what the
   * machine would pick, all in words.
   *
   * Props:
   *   result: PreflightResponse | undefined
   *   pending?: boolean                     the dry run is in flight
   *   error?: unknown                       the dry run itself failed (network, 4xx)
   *   onRetry?: () => void
   *   kind?: PreflightKind                  words the summary ("Provisioning can start")
   *   class?: string
   */
  import type { PreflightKind, PreflightResponse } from '@shared/contracts/edges';
  import CircleCheck from '@lucide/svelte/icons/circle-check';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { cn } from '@client/lib/utils';
  import AdminListState from '../../AdminListState.svelte';
  import CodeNote from './CodeNote.svelte';
  import LayerBadge from './LayerBadge.svelte';
  import KeyValue from './KeyValue.svelte';
  import { providerLabel } from '../lib/format';
  import { shortId } from '../lib/time';
  import type { KeyValueRow } from '../lib/types';

  interface Props {
    result: PreflightResponse | undefined;
    pending?: boolean;
    error?: unknown;
    onRetry?: () => void;
    kind?: PreflightKind;
    class?: string;
  }
  let { result, pending = false, error, onRetry, kind, class: className }: Props = $props();

  const KIND_WORDS: Record<PreflightKind, string> = {
    provision: 'Provisioning',
    publish: 'Publishing',
    replace: 'The replacement',
    'test-provision': 'The test provision',
  };
  const subjectWord = $derived(kind ? KIND_WORDS[kind] : 'The operation');

  const pick = $derived(result?.wouldSelect ?? null);
  const pickRows = $derived.by((): KeyValueRow[] => {
    if (!pick) return [];
    const rows: KeyValueRow[] = [];
    if (pick.accountName || pick.accountId) {
      rows.push({
        label: 'Account',
        value: pick.accountName ?? `Account ${shortId(pick.accountId)}`,
      });
    }
    if (pick.provider) rows.push({ label: 'Provider', value: providerLabel(pick.provider) });
    if (pick.listenerKey) rows.push({ label: 'Listener', value: pick.listenerKey, mono: true });
    if (pick.standbyEdgeId) {
      rows.push({
        label: 'Edge',
        value: `Standby edge ${shortId(pick.standbyEdgeId)}`,
        hint: 'An existing standby is published, nothing new is created.',
      });
    }
    if (pick.templateId)
      rows.push({ label: 'Template', value: `Template ${shortId(pick.templateId)}` });
    return rows;
  });
</script>

<div class={cn('space-y-3', className)} aria-live="polite" aria-busy={pending}>
  {#if error !== undefined && error !== null}
    <AdminListState {error} {onRetry} />
  {:else if pending && !result}
    <div class="space-y-2" role="status">
      <span class="sr-only">Checking</span>
      <Skeleton class="h-9 w-full" />
      <Skeleton class="h-9 w-2/3" />
    </div>
  {:else if !result}
    <p class="text-muted-foreground text-sm">
      Run the check to see whether this would start, without changing anything.
    </p>
  {:else}
    {#if result.ok}
      <div
        class="flex items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm"
      >
        <CircleCheck
          class="size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
          aria-hidden="true"
        />
        <span>
          <span class="font-medium">{subjectWord} can start.</span>
          {result.warnings.length > 0 ? 'Read the notes below first.' : 'Nothing blocks it.'}
        </span>
      </div>
    {:else}
      <p class="text-sm font-medium">
        {subjectWord} cannot start yet: {result.blockers.length}
        {result.blockers.length === 1 ? 'thing blocks it' : 'things block it'}.
      </p>
    {/if}

    {#if result.blockers.length > 0}
      <div class="space-y-1.5">
        {#each result.blockers as b, i (`${b.code}:${i}`)}
          <CodeNote issue={b} tone="blocker" />
        {/each}
      </div>
    {/if}
    {#if result.warnings.length > 0}
      <div class="space-y-1.5">
        {#each result.warnings as w, i (`${w.code}:${i}`)}
          <CodeNote issue={w} tone="warning" />
        {/each}
      </div>
    {/if}

    {#if pick && pickRows.length > 0}
      <KeyValue title="What would be used" rows={pickRows}>
        {#snippet actions()}
          {#if pick.layer}<LayerBadge layer={pick.layer} />{/if}
        {/snippet}
      </KeyValue>
    {/if}
  {/if}
</div>
