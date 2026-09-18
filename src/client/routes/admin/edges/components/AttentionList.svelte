<script lang="ts">
  /**
   * Ranked attention rows (the server ranks; this keeps the order), one action
   * button each, toned by severity. Every `AttentionAction` literal is handled
   * (lib/attention.ts, typechecked complete):
   *
   *   pure navigation, done here:
   *     open_setup          -> /admin/edges/setup?relay=<slug>
   *     open_relay          -> the relay page (rotations tab + ?rotation when the item names one)
   *     open_edge, resolve_operator -> relay page ?tab=edges&edge=<id>
   *     resolve_quarantine  -> relay page ?tab=rotations&rotation=<id>
   *     look_at_host        -> relay page ?tab=listeners&listener=<key>
   *     open_account        -> /admin/edges/providers/<id>
   *     open_settings       -> /admin/edges/settings
   *   server calls, handed to `onAction` (after a ConfirmDialog for the billable /
   *   disruptive ones: publish, provision, rotate, thaw; none for qualify_front,
   *   test_credentials):
   *     publish, provision, qualify_front, rotate, test_credentials, thaw
   *   Without `onAction` a call action falls back to navigating to the page where
   *   the operator can do it by hand (provision -> relay page ?tab=edges, ...).
   *
   * Props:
   *   items: AttentionItem[]
   *   onAction?: (item: AttentionItem) => void | Promise<unknown>
   *       Only ever called for the server-call actions above, already confirmed.
   *       A returned promise keeps the row busy (and the confirm dialog open) until it settles.
   *   max?: number                          show at most this many, with a "Show all" button
   *   emptyText?: string
   *   class?: string
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Button } from '@client/components/ui/button';
  import { cn } from '@client/lib/utils';
  import { router } from '@client/stores/router.svelte';
  import { ATTENTION_ACTION_LABELS, codeExplain, codeFix, codeLabel } from '@client/lib/edgeCodes';
  import StatusBadge from './StatusBadge.svelte';
  import ConfirmDialog from './ConfirmDialog.svelte';
  import {
    ATTENTION_ACTION_PLAN,
    attentionFactsLine,
    attentionSubject,
    attentionTarget,
    type AttentionItem,
  } from '../lib/attention';
  import { relativeTime } from '../lib/time';

  interface Props {
    items: AttentionItem[];
    onAction?: (item: AttentionItem) => void | Promise<unknown>;
    max?: number;
    emptyText?: string;
    class?: string;
  }
  let {
    items,
    onAction,
    max,
    emptyText = 'Nothing needs your attention. New items appear here as soon as the fleet needs a decision.',
    class: className,
  }: Props = $props();

  let showAll = $state(false);
  const shown = $derived(max !== undefined && !showAll ? items.slice(0, max) : items);

  let confirming = $state<AttentionItem | null>(null);
  let confirmOpen = $state(false);
  let busyId = $state<string | null>(null);
  const confirmCopy = $derived.by(() => {
    if (!confirming) return null;
    const plan = ATTENTION_ACTION_PLAN[confirming.action];
    return plan.type === 'call' ? plan.confirm : null;
  });

  async function run(item: AttentionItem): Promise<void> {
    if (!onAction) return;
    busyId = item.id;
    try {
      await onAction(item);
    } finally {
      busyId = null;
    }
  }

  function act(item: AttentionItem) {
    const plan = ATTENTION_ACTION_PLAN[item.action];
    if (plan.type === 'navigate' || !onAction) {
      router.navigate(attentionTarget(item));
      return;
    }
    if (plan.confirm) {
      confirming = item;
      confirmOpen = true;
      return;
    }
    // Errors of an unconfirmed call are the host page's to show (toast); never an unhandled rejection.
    run(item).catch(() => {});
  }

  const BORDER = {
    critical: 'border-s-destructive',
    warning: 'border-s-amber-500',
    info: 'border-s-sky-500',
  } as const;
</script>

{#if items.length === 0}
  <div
    class={cn(
      'text-muted-foreground rounded-lg border border-dashed p-6 text-center text-sm',
      className,
    )}
  >
    {emptyText}
  </div>
{:else}
  <ul class={cn('space-y-2', className)} aria-label="Needs attention">
    {#each shown as item (item.id)}
      {@const plan = ATTENTION_ACTION_PLAN[item.action]}
      {@const facts = attentionFactsLine(item)}
      {@const subject = attentionSubject(item)}
      <li
        class={cn(
          'bg-card flex flex-wrap items-start gap-x-4 gap-y-2 rounded-lg border border-s-4 px-3 py-2.5',
          BORDER[item.severity],
        )}
      >
        <div class="min-w-0 flex-1 basis-64">
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge kind="severity" value={item.severity} />
            <span class="text-sm font-medium">{codeLabel(item.kind)}</span>
            {#if subject}<span class="text-muted-foreground text-sm">{subject}</span>{/if}
          </div>
          <p class="text-muted-foreground mt-1 text-sm">
            {codeExplain(item.kind)}
            {#if item.code}
              <span class="text-foreground">Reason: {codeLabel(item.code)}.</span>
            {/if}
          </p>
          {#if item.code && codeFix(item.code)}
            <p class="mt-0.5 text-sm">{codeFix(item.code)}</p>
          {/if}
          {#if facts || item.since}
            <p class="text-muted-foreground mt-1 text-xs">
              {facts}{#if facts && item.since}<span aria-hidden="true"> · </span>{/if}
              {#if item.since}
                <time datetime={item.since} title={new Date(item.since).toLocaleString()}>
                  since {relativeTime(item.since)}
                </time>
              {/if}
            </p>
          {/if}
        </div>
        <Button
          size="sm"
          variant={item.severity === 'critical' ? 'default' : 'outline'}
          disabled={busyId === item.id}
          aria-label={subject
            ? `${ATTENTION_ACTION_LABELS[item.action]}: ${subject}`
            : ATTENTION_ACTION_LABELS[item.action]}
          onclick={() => act(item)}
        >
          {busyId === item.id ? 'Working…' : ATTENTION_ACTION_LABELS[item.action]}
          {#if plan.type === 'navigate' || !onAction}
            <ChevronRight class="rtl:rotate-180" aria-hidden="true" />
          {/if}
        </Button>
      </li>
    {/each}
  </ul>
  {#if max !== undefined && items.length > max && !showAll}
    <Button variant="ghost" size="sm" class="mt-2" onclick={() => (showAll = true)}>
      Show all {items.length}
    </Button>
  {/if}
{/if}

{#if confirmCopy && confirming}
  {@const item = confirming}
  <ConfirmDialog
    bind:open={confirmOpen}
    title={confirmCopy.title}
    body={confirmCopy.body}
    confirmLabel={confirmCopy.confirmLabel}
    danger={confirmCopy.danger}
    onConfirm={() => run(item)}
    onCancel={() => (confirming = null)}
  >
    {#if attentionSubject(item)}
      <p class="text-muted-foreground">{attentionSubject(item)}</p>
    {/if}
  </ConfirmDialog>
{/if}
