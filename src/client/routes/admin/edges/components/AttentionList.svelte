<script lang="ts">
  /**
   * Ranked attention rows (the server ranks; this keeps the order), one action
   * button each, toned by severity. Each row is one IssueRow: title, who it is
   * about and the brief facts; why, the reason, what to do and the full facts
   * wait behind its disclosure. Every `AttentionAction` literal is handled
   * (lib/attention.ts, typechecked complete):
   *
   *   pure navigation, done here:
   *     open_setup          -> the origin's details
   *     open_relay          -> the origin page (rotations tab + ?rotation when the item names one)
   *     open_edge, resolve_operator -> origin page ?tab=edges&edge=<id>
   *     resolve_quarantine  -> origin page ?tab=rotations&rotation=<id>
   *     look_at_host        -> origin page ?tab=listeners&listener=<key>
   *     open_account        -> /admin/servers/providers/<id>
   *     open_settings       -> /admin/servers/settings
   *   server calls, handed to `onAction` (after a ConfirmDialog for the billable /
   *   disruptive ones: publish, provision, rotate, thaw, rebalance; none for
   *   qualify_front, test_credentials, verify_endpoint, require_edges):
   *     publish, provision, qualify_front, rotate, test_credentials, thaw, rebalance,
   *     verify_endpoint (the host opens the test card), require_edges (go live)
   *   Without `onAction` a call action falls back to navigating to the page where
   *   the operator can do it by hand (provision -> origin page ?tab=edges,
   *   verify_endpoint / require_edges -> the node page, ...). So does a call item
   *   without the ids its call needs (attentionCallable): no confirm promises a
   *   call that cannot run. The host pages run the calls with lib/attentionCalls.ts.
   *
   * Props:
   *   items: AttentionItem[]
   *   onAction?: (item: AttentionItem) => void | Promise<unknown>
   *       Only ever called for the server-call actions above, already confirmed.
   *       A returned promise keeps the row busy (and the confirm dialog open) until it settles.
   *   max?: number                          show at most this many, with a "Show all" button
   *   emptyText?: string
   *   plain?: boolean                       the simple screens: words through PLAIN_WORDS
   *                                         (origin -> protected node, edge -> address, ...),
   *                                         buttons from PLAIN_ATTENTION_ACTION_LABELS
   *   layout?: 'list' | 'bare' | 'nested'   'list' (default): its own bordered list;
   *                                         'bare': the rows only (the caller's <li> holds one);
   *                                         'nested': the items of a group (Action needed), each
   *                                         titled by its node, the kind's words left to the group
   *   sharedCode?: string | null            'nested': the reason every item of the group shares
   *                                         (the group says it and its fix once)
   *   class?: string
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Button } from '@client/components/ui/button';
  import { transportName } from '@client/lib/transportName';
  import { cn } from '@client/lib/utils';
  import { router } from '@client/stores/router.svelte';
  import {
    PLAIN_ATTENTION_ACTION_LABELS,
    codeFix,
    codeLabel,
    plainWords,
    providerAnswerWords,
  } from '@client/lib/edgeCodes';
  import IssueRow from './IssueRow.svelte';
  import ConfirmDialog from './ConfirmDialog.svelte';
  import {
    ATTENTION_ACTION_PLAN,
    attentionActionLabel,
    attentionCallable,
    attentionFactsLine,
    attentionHeading,
    attentionSubject,
    attentionTarget,
    attentionWho,
    type AttentionItem,
  } from '../lib/attention';

  interface Props {
    items: AttentionItem[];
    onAction?: (item: AttentionItem) => void | Promise<unknown>;
    max?: number;
    emptyText?: string;
    plain?: boolean;
    layout?: 'list' | 'bare' | 'nested';
    sharedCode?: string | null;
    class?: string;
  }
  let {
    items,
    onAction,
    max,
    emptyText = 'Nothing needs your attention.',
    plain = false,
    layout = 'list',
    sharedCode = null,
    class: className,
  }: Props = $props();

  /** The words of a row, rewritten for the simple screens when `plain`. */
  const w = (text: string | undefined): string | undefined =>
    text !== undefined && plain ? plainWords(text) : text;

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

  /** The row runs a call (through `onAction`) rather than navigating. */
  const calls = (item: AttentionItem): boolean =>
    !!onAction && ATTENTION_ACTION_PLAN[item.action].type === 'call' && attentionCallable(item);

  function act(item: AttentionItem) {
    const plan = ATTENTION_ACTION_PLAN[item.action];
    if (plan.type === 'navigate' || !calls(item)) {
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
  {#snippet row(item: AttentionItem)}
    {@const subject = w(attentionSubject(item))}
    {@const actionLabel = attentionActionLabel(item, plain)}
    {@const heading = attentionHeading(item, plain)}
    {@const label = heading.final ? heading.label : (w(heading.label) ?? heading.label)}
    {@const explain = heading.final ? heading.explain : w(heading.explain)}
    {@const brief = w(attentionFactsLine(item, { brief: true }))}
    {@const facts = w(attentionFactsLine(item))}
    {@const answer = providerAnswerWords(item.facts)}
    {@const fix = item.code ? w(codeFix(item.code)) : undefined}
    {@const nested = layout === 'nested'}
    <!-- Nested in a group: the group says the kind (and a reason all share) once; each row
         keeps only its own facts. -->
    {@const showExplain = !!explain && (!nested || heading.final)}
    {@const showCode = !!item.code && !(nested && item.code === sharedCode)}
    {@const who = nested ? attentionWho(item) : null}
    {@const nestedLine = [item.listenerTag ? transportName(item.listenerTag) : null, brief]
      .filter(Boolean)
      .join(' · ')}
    {@const hasDetails = showExplain || showCode || !!answer || (!!facts && facts !== brief)}
    {#snippet details()}
      {#if showExplain}<p>{explain}</p>{/if}
      {#if showCode && item.code}
        <p>
          <span class="text-foreground font-medium">Reason:</span>
          {w(codeLabel(item.code))}.
          {#if answer}<span class="text-foreground">{answer}</span>{/if}
        </p>
      {:else if answer}
        <!-- The provider's own words, as it sent them (never rewritten). -->
        <p class="text-foreground">{answer}</p>
      {/if}
      {#if fix && showCode}
        <p><span class="text-foreground font-medium">What to do:</span> {fix}</p>
      {/if}
      {#if facts && facts !== brief}<p class="text-xs">{facts}</p>{/if}
    {/snippet}
    {#snippet button()}
      <Button
        size="sm"
        variant={item.severity === 'critical' && !nested ? 'default' : 'outline'}
        disabled={busyId === item.id}
        aria-label={subject ? `${actionLabel}: ${subject}` : actionLabel}
        onclick={() => act(item)}
      >
        {busyId === item.id ? 'Working…' : actionLabel}
        {#if !calls(item)}
          <ChevronRight class="rtl:rotate-180" aria-hidden="true" />
        {/if}
      </Button>
    {/snippet}
    <IssueRow
      severity={item.severity}
      title={nested ? who || subject || brief || label : label}
      subject={nested ? null : subject}
      line={nested ? (who ? nestedLine : null) || null : brief || null}
      since={item.since}
      {nested}
      details={hasDetails ? details : undefined}
      action={button}
    />
  {/snippet}

  {#if layout === 'bare'}
    {#each shown as item (item.id)}{@render row(item)}{/each}
  {:else}
    <ul
      class={cn(
        'divide-y',
        layout === 'nested' ? 'rounded-md border' : 'bg-card rounded-lg border',
        className,
      )}
      aria-label="Needs attention"
    >
      {#each shown as item (item.id)}
        <li>{@render row(item)}</li>
      {/each}
    </ul>
  {/if}
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
    title={w(confirmCopy.title) ?? confirmCopy.title}
    body={w(confirmCopy.body)}
    confirmLabel={plain ? PLAIN_ATTENTION_ACTION_LABELS[item.action] : confirmCopy.confirmLabel}
    danger={confirmCopy.danger}
    onConfirm={() => run(item)}
    onCancel={() => (confirming = null)}
  >
    {#if attentionSubject(item)}
      <p class="text-muted-foreground">{w(attentionSubject(item))}</p>
    {/if}
  </ConfirmDialog>
{/if}
