<script lang="ts">
  /**
   * One server code (a blocker, a warning, a refusal) in words: what it is, what
   * it means, what to do. Never shows the bare code.
   *
   * Props:
   *   issue: { code: string; subject?: string | null; detail?: string | null }
   *       SetupBlocker and PreflightIssue both fit. `subject` names the thing
   *       (a slug, an account, a listener key); `detail` is a short server hint.
   *   tone?: 'blocker' | 'warning' | 'info'     default 'blocker'
   *   compact?: boolean                         label + fix on one line, no explanation
   *   actions?: Snippet                         e.g. a "Fix it" link, right-aligned
   *   class?: string
   */
  import type { Snippet } from 'svelte';
  import OctagonAlert from '@lucide/svelte/icons/octagon-alert';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import Info from '@lucide/svelte/icons/info';
  import { cn } from '@client/lib/utils';
  import {
    EDGE_CODE_COPY,
    codeExplain,
    codeFix,
    codeLabel,
    humanizeCode,
  } from '@client/lib/edgeCodes';
  import type { CodeIssue } from '../lib/types';

  interface Props {
    issue: CodeIssue;
    tone?: 'blocker' | 'warning' | 'info';
    compact?: boolean;
    actions?: Snippet;
    class?: string;
  }
  let { issue, tone = 'blocker', compact = false, actions, class: className }: Props = $props();

  // Refusals arrive as `edge.<code>` on thrown errors; the copy is keyed by the bare code.
  const code = $derived(issue.code.replace(/^edge\./, ''));
  const known = $derived(EDGE_CODE_COPY[code] !== undefined);
  const subject = $derived('subject' in issue ? (issue.subject ?? null) : null);
  // The server hint is shown only when it adds something: never when it merely repeats the code.
  const detail = $derived(
    issue.detail && issue.detail !== issue.code && humanizeCode(issue.detail) !== codeLabel(code)
      ? issue.detail
      : null,
  );

  const TONE = {
    blocker: 'border-destructive/40 bg-destructive/10',
    warning: 'border-amber-500/40 bg-amber-500/10',
    info: 'border-sky-500/40 bg-sky-500/10',
  } as const;
  const ICON_TONE = {
    blocker: 'text-destructive',
    warning: 'text-amber-600 dark:text-amber-400',
    info: 'text-sky-600 dark:text-sky-400',
  } as const;
  const TONE_WORD = { blocker: 'Blocker', warning: 'Warning', info: 'Note' } as const;
</script>

<div class={cn('flex gap-2.5 rounded-md border px-3 py-2 text-sm', TONE[tone], className)}>
  <span class={cn('mt-0.5 shrink-0', ICON_TONE[tone])} aria-hidden="true">
    {#if tone === 'blocker'}
      <OctagonAlert class="size-4" />
    {:else if tone === 'warning'}
      <TriangleAlert class="size-4" />
    {:else}
      <Info class="size-4" />
    {/if}
  </span>
  <div class="min-w-0 flex-1">
    <p class="font-medium">
      <span class="sr-only">{TONE_WORD[tone]}: </span>{codeLabel(code)}{#if subject}<span
          class="text-muted-foreground font-normal"
        >
          ({subject})</span
        >{/if}
    </p>
    {#if !compact && known}
      <p class="text-muted-foreground">{codeExplain(code)}</p>
    {/if}
    {#if detail}
      <p class="text-muted-foreground break-words">Detail: {detail}</p>
    {/if}
    {#if codeFix(code)}
      <p class={cn(!compact && 'mt-0.5')}>{codeFix(code)}</p>
    {/if}
  </div>
  {#if actions}
    <div class="flex shrink-0 items-start gap-1.5">{@render actions()}</div>
  {/if}
</div>
