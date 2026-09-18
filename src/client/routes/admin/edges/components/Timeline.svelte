<script lang="ts">
  /**
   * Audit entries in words, newest first: what happened (action -> label through
   * `auditActionLabel`), a short detail line from known payload keys, who did it,
   * and when (relative, with the exact time as a tooltip).
   *
   * Props:
   *   entries: TimelineRow[]                TimelineResponse.entries, or plain AuditEntry rows
   *                                         (EdgeRotationDetail.audit, ProbeAuditResponse.entries)
   *   truncated?: boolean                   TimelineResponse.truncated
   *   emptyText?: string
   *   hrefFor?: (entry: TimelineRow) => string | null    make an entry a link (e.g. to its rotation)
   *   max?: number                          show at most this many, with a "Show all" button
   *   label?: string                        accessible name (default 'Timeline')
   *   labelFor?: (action: string) => string the words for an action (default auditActionLabel;
   *                                         the simple node page passes plainAuditActionLabel)
   *   class?: string
   */
  import Waypoints from '@lucide/svelte/icons/waypoints';
  import Network from '@lucide/svelte/icons/network';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import Radar from '@lucide/svelte/icons/radar';
  import EthernetPort from '@lucide/svelte/icons/ethernet-port';
  import Circle from '@lucide/svelte/icons/circle';
  import type { LucideIcon } from '@lucide/svelte';
  import Link from '@client/components/Link.svelte';
  import { Button } from '@client/components/ui/button';
  import { cn } from '@client/lib/utils';
  import { auditActionLabel } from '@client/lib/edgeCodes';
  import { relativeTime } from '../lib/time';
  import { auditDetailLine } from '../lib/format';
  import { actorLabel, subjectOf } from '../lib/timeline';
  import type { TimelineRow, TimelineSubject } from '../lib/types';

  interface Props {
    entries: TimelineRow[];
    truncated?: boolean;
    emptyText?: string;
    hrefFor?: (entry: TimelineRow) => string | null;
    max?: number;
    label?: string;
    labelFor?: (action: string) => string;
    class?: string;
  }
  let {
    entries,
    truncated = false,
    emptyText = 'Nothing has happened here yet.',
    hrefFor,
    max,
    label = 'Timeline',
    labelFor = auditActionLabel,
    class: className,
  }: Props = $props();

  const ICONS: Record<TimelineSubject, LucideIcon> = {
    relay: Waypoints,
    edge: Network,
    rotation: RefreshCw,
    probe: Radar,
    listener: EthernetPort,
    other: Circle,
  };
  const SUBJECT_WORD: Record<TimelineSubject, string> = {
    relay: 'Relay',
    edge: 'Edge',
    rotation: 'Rotation',
    probe: 'Probe',
    listener: 'Listener',
    other: 'Event',
  };

  let showAll = $state(false);
  const shown = $derived(max !== undefined && !showAll ? entries.slice(0, max) : entries);
</script>

{#if entries.length === 0}
  <p class={cn('text-muted-foreground text-sm', className)}>{emptyText}</p>
{:else}
  <ol class={cn('space-y-3', className)} aria-label={label}>
    {#each shown as entry (entry.id)}
      {@const subject = subjectOf(entry)}
      {@const Icon = ICONS[subject]}
      {@const href = hrefFor?.(entry) ?? null}
      {@const detail = auditDetailLine(entry.payload)}
      <li class="flex gap-2.5 text-sm">
        <span
          class="bg-muted text-muted-foreground mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full"
          title={SUBJECT_WORD[subject]}
        >
          <Icon class="size-3.5" aria-hidden="true" />
          <span class="sr-only">{SUBJECT_WORD[subject]}: </span>
        </span>
        <div class="min-w-0 flex-1">
          <p>
            {#if href}
              <Link {href} class="font-medium underline-offset-4 hover:underline">
                {labelFor(entry.action)}
              </Link>
            {:else}
              <span class="font-medium">{labelFor(entry.action)}</span>
            {/if}
          </p>
          <p class="text-muted-foreground text-xs">
            <time datetime={entry.createdAt} title={new Date(entry.createdAt).toLocaleString()}>
              {relativeTime(entry.createdAt)}
            </time>
            <span aria-hidden="true"> · </span>{actorLabel(entry)}{#if detail}<span
                aria-hidden="true"
              >
                ·
              </span>{detail}{/if}
          </p>
        </div>
      </li>
    {/each}
  </ol>
  {#if max !== undefined && entries.length > max && !showAll}
    <Button variant="ghost" size="sm" class="mt-2" onclick={() => (showAll = true)}>
      Show all {entries.length}
    </Button>
  {/if}
  {#if truncated}
    <p class="text-muted-foreground mt-2 text-xs">
      Older entries are not shown here. The audit log has the full history.
    </p>
  {/if}
{/if}
