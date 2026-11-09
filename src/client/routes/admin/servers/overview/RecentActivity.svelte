<script lang="ts">
  /**
   * The Overview's Recent activity: one timeline, newest first, merging every
   * fronted node's runs and replacements with every backend's recent changes
   * (overviewModel.ts `mergeActivity`). Each line names whose it is and links
   * to that page.
   *
   * Props:
   *   entries: ActivityEntry[]
   */
  import Link from '@client/components/Link.svelte';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import { relativeTime } from '../../edges/lib/time';
  import type { ActivityEntry } from './overviewModel';

  let { entries }: { entries: ActivityEntry[] } = $props();
</script>

<section aria-labelledby="recent-activity">
  <h2 id="recent-activity" class="mb-3 text-base font-semibold">Recent activity</h2>
  {#if entries.length === 0}
    <p class="text-muted-foreground text-sm">Nothing has happened yet.</p>
  {:else}
    <ul class="space-y-1.5 text-sm" aria-label="Recent activity">
      {#each entries as e (e.key)}
        <li class="flex items-baseline gap-3">
          <time
            datetime={e.at}
            title={new Date(e.at).toLocaleString()}
            class="text-muted-foreground w-20 shrink-0 text-xs tabular-nums"
          >
            {relativeTime(e.at)}
          </time>
          <span class="flex min-w-0 flex-1 items-baseline gap-2">
            {#if e.dot}<StatusDot dot={e.dot} class="shrink-0 self-center" />{/if}
            <span class="min-w-0">
              {#if e.href}
                <Link href={e.href} class="font-medium hover:underline">{e.who}</Link>
              {:else}
                <span class="font-medium">{e.who}</span>
              {/if}
              <span class="text-muted-foreground">{e.text}</span>
            </span>
          </span>
        </li>
      {/each}
    </ul>
  {/if}
</section>
