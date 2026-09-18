<script lang="ts">
  /**
   * The test card: one line per address to try from a real client. Each line
   * shows the isolated test link (copy button) and a "Works" tick that echoes
   * the binding the line was built from, EXACTLY (`edgeId`, `endpoint`,
   * `listenerRevision`, `configHash`); the server refuses a stale one.
   *
   * Props:
   *   items: TestItem[]
   *   done: ReadonlySet<string>            edge ids already ticked
   *   busyId?: string | null               a tick in flight
   *   onWorks: (item: TestItem) => void
   *   intro?: string                       the sentence above the lines
   */
  import Check from '@lucide/svelte/icons/check';
  import { Button } from '@client/components/ui/button';
  import CopyButton from '../components/CopyButton.svelte';
  import type { TestItem } from './runWords';

  interface Props {
    items: TestItem[];
    done: ReadonlySet<string>;
    busyId?: string | null;
    onWorks: (item: TestItem) => void;
    intro?: string;
  }
  let {
    items,
    done,
    busyId = null,
    onWorks,
    intro = 'Import this test link into a client (it uses FCP’s own test account), connect, load a page.',
  }: Props = $props();
</script>

<div class="space-y-3">
  <p class="text-sm">{intro}</p>
  <ul class="space-y-2">
    {#each items as item (item.edgeId)}
      {@const ticked = done.has(item.edgeId)}
      <li class="bg-card rounded-md border p-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="text-sm font-medium">
            {item.listenerKey}
            <span class="text-muted-foreground font-normal">{item.endpoint}</span>
          </span>
          {#if ticked}
            <span class="flex items-center gap-1 text-sm text-emerald-700 dark:text-emerald-300">
              <Check class="size-4" aria-hidden="true" /> Works
            </span>
          {:else}
            <Button
              size="sm"
              variant="outline"
              disabled={busyId !== null}
              onclick={() => onWorks(item)}
            >
              {busyId === item.edgeId ? 'Saving' : 'Works'}
            </Button>
          {/if}
        </div>
        {#if item.method === 'named_connection' || item.link === ''}
          <p class="text-muted-foreground mt-2 text-xs">
            This address is already in use. In your client, select the connection named
            <span class="font-mono">{item.listenerKey}</span> with fallback off, connect and load a page.
          </p>
        {:else}
          <div class="mt-2 flex items-center gap-1">
            <code
              class="bg-muted min-w-0 flex-1 truncate rounded px-2 py-1 text-xs"
              title={item.link}>{item.link}</code
            >
            <CopyButton value={item.link} label="Copy the test link" />
          </div>
        {/if}
      </li>
    {/each}
  </ul>
</div>
