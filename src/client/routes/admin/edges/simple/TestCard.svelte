<script lang="ts">
  /**
   * The test card: one line per address to try from a real client. Each line
   * shows the isolated test link as a QR code (scan it with the phone you test
   * on), a 44px "Copy link" button, the full link behind "Show the full link",
   * which catalog apps take it, and two answers: "Works" echoes the binding the
   * line was built from, EXACTLY (`edgeId`, `endpoint`, `listenerRevision`,
   * `configHash`; the server refuses a stale one); "Doesn't work" replaces that
   * one address. A ticked line stays on the card, folded to its "Works" mark.
   *
   * Props:
   *   items: TestItem[]
   *   done: ReadonlySet<string>            edge ids already ticked
   *   busyId?: string | null               a line whose answer is being saved
   *   locked?: boolean                     every answer waits (the card is being rebuilt)
   *   onWorks: (item: TestItem) => void
   *   onFails?: (item: TestItem) => void   "Doesn't work" (no button without it)
   *   intro?: string                       the sentence above the lines
   */
  import Check from '@lucide/svelte/icons/check';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Button } from '@client/components/ui/button';
  import * as Collapsible from '@client/components/ui/collapsible';
  import QrCode from '@client/components/QrCode.svelte';
  import { configQuery } from '@client/lib/queries';
  import { shareLinkApps } from '@client/lib/appLinks';
  import CopyButton from '../components/CopyButton.svelte';
  import type { TestItem } from './runWords';

  interface Props {
    items: TestItem[];
    done: ReadonlySet<string>;
    busyId?: string | null;
    locked?: boolean;
    onWorks: (item: TestItem) => void;
    onFails?: (item: TestItem) => void;
    intro?: string;
  }
  let {
    items,
    done,
    busyId = null,
    locked = false,
    onWorks,
    onFails,
    intro = 'Scan or copy each test link into a client on the device you test with (it uses a test account of its own), connect, and load a page.',
  }: Props = $props();

  // The member catalog says which apps take a single link (cached app-wide).
  const config = configQuery();
  const appsFor = (link: string): string[] => shareLinkApps(config.data?.clients ?? [], link);
  const waiting = $derived(busyId !== null || locked);
</script>

<div class="space-y-3">
  <p class="text-sm">{intro}</p>
  <ul class="space-y-2">
    {#each items as item (item.edgeId)}
      {@const ticked = done.has(item.edgeId)}
      {@const named = item.method === 'named_connection' || item.link === ''}
      {@const apps = named ? [] : appsFor(item.link)}
      <li class="bg-card rounded-md border p-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="min-w-0 text-sm font-medium break-all">
            {item.listenerKey}
            <span class="text-muted-foreground font-normal">{item.endpoint}</span>
          </span>
          {#if ticked}
            <span class="flex items-center gap-1 text-sm text-emerald-700 dark:text-emerald-300">
              <Check class="size-4" aria-hidden="true" /> Works
            </span>
          {/if}
        </div>
        {#if !ticked}
          {#if named}
            <p class="text-muted-foreground mt-2 text-xs">
              This address is already in use. In your client, select the connection named
              <span class="font-mono">{item.listenerKey}</span> with fallback off, connect and load a
              page.
            </p>
          {:else}
            <div class="mt-3 flex flex-col gap-3 sm:flex-row sm:items-start">
              <QrCode text={item.link} size={168} class="shrink-0 self-center sm:self-start" />
              <div class="min-w-0 flex-1 space-y-2">
                <CopyButton
                  value={item.link}
                  text="Copy link"
                  label={`Copy the test link for ${item.listenerKey}`}
                  class="h-11 w-full sm:w-auto"
                />
                <p class="text-muted-foreground text-xs">
                  {#if apps.length > 0}
                    Works in {apps.join(', ')}, and other apps that import a single link.
                  {:else}
                    Import it into any app that takes a single link.
                  {/if}
                </p>
                <Collapsible.Root>
                  <Collapsible.Trigger
                    class="group text-muted-foreground hover:text-foreground flex min-h-11 items-center gap-1 text-xs sm:min-h-0"
                  >
                    <ChevronRight
                      class="size-4 transition-transform group-data-[state=open]:rotate-90"
                      aria-hidden="true"
                    />
                    Show the full link
                  </Collapsible.Trigger>
                  <Collapsible.Content>
                    <code class="bg-muted mt-1 block rounded px-2 py-1 text-xs break-all select-all"
                      >{item.link}</code
                    >
                  </Collapsible.Content>
                </Collapsible.Root>
              </div>
            </div>
          {/if}
          <div class="mt-3 flex flex-wrap gap-2">
            <Button
              class="h-11 flex-1 sm:h-9 sm:flex-none"
              disabled={waiting}
              onclick={() => onWorks(item)}
            >
              {busyId === item.edgeId ? 'Saving' : 'Works'}
            </Button>
            {#if onFails}
              <Button
                variant="outline"
                class="h-11 flex-1 sm:h-9 sm:flex-none"
                disabled={waiting}
                onclick={() => onFails(item)}
              >
                Doesn’t work
              </Button>
            {/if}
          </div>
        {/if}
      </li>
    {/each}
  </ul>
</div>
