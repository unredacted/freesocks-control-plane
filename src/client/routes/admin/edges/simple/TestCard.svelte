<script lang="ts">
  /**
   * The test card: one line per address to try from a real client. Each line
   * shows the isolated test link (TestLink: its QR code, a 44px "Copy link"
   * button, which catalog apps take it, the full link behind "Show the full
   * link") and two answers: "Works" echoes the binding the
   * line was built from, EXACTLY (`edgeId`, `endpoint`, `listenerRevision`,
   * `configHash`; the server refuses a stale one); "Doesn't work" replaces that
   * one address. A ticked line stays on the card, folded to its "Works" mark.
   *
   * With `confirmFails`, "Doesn't work" first asks (ConfirmDialog): the dialog
   * names the address and says it is removed and replaced, so a mis-press
   * costs nothing. A caller whose "Doesn't work" opens its own dialog leaves it off.
   *
   * Props:
   *   items: TestItem[]
   *   done: ReadonlySet<string>            edge ids already ticked
   *   busyId?: string | null               a line whose answer is being saved
   *   locked?: boolean                     every answer waits (the card is being rebuilt)
   *   onWorks: (item: TestItem) => void
   *   onFails?: (item: TestItem) => void   "Doesn't work" (no button without it)
   *   confirmFails?: boolean               ask before `onFails` (default false)
   *   intro?: string                       the sentence above the lines
   *
   * A REALITY line (`item.reality`) also says to try a sing-box or Mihomo
   * client, or, when its transport refuses them, why and the fix: a test with
   * an Xray client alone would pass while those members cannot connect.
   */
  import Check from '@lucide/svelte/icons/check';
  import { Button } from '@client/components/ui/button';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import TestLink from './TestLink.svelte';
  import { replaceWords, type TestItem } from './runWords';
  import { REALITY_TEST_ADVICE, realityRefusalWords } from '@client/lib/realityClientWords';

  interface Props {
    items: TestItem[];
    done: ReadonlySet<string>;
    busyId?: string | null;
    locked?: boolean;
    onWorks: (item: TestItem) => void;
    onFails?: (item: TestItem) => void;
    confirmFails?: boolean;
    intro?: string;
  }
  let {
    items,
    done,
    busyId = null,
    locked = false,
    onWorks,
    onFails,
    confirmFails = false,
    intro = 'Scan or copy each test link into a client on the device you test with (it uses a test account of its own), connect, and load a page.',
  }: Props = $props();

  const waiting = $derived(busyId !== null || locked);

  // "Doesn't work" asks first: the line it would remove, in words.
  let asking = $state<TestItem | null>(null);
  let askOpen = $state(false);
  const askWords = $derived(asking ? replaceWords(asking) : null);
  function failPressed(item: TestItem): void {
    if (!confirmFails) return onFails?.(item);
    asking = item;
    askOpen = true;
  }
</script>

<div class="space-y-3">
  <p class="text-sm">{intro}</p>
  <ul class="space-y-2">
    {#each items as item (item.edgeId)}
      {@const ticked = done.has(item.edgeId)}
      {@const named = item.method === 'named_connection' || item.link === ''}
      <li class="bg-card rounded-md border p-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="min-w-0 text-sm font-medium break-all">
            {item.name ?? 'Address'}
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
              This address is already in use. In your client, pick the connection to
              <span class="font-mono">{item.endpoint}</span> with fallback off, connect and load a page.
            </p>
          {:else}
            <div class="mt-3">
              <TestLink
                link={item.link}
                label={`Copy the test link for ${item.name ?? item.endpoint}`}
              />
            </div>
          {/if}
          {#if item.reality?.refusal}
            {@const r = realityRefusalWords(item.reality.refusal)}
            <!-- An Xray client passes here while members on the others cannot connect. -->
            <div class="mt-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs">
              <p class="font-medium">{r.title}</p>
              <p class="mt-1">{r.why}</p>
              <p class="mt-1">{r.fix} Test with one of those clients, not only an Xray one.</p>
            </div>
          {:else if item.reality}
            <p class="text-muted-foreground mt-2 text-xs">{REALITY_TEST_ADVICE}</p>
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
                onclick={() => failPressed(item)}
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

{#if confirmFails && askWords}
  <ConfirmDialog
    bind:open={askOpen}
    title={askWords.title}
    body={askWords.body}
    confirmLabel="Remove and replace"
    cancelLabel="Keep it"
    danger
    onConfirm={() => {
      const item = asking;
      askOpen = false;
      if (item) onFails?.(item);
    }}
  />
{/if}
