<script lang="ts">
  /**
   * One isolated test link, ready to try from a real client: the link as a QR
   * code (scan it with the phone you test on), a 44px "Copy link" button, which
   * catalog apps take a single link, and the full link behind "Show the full
   * link", and the note that the profile is for a short test only
   * (TEST_PROFILE_NOTE). Shared by the edge test card (TestCard) and the
   * direct node's test card on Servers, so the two never drift.
   *
   * Props:
   *   link: string    the test link
   *   label: string   what the copy button says to a screen reader
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import * as Collapsible from '@client/components/ui/collapsible';
  import QrCode from '@client/components/QrCode.svelte';
  import { configQuery } from '@client/lib/queries';
  import { shareLinkApps } from '@client/lib/appLinks';
  import CopyButton from '../components/CopyButton.svelte';
  import { TEST_PROFILE_NOTE } from './runWords';

  let { link, label }: { link: string; label: string } = $props();

  // The member catalog says which apps take a single link (cached app-wide).
  const config = configQuery();
  const apps = $derived(shareLinkApps(config.data?.clients ?? [], link));
</script>

<div class="flex flex-col gap-3 sm:flex-row sm:items-start">
  <QrCode text={link} size={168} class="shrink-0 self-center sm:self-start" />
  <div class="min-w-0 flex-1 space-y-2">
    <CopyButton value={link} text="Copy link" {label} class="h-11 w-full sm:w-auto" />
    <p class="text-muted-foreground text-xs">
      {#if apps.length > 0}
        Works in {apps.join(', ')}, and other apps that import a single link.
      {:else}
        Import it into any app that takes a single link.
      {/if}
    </p>
    <p class="text-muted-foreground text-xs">{TEST_PROFILE_NOTE}</p>
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
          >{link}</code
        >
      </Collapsible.Content>
    </Collapsible.Root>
  </div>
</div>
