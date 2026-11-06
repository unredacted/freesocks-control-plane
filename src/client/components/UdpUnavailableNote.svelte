<script lang="ts">
  /**
   * The account page's note that a Hysteria key gets its REALITY backup only
   * right now: no node serves its UDP connection for it (the account view's
   * `subscription.udpUnavailable`, convex/lib/extraModeNodes.ts). Informational:
   * the member stays connected; copying the configuration again later brings
   * the UDP connection back.
   */
  import Info from '@lucide/svelte/icons/info';
  import { t } from '../lib/i18n/index.svelte';
</script>

<div
  role="note"
  aria-labelledby="udp-unavailable-title"
  class="flex items-start gap-3 rounded-lg border border-border bg-muted/40 px-5 py-4"
>
  <Info class="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
  <div class="min-w-0 space-y-1">
    <p id="udp-unavailable-title" class="font-bold">{t('account.udpUnavailable.title')}</p>
    <p class="text-[15px] text-muted-foreground">{t('account.udpUnavailable.body')}</p>
  </div>
</div>
