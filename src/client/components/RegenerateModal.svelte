<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';

  interface Props {
    open: boolean;
    /** The opaque FCP-fronted token - its tail matches the subscription URL the
     *  page actually shows (…/api/v1/sub/<subToken>). Null on a legacy sub. */
    subToken: string | null;
    /** Raw Remnawave short id - the fallback suffix when no fronted token exists. */
    shortUuid: string;
    deviceCount: number;
    onCancel: () => void;
    onConfirm: () => void;
    busy: boolean;
  }

  let {
    open = $bindable(),
    subToken,
    shortUuid,
    deviceCount,
    onCancel,
    onConfirm,
    busy,
  }: Props = $props();

  // Match the URL the member sees/copies: the fronted token when present, else the
  // raw URL whose tail is the shortUuid. Mirrors utils.ts:subscriptionDisplayUrl's
  // own fallback so the "ending …" in the dialog always names the displayed URL.
  const suffix = $derived((subToken ?? shortUuid).slice(-6));

  function onOpenChange(next: boolean) {
    // Sync the parent's `open` flag, and treat external close (Escape, outside
    // click) as a cancel, but don't allow it while a regen is in flight.
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{t('regen.title')}</Dialog.Title>
      <Dialog.Description>
        {t('regen.body', { suffix })}
      </Dialog.Description>
    </Dialog.Header>
    <ul class="text-sm space-y-1 list-disc ps-5">
      <li>{t('regen.point1')}</li>
      <li>{t('regen.point2')}</li>
      {#if deviceCount > 0}
        <li>{t('regen.pointDevices', { count: deviceCount })}</li>
      {/if}
    </ul>
    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
      <Button onclick={onConfirm} disabled={busy} variant="destructive">
        {busy ? t('regen.working') : t('regen.confirm')}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
