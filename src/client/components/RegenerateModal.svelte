<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';

  interface Props {
    open: boolean;
    shortUuid: string;
    deviceCount: number;
    onCancel: () => void;
    onConfirm: () => void;
    busy: boolean;
  }

  let { open = $bindable(), shortUuid, deviceCount, onCancel, onConfirm, busy }: Props = $props();

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
        {t('regen.body', { suffix: shortUuid.slice(-6) })}
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
