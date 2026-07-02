<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';

  interface Props {
    open: boolean;
    hwid: string;
    onCancel: () => void;
    onConfirm: () => void;
    busy: boolean;
  }

  let { open = $bindable(), hwid, onCancel, onConfirm, busy }: Props = $props();

  function onOpenChange(next: boolean) {
    // Sync the parent's `open` flag, and treat external close (Escape, outside
    // click) as a cancel, but don't allow it while the revoke is in flight.
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{t('deviceRevoke.title')}</Dialog.Title>
      <Dialog.Description>
        {t('deviceRevoke.body', { suffix: hwid.slice(-6) })}
      </Dialog.Description>
    </Dialog.Header>
    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
      <Button onclick={onConfirm} disabled={busy} variant="destructive">
        {busy ? t('deviceRevoke.working') : t('deviceRevoke.confirm')}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
