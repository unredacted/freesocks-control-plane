<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Confirmation dialog for rotating the account number - the most destructive
   * member action (it invalidates the only credential immediately). Mirrors
   * RegenerateModal/SwitchBackendModal so all three destructive account actions
   * share one shape: Dialog with focus trap + Escape, consequences up front,
   * destructive commit button, close blocked while the mutation is in flight.
   * The reveal of the NEW number afterwards stays in AccountNumberReveal.
   */
  interface Props {
    open: boolean;
    onCancel: () => void;
    onConfirm: () => void;
    busy: boolean;
  }

  let { open = $bindable(), onCancel, onConfirm, busy }: Props = $props();

  function onOpenChange(next: boolean) {
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{t('account.rotateTitle')}</Dialog.Title>
      <Dialog.Description>{t('account.rotateBody')}</Dialog.Description>
    </Dialog.Header>
    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
      <Button onclick={onConfirm} disabled={busy} variant="destructive">
        {busy ? t('account.rotating') : t('account.rotateConfirm')}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
