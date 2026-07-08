<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Confirmation dialog for `/api/v1/account/switch-mode` (the connection-mode /
   * transport choice). Mirrors SwitchBackendModal: switching a mode re-issues the
   * member's key into a different node/placement and tombstones the old one with
   * a 24h grace window, so it warrants the same explicit confirmation. Purely
   * presentational — the mutation lives in Account.svelte.
   */
  interface Props {
    open: boolean;
    /** Human label of the mode being switched TO (localized title). */
    targetLabel: string;
    deviceCount: number;
    onCancel: () => void;
    onConfirm: () => void;
    busy: boolean;
  }

  let { open = $bindable(), targetLabel, deviceCount, onCancel, onConfirm, busy }: Props = $props();

  function onOpenChange(next: boolean) {
    // Don't allow Escape / outside-click while the switch is in flight: a
    // mid-request close could leave the user unsure whether the new key issued.
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{t('delivery.confirmTitle', { label: targetLabel })}</Dialog.Title>
      <Dialog.Description>
        {t('delivery.confirmBody', { label: targetLabel })}
      </Dialog.Description>
    </Dialog.Header>
    <ul class="text-sm space-y-1 list-disc ps-5">
      <li>{t('delivery.confirmPoint1', { label: targetLabel })}</li>
      <li>{t('delivery.confirmPoint2')}</li>
      <li>{t('delivery.confirmPoint3')}</li>
      {#if deviceCount > 0}
        <li>{t('delivery.confirmPointDevices', { count: deviceCount })}</li>
      {/if}
    </ul>
    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
      <Button onclick={onConfirm} disabled={busy} variant="destructive">
        {busy ? t('delivery.working') : t('delivery.confirm')}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
