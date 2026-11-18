<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Confirmation dialog for `/api/v1/account/switch-mode` (the connection-mode /
   * transport choice). Private destinations require a separate opt-in to
   * preserve unsealed subscription links.
   */
  interface Props {
    open: boolean;
    /** Human label of the mode being switched TO (localized title). */
    targetLabel: string;
    privateTarget: boolean;
    deviceCount: number;
    onCancel: () => void;
    onConfirm: (keepUnsealedUrls: boolean) => void;
    busy: boolean;
  }

  let {
    open = $bindable(),
    targetLabel,
    privateTarget,
    deviceCount,
    onCancel,
    onConfirm,
    busy,
  }: Props = $props();

  let keepUnsealedUrls = $state(false);

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
        {privateTarget
          ? t('delivery.privateSwitchBody')
          : t('delivery.confirmBody', { label: targetLabel })}
      </Dialog.Description>
    </Dialog.Header>
    {#if privateTarget}
      <label class="flex items-start gap-2 text-sm">
        <input type="checkbox" bind:checked={keepUnsealedUrls} disabled={busy} />
        {t('delivery.keepUnsealedUrls')}
      </label>
    {:else}
      <ul class="text-sm space-y-1 list-disc ps-5">
        <li>{t('delivery.confirmPoint1', { label: targetLabel })}</li>
        <li>{t('delivery.confirmPoint2')}</li>
        {#if deviceCount > 0}
          <li>{t('delivery.confirmPointDevices', { count: deviceCount })}</li>
        {/if}
      </ul>
    {/if}
    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
      <Button
        onclick={() => onConfirm(privateTarget && keepUnsealedUrls)}
        disabled={busy}
        variant="default"
      >
        {busy ? t('delivery.working') : t('delivery.confirm')}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
