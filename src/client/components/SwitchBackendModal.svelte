<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Confirmation dialog for `/api/v1/account/switch-backend`. Mirrors the
   * regenerate-modal shape so the two destructive-ish account actions feel
   * consistent: a clear description of consequences, a bulleted list of
   * what the user needs to do next, and a destructive-style commit button.
   *
   * The actual mutation lives in `Account.svelte` so this component stays
   * purely presentational and reusable from anywhere a backend switch is
   * triggered.
   */
  interface Props {
    open: boolean;
    /** Target backend after the switch, used for the body copy. */
    targetBackend: 'remnawave' | 'outline';
    /** Current backend, for the "from X to Y" framing. */
    currentBackend: 'remnawave' | 'outline';
    /** Admin-configurable labels (default to provider names). */
    labels: { remnawave: string; outline: string };
    deviceCount: number;
    onCancel: () => void;
    onConfirm: () => void;
    busy: boolean;
  }

  let {
    open = $bindable(),
    targetBackend,
    currentBackend,
    labels,
    deviceCount,
    onCancel,
    onConfirm,
    busy,
  }: Props = $props();

  let fromLabel = $derived(labels[currentBackend]);
  let toLabel = $derived(labels[targetBackend]);

  function onOpenChange(next: boolean) {
    // Don't allow Escape / outside-click while the switch is in flight:
    // a mid-request close could leave the user in an ambiguous state about
    // whether the new subscription was actually issued.
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{t('switch.title', { to: toLabel })}</Dialog.Title>
      <Dialog.Description>
        {t('switch.body', { from: fromLabel, to: toLabel })}
      </Dialog.Description>
    </Dialog.Header>
    <ul class="text-sm space-y-1 list-disc ps-5">
      <li>{t('switch.point1', { to: toLabel })}</li>
      <li>{t('switch.point2', { from: fromLabel })}</li>
      <li>{t('switch.point3')}</li>
      {#if deviceCount > 0}
        <li>{t('switch.pointDevices', { count: deviceCount })}</li>
      {/if}
    </ul>
    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
      <Button onclick={onConfirm} disabled={busy} variant="destructive">
        {busy ? t('switch.working') : t('switch.confirm', { to: toLabel })}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
