<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';

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
    /** Target backend after the switch — used for the body copy. */
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
    // Don't allow Escape / outside-click while the switch is in flight —
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
      <Dialog.Title>Switch to {toLabel}?</Dialog.Title>
      <Dialog.Description>
        Your current {fromLabel} subscription will be replaced with a new {toLabel} one. The old subscription
        stays usable for 24 hours so you can re-import on every device before it stops working.
      </Dialog.Description>
    </Dialog.Header>
    <ul class="text-sm space-y-1 list-disc pl-5">
      <li>A new subscription URL is issued on the {toLabel} backend</li>
      <li>The current {fromLabel} URL keeps working for 24 hours, then is deleted</li>
      <li>You'll need to re-import the new URL in each VPN client you use</li>
      {#if deviceCount > 0}
        <li>
          You currently have <strong>{deviceCount}</strong>
          connected device{deviceCount === 1 ? '' : 's'} — re-import on all of them
        </li>
      {/if}
    </ul>
    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>Cancel</Button>
      <Button onclick={onConfirm} disabled={busy} variant="destructive">
        {busy ? 'Switching…' : `Switch to ${toLabel}`}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
