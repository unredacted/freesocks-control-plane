<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';

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
    // click) as a cancel — but don't allow it while a regen is in flight.
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>Regenerate subscription?</Dialog.Title>
      <Dialog.Description>
        Your current subscription URL (ending
        <code class="font-mono">…{shortUuid.slice(-6)}</code>) will be replaced with a new one. The
        old URL becomes read-only for 24 hours, then is deleted.
      </Dialog.Description>
    </Dialog.Header>
    <ul class="text-sm space-y-1 list-disc pl-5">
      <li>Your current key remains usable for the next 24 hours</li>
      <li>You'll need to re-import the new URL in each of your devices</li>
      {#if deviceCount > 0}
        <li>
          You currently have <strong>{deviceCount}</strong>
          connected device{deviceCount === 1 ? '' : 's'} — they'll all need re-import
        </li>
      {/if}
    </ul>
    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>Cancel</Button>
      <Button onclick={onConfirm} disabled={busy} variant="destructive">
        {busy ? 'Regenerating…' : 'Regenerate'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
