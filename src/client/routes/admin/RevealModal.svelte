<script lang="ts">
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { toast } from 'svelte-sonner';

  interface Props {
    open: boolean;
    token: { plaintext: string; name: string };
    onClose: () => void;
  }

  let { open = $bindable(), token, onClose }: Props = $props();

  let copied = $state(false);
  let acknowledged = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(token.plaintext);
      copied = true;
      toast.success('Token copied to clipboard');
      setTimeout(() => (copied = false), 2000);
    } catch {
      toast.error('Copy failed — select the token text above and copy it manually.');
    }
  }

  // Block accidental dismissal until the user has explicitly acknowledged
  // that they saved the token. The plaintext is only available right now;
  // if they lose it, revoke + recreate is the only recovery path.
  function onOpenChange(next: boolean) {
    if (!next && !acknowledged) {
      // User tried to dismiss (Escape, outside click, X) without confirming.
      // Refuse the close and surface the reason.
      toast.warning('Confirm you saved the token first', {
        description:
          "Closing now means losing the plaintext forever. Tick the checkbox if you've saved it.",
      });
      open = true;
      return;
    }
    open = next;
    if (!next) onClose();
  }

  function done() {
    open = false;
    onClose();
  }
</script>

<AlertDialog.Root bind:open {onOpenChange}>
  <AlertDialog.Content>
    <AlertDialog.Header>
      <AlertDialog.Title>Save your token now</AlertDialog.Title>
      <AlertDialog.Description>
        This is the only time you'll see <strong>{token.name}</strong>'s plaintext value. Copy it
        and store it somewhere safe — it cannot be recovered if you close this dialog without saving
        it.
      </AlertDialog.Description>
    </AlertDialog.Header>
    <code class="block p-3 bg-muted rounded text-xs font-mono break-all">{token.plaintext}</code>
    <label class="flex items-center gap-2 text-sm cursor-pointer select-none">
      <Checkbox bind:checked={acknowledged} id="ack-saved" />
      I have saved this token in a secure place.
    </label>
    <AlertDialog.Footer>
      <Button onclick={copy} variant="outline">{copied ? 'Copied!' : 'Copy'}</Button>
      <Button onclick={done} disabled={!acknowledged}>
        {acknowledged ? 'Done' : 'Confirm save first'}
      </Button>
    </AlertDialog.Footer>
  </AlertDialog.Content>
</AlertDialog.Root>
