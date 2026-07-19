<script lang="ts">
  /**
   * One-time reveal of freshly-purchased gift codes (the buyer returns from the
   * processor to /account?order=ref; Account's poll hands us the plaintext codes).
   * Mirrors AccountNumberReveal: a blocking AlertDialog gated on an "I saved them"
   * checkbox + a beforeunload guard, because the codes are bearer secrets shown
   * ONCE - the server clears the transient buffer on ack, and afterwards only a
   * prefix is ever shown.
   */
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { toast } from 'svelte-sonner';
  import { t } from '../lib/i18n/index.svelte';
  import { copyText } from '../lib/utils';
  import Copy from '@lucide/svelte/icons/copy';
  import Gift from '@lucide/svelte/icons/gift';

  interface Props {
    open: boolean;
    codes: string[];
    /** Called once the buyer acknowledges saving the codes (clears the buffer). */
    onAck: () => void;
  }
  let { open = $bindable(), codes, onAck }: Props = $props();
  let acknowledged = $state(false);

  $effect(() => {
    if (!open || acknowledged) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  });

  async function copyAll() {
    if (await copyText(codes.join('\n'))) toast.success(t('common.copied'));
    else toast.error(t('common.copyFailed'));
  }

  function onOpenChange(next: boolean) {
    if (!next && !acknowledged) {
      toast.warning(t('gift.reveal.leaveWarning'));
      open = true;
      return;
    }
    open = next;
    if (!next) onAck();
  }
  function done() {
    open = false;
    onAck();
  }
</script>

<AlertDialog.Root bind:open {onOpenChange}>
  <AlertDialog.Content>
    <AlertDialog.Header>
      <AlertDialog.Title class="flex items-center gap-2">
        <Gift class="size-5 text-primary" aria-hidden="true" />
        {t('gift.reveal.title')}
      </AlertDialog.Title>
      <AlertDialog.Description>{t('gift.reveal.body')}</AlertDialog.Description>
    </AlertDialog.Header>

    <ul class="max-h-60 space-y-1 overflow-auto rounded-md border border-border bg-muted p-3">
      {#each codes as code (code)}
        <li dir="ltr" class="select-all font-mono text-sm tracking-wider break-all">{code}</li>
      {/each}
    </ul>

    <div class="flex flex-wrap gap-2">
      <Button onclick={copyAll} variant="outline" size="sm" class="min-h-11">
        <Copy class="size-4" />
        {t('gift.copyAll')}
      </Button>
    </div>

    <label class="flex cursor-pointer select-none items-center gap-2 text-sm">
      <Checkbox bind:checked={acknowledged} id="ack-gift-codes" />
      {t('gift.reveal.ack')}
    </label>

    <AlertDialog.Footer>
      <Button onclick={done} disabled={!acknowledged} class="min-h-11">
        {t('gift.reveal.saved')}
      </Button>
    </AlertDialog.Footer>
  </AlertDialog.Content>
</AlertDialog.Root>
