<script lang="ts">
  /**
   * A2 (launch P0): the reveal-once account-number moment — the single
   * highest-stakes screen in the product. The 32-digit number is the user's
   * ONLY, unrecoverable credential. This modal makes losing it hard:
   *  - blocking AlertDialog: dismissal is refused until the user ticks
   *    "I have saved it" (modeled on the admin RevealModal),
   *  - a `beforeunload` guard while it's open (refresh/close/back is intercepted),
   *  - Copy is AWAITED with a manual-copy fallback (never a false "Copied"),
   *  - Download (.txt) so there's an offline artifact,
   *  - digits grouped into quads for transcription; copy/download use the raw form.
   *
   * Used for BOTH the initial reveal (GetAccount) and the rotate reveal
   * (Account) — losing the new number after a rotation is equally fatal.
   */
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { toast } from 'svelte-sonner';
  import { t } from '../lib/i18n/index.svelte';
  import Copy from '@lucide/svelte/icons/copy';
  import Download from '@lucide/svelte/icons/download';
  import ShieldAlert from '@lucide/svelte/icons/shield-alert';

  interface Props {
    open: boolean;
    accountId: string;
    /** Optional extra line (e.g. for the rotate flow: the old number stopped working). */
    rotated?: boolean;
    onClose: () => void;
  }

  let { open = $bindable(), accountId, rotated = false, onClose }: Props = $props();

  let acknowledged = $state(false);

  const grouped = $derived(accountId.replace(/(\d{4})(?=\d)/g, '$1 '));

  // beforeunload guard: while the number is on screen and unacknowledged, warn
  // before a refresh / tab close / back-forward unload.
  $effect(() => {
    if (!open || acknowledged) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  });

  async function copy() {
    try {
      if (!navigator.clipboard) throw new Error('no clipboard');
      await navigator.clipboard.writeText(accountId);
      toast.success(t('common.copied'));
    } catch {
      toast.error(t('common.copyFailed'));
    }
  }

  function download() {
    try {
      const blob = new Blob(
        [`FreeSocks account number\n\n${accountId}\n\n${t('reveal.cannotRecover')}\n`],
        { type: 'text/plain' },
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = t('reveal.downloadFilename');
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error(t('common.copyFailed'));
    }
  }

  function onOpenChange(next: boolean) {
    if (!next && !acknowledged) {
      toast.warning(t('reveal.leaveWarning'));
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
      <AlertDialog.Title class="flex items-center gap-2">
        <ShieldAlert class="size-5 text-amber-600 dark:text-amber-500" aria-hidden="true" />
        {t('reveal.title')}
      </AlertDialog.Title>
      <AlertDialog.Description>
        {t('reveal.subtitle')}
        {#if rotated}
          <span class="mt-1 block font-medium">{t('reveal.cannotRecover')}</span>
        {/if}
      </AlertDialog.Description>
    </AlertDialog.Header>

    <!-- Deliberately NOT aria-live: auto-announcing the only credential aloud is a
         shoulder-surf/shared-device hazard. The dialog title gives SR users context;
         the number stays plain focusable, select-all text. -->
    <p
      class="block select-all rounded-md border border-border bg-muted px-3 py-4 text-center font-mono text-lg tracking-wider break-words"
      data-testid="account-number"
    >
      {grouped}
    </p>
    <p class="text-xs text-muted-foreground">{t('reveal.saveHint')}</p>

    <div class="flex flex-wrap gap-2">
      <Button onclick={copy} variant="outline" size="sm" class="min-h-11">
        <Copy class="size-4" />
        {t('common.copy')}
      </Button>
      <Button onclick={download} variant="outline" size="sm" class="min-h-11">
        <Download class="size-4" />
        {t('common.download')}
      </Button>
    </div>

    <label class="flex cursor-pointer select-none items-center gap-2 text-sm">
      <Checkbox bind:checked={acknowledged} id="ack-account-number" />
      {t('reveal.confirmCheckbox')}
    </label>

    <AlertDialog.Footer>
      <Button onclick={done} disabled={!acknowledged} class="min-h-11">
        {t('reveal.done')}
      </Button>
    </AlertDialog.Footer>
  </AlertDialog.Content>
</AlertDialog.Root>
