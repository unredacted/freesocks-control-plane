<script lang="ts">
  /**
   * A2 (launch P0): the reveal-once account-number moment - the single
   * highest-stakes screen in the product. The 32-digit number is the user's
   * ONLY, unrecoverable credential. This modal makes losing it hard with a
   * two-step flow:
   *  - step "save": the number is shown with Copy + Download; Continue stays
   *    disabled until Download is clicked, so an offline artifact exists,
   *  - step "verify": the number is HIDDEN (so it can't just be copied back
   *    off the screen) and the user must paste/type it to prove they saved a
   *    copy; Done unlocks only on an exact match. Back re-shows the number.
   *  - blocking AlertDialog: dismissal is refused until verification passes,
   *  - a `beforeunload` guard while unverified (refresh/close/back intercepted),
   *  - Copy is AWAITED with a manual-copy fallback (never a false "Copied"),
   *  - digits grouped into quads for transcription; copy/download use the raw form.
   *
   * Used for BOTH the initial reveal (GetAccount) and the rotate reveal
   * (Account) - losing the new number after a rotation is equally fatal.
   */
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { toast } from 'svelte-sonner';
  import { t } from '../lib/i18n/index.svelte';
  import { copyText } from '../lib/utils';
  import Copy from '@lucide/svelte/icons/copy';
  import Download from '@lucide/svelte/icons/download';
  import ShieldAlert from '@lucide/svelte/icons/shield-alert';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import ArrowLeft from '@lucide/svelte/icons/arrow-left';

  interface Props {
    open: boolean;
    accountId: string;
    /** Optional extra line (e.g. for the rotate flow: the old number stopped working). */
    rotated?: boolean;
    onClose: () => void;
  }

  let { open = $bindable(), accountId, rotated = false, onClose }: Props = $props();

  let step = $state<'save' | 'verify'>('save');
  let downloaded = $state(false);
  let entry = $state('');

  const grouped = $derived(accountId.replace(/(\d{4})(?=\d)/g, '$1 '));
  // Tolerate pasted quad-grouping / stray whitespace: compare digits only.
  const entryDigits = $derived(entry.replace(/\D/g, ''));
  const verified = $derived(entryDigits.length > 0 && entryDigits === accountId);
  // Only flag a mismatch once a full-length attempt is in - not while typing.
  const mismatch = $derived(entryDigits.length >= accountId.length && !verified);

  // Fresh state every time the modal (re)opens.
  $effect(() => {
    if (open) {
      step = 'save';
      downloaded = false;
      entry = '';
    }
  });

  // beforeunload guard: while the number is unverified, warn before a
  // refresh / tab close / back-forward unload.
  $effect(() => {
    if (!open || verified) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  });

  async function copy() {
    if (await copyText(accountId)) toast.success(t('common.copied'));
    else toast.error(t('common.copyFailed'));
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
      downloaded = true;
    } catch {
      toast.error(t('common.copyFailed'));
    }
  }

  function onOpenChange(next: boolean) {
    if (!next && !verified) {
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
        {#if step === 'save'}
          <ShieldAlert class="size-5 text-amber-600 dark:text-amber-500" aria-hidden="true" />
          {t('reveal.title')}
        {:else}
          <ShieldCheck class="size-5 text-primary" aria-hidden="true" />
          {t('reveal.verifyTitle')}
        {/if}
      </AlertDialog.Title>
      <AlertDialog.Description>
        {#if step === 'save'}
          {t('reveal.subtitle')}
          {#if rotated}
            <span class="mt-1 block font-medium">{t('reveal.cannotRecover')}</span>
          {/if}
        {:else}
          {t('reveal.verifySubtitle')}
        {/if}
      </AlertDialog.Description>
    </AlertDialog.Header>

    {#if step === 'save'}
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
        <Button
          onclick={download}
          variant={downloaded ? 'outline' : 'default'}
          size="sm"
          class="min-h-11"
        >
          <Download class="size-4" />
          {t('common.download')}
        </Button>
      </div>

      {#if !downloaded}
        <p class="text-xs text-muted-foreground">{t('reveal.downloadRequired')}</p>
      {/if}

      <AlertDialog.Footer>
        <Button
          onclick={() => (step = 'verify')}
          disabled={!downloaded}
          class="min-h-11"
          data-testid="reveal-continue"
        >
          {t('reveal.continue')}
        </Button>
      </AlertDialog.Footer>
    {:else}
      <!-- The number is intentionally NOT rendered on this step: pasting it back
           must come from the user's saved copy, not from the screen. -->
      <Input
        type="text"
        inputmode="numeric"
        autocomplete="off"
        spellcheck={false}
        bind:value={entry}
        placeholder={t('reveal.verifyPlaceholder')}
        aria-label={t('reveal.verifyPlaceholder')}
        aria-invalid={mismatch}
        class="font-mono tracking-wider"
        data-testid="reveal-verify-input"
      />
      {#if mismatch}
        <p class="text-xs text-destructive" role="alert">{t('reveal.verifyMismatch')}</p>
      {/if}

      <AlertDialog.Footer class="gap-2">
        <Button onclick={() => (step = 'save')} variant="outline" class="min-h-11">
          <ArrowLeft class="size-4" />
          {t('reveal.back')}
        </Button>
        <Button onclick={done} disabled={!verified} class="min-h-11" data-testid="reveal-done">
          {t('reveal.done')}
        </Button>
      </AlertDialog.Footer>
    {/if}
  </AlertDialog.Content>
</AlertDialog.Root>
