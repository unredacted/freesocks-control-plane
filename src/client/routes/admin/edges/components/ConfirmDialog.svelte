<script lang="ts">
  /**
   * Confirmation dialog for anything destructive or billable.
   *
   * Props:
   *   open: boolean (bindable)
   *   title: string
   *   body?: string                     plain explanation; `children` renders under it for anything richer
   *   typed?: string                    the operator must type this exact string to enable Confirm (deletes)
   *   confirmLabel?: string             default 'Confirm'
   *   cancelLabel?: string              default 'Cancel'
   *   danger?: boolean                  destructive styling for Confirm
   *   busy?: boolean                    external busy flag (disables both buttons, keeps the dialog open)
   *   error?: unknown                   external error, shown in words (edgeErrorMessage)
   *   onConfirm: () => void | Promise<unknown>
   *       Returning a promise lets the dialog manage itself: busy while pending,
   *       closes on resolve, stays open and shows the error on reject.
   *       Returning nothing leaves closing to the caller (set `open = false`).
   *   onCancel?: () => void
   *   children?: Snippet
   *
   * It never grows past the window: the title and the buttons stay put and
   * what is between them, the explanation included, scrolls (lib/dialogLayout.ts). A failed confirm brings
   * the first field marked invalid into view, else its error.
   */
  import { tick, type Snippet } from 'svelte';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { CONFIRM_BODY, CONFIRM_FIT } from '../lib/dialogLayout';
  import { focusFirstInvalid } from '../lib/focusInvalid';

  interface Props {
    open: boolean;
    title: string;
    body?: string;
    typed?: string;
    confirmLabel?: string;
    cancelLabel?: string;
    danger?: boolean;
    busy?: boolean;
    error?: unknown;
    onConfirm: () => void | Promise<unknown>;
    onCancel?: () => void;
    children?: Snippet;
  }
  let {
    open = $bindable(false),
    title,
    body,
    typed,
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
    danger = false,
    busy = false,
    error,
    onConfirm,
    onCancel,
    children,
  }: Props = $props();

  const uid = $props.id();
  let typedValue = $state('');
  let selfBusy = $state(false);
  let selfError = $state<unknown>(null);
  let bodyEl = $state<HTMLElement | null>(null);
  let errorEl = $state<HTMLElement | null>(null);

  const working = $derived(busy || selfBusy);
  const typedOk = $derived(!typed || typedValue.trim() === typed);
  const shownError = $derived(error ?? selfError);

  // A fresh dialog every time it opens.
  $effect(() => {
    if (open) {
      typedValue = '';
      selfError = null;
    }
  });

  async function confirm() {
    if (!typedOk || working) return;
    selfError = null;
    const result = onConfirm();
    if (result instanceof Promise) {
      selfBusy = true;
      try {
        await result;
        open = false;
      } catch (e) {
        selfError = e;
        await tick();
        if (!focusFirstInvalid(bodyEl)) errorEl?.scrollIntoView({ block: 'nearest' });
      } finally {
        selfBusy = false;
      }
    }
  }
</script>

<AlertDialog.Root
  {open}
  onOpenChange={(o) => {
    if (o) {
      open = true;
    } else if (!working) {
      open = false;
      onCancel?.();
    }
  }}
>
  <AlertDialog.Content class={CONFIRM_FIT}>
    <!-- With an explanation under it, the title keeps its old, closer spacing. -->
    <AlertDialog.Header class={body ? 'shrink-0 -mb-2.5' : 'shrink-0'}>
      <AlertDialog.Title>{title}</AlertDialog.Title>
    </AlertDialog.Header>
    {#if body || children || typed || (shownError !== null && shownError !== undefined)}
      <!-- Between the title and the buttons, the explanation included: scrolls when it outgrows the window. -->
      <div bind:this={bodyEl} data-slot="confirm-body" class={CONFIRM_BODY}>
        {#if body}
          <AlertDialog.Description class="text-center sm:text-start">{body}</AlertDialog.Description
          >
        {/if}
        {#if children}
          <div class="text-sm">{@render children()}</div>
        {/if}
        {#if typed}
          <div class="space-y-1.5">
            <Label for={`${uid}-typed`}>
              Type <span class="font-mono font-semibold">{typed}</span> to confirm
            </Label>
            <Input
              id={`${uid}-typed`}
              bind:value={typedValue}
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
              disabled={working}
              onkeydown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  void confirm();
                }
              }}
            />
          </div>
        {/if}
        {#if shownError !== null && shownError !== undefined}
          <div bind:this={errorEl}><InlineError message={edgeErrorMessage(shownError)} /></div>
        {/if}
      </div>
    {/if}
    <AlertDialog.Footer class="shrink-0">
      <AlertDialog.Cancel disabled={working}>{cancelLabel}</AlertDialog.Cancel>
      <AlertDialog.Action
        variant={danger ? 'destructive' : 'default'}
        disabled={!typedOk || working}
        onclick={() => void confirm()}
      >
        {working ? 'Working…' : confirmLabel}
      </AlertDialog.Action>
    </AlertDialog.Footer>
  </AlertDialog.Content>
</AlertDialog.Root>
