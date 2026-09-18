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
   */
  import type { Snippet } from 'svelte';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';

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
  <AlertDialog.Content>
    <AlertDialog.Header>
      <AlertDialog.Title>{title}</AlertDialog.Title>
      {#if body}
        <AlertDialog.Description>{body}</AlertDialog.Description>
      {/if}
    </AlertDialog.Header>
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
      <InlineError message={edgeErrorMessage(shownError)} />
    {/if}
    <AlertDialog.Footer>
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
