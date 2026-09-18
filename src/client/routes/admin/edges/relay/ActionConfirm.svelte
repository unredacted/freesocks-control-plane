<script lang="ts">
  /**
   * ConfirmDialog for one async call, with the failure worded by the relay page
   * (relayErrorMessage covers refusals the shared table has no entry for).
   *
   * Props:
   *   open (bindable); title; body?; typed?; confirmLabel?; danger?
   *   disabled?: boolean          the caller's own validity gate (e.g. a required choice): Confirm
   *                               does nothing while it is true (the caller says why in `children`)
   *   run: () => Promise<unknown> closes on resolve, stays open with the error on reject
   *   onClose?: () => void        fired whenever the dialog closes (done or cancelled): for callers
   *                               that mount it with `open={true}` behind their own flag
   *   children?: Snippet
   */
  import type { Snippet } from 'svelte';
  import InlineError from '@client/components/InlineError.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { relayErrorMessage } from './relayErrors';

  interface Props {
    open: boolean;
    title: string;
    body?: string;
    typed?: string;
    confirmLabel?: string;
    danger?: boolean;
    disabled?: boolean;
    run: () => Promise<unknown>;
    onClose?: () => void;
    children?: Snippet;
  }
  let {
    open = $bindable(false),
    title,
    body,
    typed,
    confirmLabel,
    danger = false,
    disabled = false,
    run,
    onClose,
    children,
  }: Props = $props();

  let busy = $state(false);
  let error = $state<unknown>(null);
  let wasOpen = false;
  $effect(() => {
    if (open) {
      wasOpen = true;
      error = null;
    } else if (wasOpen) {
      wasOpen = false;
      onClose?.();
    }
  });

  function go(): void {
    if (busy || disabled) return;
    busy = true;
    error = null;
    run()
      .then(() => {
        open = false;
      })
      .catch((e: unknown) => {
        error = e;
      })
      .finally(() => {
        busy = false;
      });
  }
</script>

<ConfirmDialog bind:open {title} {body} {typed} {confirmLabel} {danger} {busy} onConfirm={go}>
  {@render children?.()}
  {#if error !== null}
    <InlineError message={relayErrorMessage(error)} class="mt-3" />
  {/if}
</ConfirmDialog>
