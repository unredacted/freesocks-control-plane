<script lang="ts">
  /**
   * ConfirmDialog for one async call, with a caller-side validity gate and a
   * close callback. The failure is worded by the shared table (edgeErrorMessage).
   *
   * Props:
   *   open (bindable); title; body?; typed?; confirmLabel?; danger?
   *   disabled?: boolean          the caller's own validity gate (e.g. a required choice): Confirm
   *                               does nothing while it is true (the caller says why in `children`)
   *   run: () => Promise<unknown> closes on resolve, stays open with the error on reject (the
   *                               first field marked invalid is focused, else the error shown)
   *   onClose?: () => void        fired whenever the dialog closes (done or cancelled): for callers
   *                               that mount it with `open={true}` behind their own flag
   *   children?: Snippet
   */
  import { tick, type Snippet } from 'svelte';
  import InlineError from '@client/components/InlineError.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { focusFirstInvalid } from '../lib/focusInvalid';

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
  let rootEl = $state<HTMLElement | null>(null);
  let errorEl = $state<HTMLElement | null>(null);
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
      .catch(async (e: unknown) => {
        error = e;
        // The dialog body scrolls: bring the field to fix, else the error, into view.
        await tick();
        if (!focusFirstInvalid(rootEl)) errorEl?.scrollIntoView({ block: 'nearest' });
      })
      .finally(() => {
        busy = false;
      });
  }
</script>

<ConfirmDialog bind:open {title} {body} {typed} {confirmLabel} {danger} {busy} onConfirm={go}>
  <div bind:this={rootEl}>
    {@render children?.()}
    {#if error !== null}
      <div bind:this={errorEl}>
        <InlineError message={edgeErrorMessage(error)} class="mt-3" />
      </div>
    {/if}
  </div>
</ConfirmDialog>
