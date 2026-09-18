<script lang="ts">
  /**
   * Typed-confirmation delete for a provider account or a template. Wraps the
   * shared ConfirmDialog so an in-use refusal is shown in words (refusals.ts)
   * instead of the raw server message.
   *
   * Props:
   *   open: boolean (bindable)
   *   kind: 'account' | 'template'
   *   name: string                       what the operator types to confirm
   *   body: string
   *   run: () => Promise<unknown>        the delete call
   *   ondeleted?: () => void             after a successful delete (invalidate + toast here)
   *   children?: Snippet                 extra consequences under the body
   */
  import type { Snippet } from 'svelte';
  import InlineError from '@client/components/InlineError.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { deleteRefusal } from './refusals';

  interface Props {
    open: boolean;
    kind: 'account' | 'template';
    name: string;
    body: string;
    run: () => Promise<unknown>;
    ondeleted?: () => void;
    children?: Snippet;
  }
  let { open = $bindable(false), kind, name, body, run, ondeleted, children }: Props = $props();

  let busy = $state(false);
  let refusal = $state<string | null>(null);
  $effect(() => {
    if (open) refusal = null;
  });

  function confirm() {
    busy = true;
    refusal = null;
    run()
      .then(() => {
        open = false;
        ondeleted?.();
      })
      .catch((err: unknown) => {
        refusal = deleteRefusal(err, kind) ?? edgeErrorMessage(err);
      })
      .finally(() => {
        busy = false;
      });
  }
</script>

<ConfirmDialog
  bind:open
  title={kind === 'account' ? `Delete the account "${name}"?` : `Delete the template "${name}"?`}
  {body}
  typed={name}
  confirmLabel={kind === 'account' ? 'Delete account' : 'Delete template'}
  danger
  {busy}
  onConfirm={confirm}
>
  {@render children?.()}
  {#if refusal}
    <InlineError message={refusal} class="mt-2" />
  {/if}
</ConfirmDialog>
