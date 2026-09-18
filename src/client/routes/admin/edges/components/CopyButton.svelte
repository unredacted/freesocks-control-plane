<script lang="ts">
  /**
   * Icon button that copies `value` to the clipboard (toast on success / failure).
   *
   * Props:
   *   value: string
   *   label?: string          what is being copied, for the accessible name ("Copy address")
   *   class?: string
   */
  import { toast } from 'svelte-sonner';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import { Button } from '@client/components/ui/button';

  interface Props {
    value: string;
    label?: string;
    class?: string;
  }
  let { value, label = 'Copy', class: className }: Props = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      copied = true;
      clearTimeout(timer);
      timer = setTimeout(() => (copied = false), 1500);
      toast.success('Copied');
    } catch {
      toast.error('Could not copy. Select the text and copy it by hand.');
    }
  }
  $effect(() => () => clearTimeout(timer));
</script>

<Button
  type="button"
  variant="ghost"
  size="icon-xs"
  class={className}
  aria-label={label}
  title={label}
  onclick={copy}
>
  {#if copied}<Check aria-hidden="true" />{:else}<Copy aria-hidden="true" />{/if}
</Button>
