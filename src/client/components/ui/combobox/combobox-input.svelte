<script lang="ts">
  import { Combobox as ComboboxPrimitive } from 'bits-ui';
  import { cn } from '@client/lib/utils.js';

  let {
    ref = $bindable(null),
    class: className,
    ...restProps
  }: ComboboxPrimitive.InputProps = $props();
</script>

<ComboboxPrimitive.Input
  bind:ref
  data-slot="combobox-input"
  class={cn(
    'dark:bg-input/30 border-input focus-visible:border-ring focus-visible:ring-ring/50 placeholder:text-muted-foreground h-8 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1 text-sm transition-colors outline-none focus-visible:ring-3 disabled:cursor-not-allowed disabled:opacity-50',
    className,
  )}
  {...restProps}
/>
