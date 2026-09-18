<script lang="ts">
  import { Combobox as ComboboxPrimitive } from 'bits-ui';
  import { cn } from '@client/lib/utils.js';

  let {
    ref = $bindable(null),
    class: className,
    ...restProps
  }: ComboboxPrimitive.GroupHeadingProps = $props();
</script>

<ComboboxPrimitive.GroupHeading
  bind:ref
  data-slot="combobox-group-heading"
  class={cn('text-muted-foreground px-1.5 py-1 text-xs font-medium', className)}
  {...restProps}
/>
