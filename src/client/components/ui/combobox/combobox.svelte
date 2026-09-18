<script lang="ts">
  import { Combobox as ComboboxPrimitive } from 'bits-ui';

  let {
    open = $bindable(false),
    value = $bindable(),
    ...restProps
  }: ComboboxPrimitive.RootProps = $props();
</script>

<!-- bits-ui discriminates the root on `type` (single | multiple); the value binding
     follows that discriminator, so the cast keeps one wrapper for both. -->
<ComboboxPrimitive.Root
  bind:open
  bind:value={value as never}
  {...restProps as ComboboxPrimitive.RootProps}
/>
