<script lang="ts">
  import { Combobox as ComboboxPrimitive } from 'bits-ui';

  let { ref = $bindable(null), ...restProps }: ComboboxPrimitive.GroupProps = $props();
</script>

<ComboboxPrimitive.Group bind:ref data-slot="combobox-group" {...restProps} />
