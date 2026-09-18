<script lang="ts">
  import { Dialog as SheetPrimitive } from 'bits-ui';

  let {
    ref = $bindable(null),
    type = 'button',
    ...restProps
  }: SheetPrimitive.TriggerProps = $props();
</script>

<SheetPrimitive.Trigger bind:ref data-slot="sheet-trigger" {type} {...restProps} />
