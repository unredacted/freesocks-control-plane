<script lang="ts">
  import { Tooltip as TooltipPrimitive } from 'bits-ui';

  /**
   * Root wraps its own Provider so a single `<Tooltip.Root>` works anywhere
   * (bits-ui requires a Provider ancestor). Nest several under one
   * `<Tooltip.Provider>` when they should share the open delay.
   */
  let {
    open = $bindable(false),
    delayDuration = 200,
    ...restProps
  }: TooltipPrimitive.RootProps & { delayDuration?: number } = $props();
</script>

<TooltipPrimitive.Provider {delayDuration}>
  <TooltipPrimitive.Root bind:open {...restProps} />
</TooltipPrimitive.Provider>
