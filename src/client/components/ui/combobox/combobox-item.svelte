<script lang="ts">
  import { Combobox as ComboboxPrimitive } from 'bits-ui';
  import { cn, type WithoutChild } from '@client/lib/utils.js';
  import CheckIcon from '@lucide/svelte/icons/check';

  let {
    ref = $bindable(null),
    class: className,
    value,
    label,
    children: childrenProp,
    ...restProps
  }: WithoutChild<ComboboxPrimitive.ItemProps> = $props();
</script>

<ComboboxPrimitive.Item
  bind:ref
  {value}
  {label}
  data-slot="combobox-item"
  class={cn(
    'data-highlighted:bg-accent data-highlighted:text-accent-foreground relative flex w-full cursor-default items-center gap-1.5 rounded-md py-1 pe-8 ps-1.5 text-sm outline-hidden select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
    className,
  )}
  {...restProps}
>
  {#snippet children({ selected, highlighted })}
    <span class="absolute end-2 flex size-3.5 items-center justify-center">
      {#if selected}<CheckIcon class="size-4" />{/if}
    </span>
    {#if childrenProp}
      {@render childrenProp({ selected, highlighted })}
    {:else}
      {label || value}
    {/if}
  {/snippet}
</ComboboxPrimitive.Item>
