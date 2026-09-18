<script lang="ts">
  import { Combobox as ComboboxPrimitive } from 'bits-ui';
  import { cn } from '@client/lib/utils.js';
  import ChevronsUpDownIcon from '@lucide/svelte/icons/chevrons-up-down';

  let {
    ref = $bindable(null),
    class: className,
    children,
    ...restProps
  }: ComboboxPrimitive.TriggerProps = $props();
</script>

<ComboboxPrimitive.Trigger
  bind:ref
  data-slot="combobox-trigger"
  class={cn(
    'text-muted-foreground hover:text-foreground inline-flex size-8 shrink-0 items-center justify-center rounded-md outline-none disabled:cursor-not-allowed disabled:opacity-50',
    className,
  )}
  {...restProps}
>
  {#if children}{@render children()}{:else}<ChevronsUpDownIcon class="size-4" />{/if}
</ComboboxPrimitive.Trigger>
