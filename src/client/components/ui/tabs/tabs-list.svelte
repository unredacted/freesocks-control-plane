<script lang="ts">
  import { Tabs as TabsPrimitive } from 'bits-ui';
  import { cn } from '@client/lib/utils.js';

  // `line`: an underlined row of plain labels (the active one bold, with a
  // 2px brand underline) instead of the filled pill strip.
  let {
    ref = $bindable(null),
    class: className,
    variant = 'default',
    ...restProps
  }: TabsPrimitive.ListProps & { variant?: 'default' | 'line' } = $props();
</script>

<TabsPrimitive.List
  bind:ref
  data-slot="tabs-list"
  class={cn(
    variant === 'line'
      ? 'text-muted-foreground flex w-full flex-wrap items-center justify-start gap-x-7 border-b border-border'
      : 'bg-muted text-muted-foreground inline-flex h-9 w-fit items-center justify-center rounded-md p-1',
    className,
  )}
  {...restProps}
/>
