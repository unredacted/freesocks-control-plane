<script lang="ts">
  import { Tabs as TabsPrimitive } from 'bits-ui';
  import { cn } from '@client/lib/utils.js';

  let {
    ref = $bindable(null),
    class: className,
    variant = 'default',
    ...restProps
  }: TabsPrimitive.TriggerProps & { variant?: 'default' | 'line' } = $props();
</script>

<TabsPrimitive.Trigger
  bind:ref
  data-slot="tabs-trigger"
  class={cn(
    variant === 'line'
      ? 'data-[state=active]:text-foreground data-[state=active]:font-bold data-[state=active]:shadow-[inset_0_-2px_0_var(--primary)] hover:text-foreground focus-visible:ring-ring inline-flex min-h-11 items-center gap-1.5 text-base whitespace-nowrap transition-colors focus-visible:ring-2 focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50'
      : "data-[state=active]:bg-background data-[state=active]:text-foreground hover:text-foreground focus-visible:border-ring focus-visible:ring-ring/50 inline-flex h-7 flex-1 items-center justify-center gap-1.5 rounded-sm border border-transparent px-3 py-1 text-sm font-medium whitespace-nowrap transition-[color,box-shadow] focus-visible:ring-3 focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50 data-[state=active]:shadow-sm [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
    className,
  )}
  {...restProps}
/>
