<script lang="ts">
  import { Progress as ProgressPrimitive } from 'bits-ui';
  import { cn, type WithoutChildrenOrChild } from '@client/lib/utils.js';

  let {
    ref = $bindable(null),
    class: className,
    max = 100,
    value = 0,
    ...restProps
  }: WithoutChildrenOrChild<ProgressPrimitive.RootProps> = $props();

  const pct = $derived(max && max > 0 ? Math.min(100, Math.max(0, ((value ?? 0) / max) * 100)) : 0);
</script>

<ProgressPrimitive.Root
  bind:ref
  data-slot="progress"
  class={cn('bg-primary/20 relative h-2 w-full overflow-hidden rounded-full', className)}
  {value}
  {max}
  {...restProps}
>
  <div
    data-slot="progress-indicator"
    class="bg-primary h-full w-full flex-1 transition-transform duration-300"
    style="transform: translateX(-{100 - pct}%)"
  ></div>
</ProgressPrimitive.Root>
