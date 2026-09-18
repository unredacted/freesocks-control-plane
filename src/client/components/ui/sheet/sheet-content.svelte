<script lang="ts" module>
  import { tv, type VariantProps } from 'tailwind-variants';

  export const sheetVariants = tv({
    base: 'bg-background text-foreground data-open:animate-in data-closed:animate-out fixed z-50 flex flex-col gap-4 shadow-lg ring-1 ring-foreground/10 duration-200 outline-none',
    variants: {
      side: {
        right:
          'data-closed:slide-out-to-right data-open:slide-in-from-right inset-y-0 end-0 h-full w-full border-s sm:max-w-lg',
        left: 'data-closed:slide-out-to-left data-open:slide-in-from-left inset-y-0 start-0 h-full w-full border-e sm:max-w-lg',
        top: 'data-closed:slide-out-to-top data-open:slide-in-from-top inset-x-0 top-0 h-auto border-b',
        bottom:
          'data-closed:slide-out-to-bottom data-open:slide-in-from-bottom inset-x-0 bottom-0 h-auto border-t',
      },
    },
    defaultVariants: { side: 'right' },
  });
  export type SheetSide = VariantProps<typeof sheetVariants>['side'];
</script>

<script lang="ts">
  import { Dialog as SheetPrimitive } from 'bits-ui';
  import type { ComponentProps, Snippet } from 'svelte';
  import SheetPortal from './sheet-portal.svelte';
  import SheetOverlay from './sheet-overlay.svelte';
  import { cn, type WithoutChildrenOrChild } from '@client/lib/utils.js';
  import { Button } from '@client/components/ui/button/index.js';
  import XIcon from '@lucide/svelte/icons/x';

  let {
    ref = $bindable(null),
    class: className,
    side = 'right',
    portalProps,
    children,
    showCloseButton = true,
    ...restProps
  }: WithoutChildrenOrChild<SheetPrimitive.ContentProps> & {
    side?: SheetSide;
    portalProps?: WithoutChildrenOrChild<ComponentProps<typeof SheetPortal>>;
    children: Snippet;
    showCloseButton?: boolean;
  } = $props();
</script>

<SheetPortal {...portalProps}>
  <SheetOverlay />
  <SheetPrimitive.Content
    bind:ref
    data-slot="sheet-content"
    data-side={side}
    class={cn(sheetVariants({ side }), className)}
    {...restProps}
  >
    {@render children?.()}
    {#if showCloseButton}
      <SheetPrimitive.Close data-slot="sheet-close">
        {#snippet child({ props })}
          <Button variant="ghost" size="icon-sm" class="absolute top-3 end-3" {...props}>
            <XIcon />
            <span class="sr-only">Close</span>
          </Button>
        {/snippet}
      </SheetPrimitive.Close>
    {/if}
  </SheetPrimitive.Content>
</SheetPortal>
