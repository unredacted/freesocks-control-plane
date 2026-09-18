<script lang="ts" module>
  import { cn, type WithElementRef } from '@client/lib/utils.js';
  import type { HTMLAttributes } from 'svelte/elements';
  import { type VariantProps, tv } from 'tailwind-variants';

  /**
   * Plain (no bits-ui) status chip. `tone` variants map the shared `Tone` union
   * of lib/edgeCodes.ts (neutral/muted/info/success/warning/danger) plus the
   * shadcn `default`/`secondary`/`outline`/`destructive` names.
   */
  export const badgeVariants = tv({
    base: 'inline-flex items-center justify-center gap-1 rounded-md border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap shrink-0 [&>svg]:size-3 [&>svg]:pointer-events-none transition-colors',
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        secondary: 'border-transparent bg-secondary text-secondary-foreground',
        outline: 'border-border text-foreground',
        destructive: 'border-transparent bg-destructive/15 text-destructive',
        neutral: 'border-transparent bg-secondary text-secondary-foreground',
        muted: 'border-transparent bg-muted text-muted-foreground',
        info: 'border-transparent bg-sky-500/15 text-sky-700 dark:text-sky-300',
        success: 'border-transparent bg-emerald-500/15 text-emerald-700 dark:text-emerald-300',
        warning: 'border-transparent bg-amber-500/15 text-amber-700 dark:text-amber-300',
        danger: 'border-transparent bg-destructive/15 text-destructive',
      },
    },
    defaultVariants: { variant: 'default' },
  });

  export type BadgeVariant = VariantProps<typeof badgeVariants>['variant'];
</script>

<script lang="ts">
  let {
    ref = $bindable(null),
    class: className,
    variant = 'default',
    children,
    ...restProps
  }: WithElementRef<HTMLAttributes<HTMLSpanElement>> & { variant?: BadgeVariant } = $props();
</script>

<span
  bind:this={ref}
  data-slot="badge"
  class={cn(badgeVariants({ variant }), className)}
  {...restProps}
>
  {@render children?.()}
</span>
