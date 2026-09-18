<script lang="ts">
  /**
   * One coloured dot (green / amber / red / blue / grey). Decorative: the
   * sentence next to it carries the meaning, so it is hidden from readers.
   *
   * Props: dot: Dot; class?: string
   */
  import { cn } from '@client/lib/utils';
  import type { Dot } from './nodeStatus';

  interface Props {
    dot: Dot;
    class?: string;
  }
  let { dot, class: className }: Props = $props();

  const COLOR: Record<Dot, string> = {
    green: 'bg-emerald-500',
    amber: 'bg-amber-500',
    red: 'bg-destructive',
    blue: 'bg-sky-500',
    grey: 'bg-muted-foreground/50',
  };
</script>

<span
  class={cn('inline-block size-2.5 shrink-0 rounded-full', COLOR[dot], className)}
  aria-hidden="true"
></span>
