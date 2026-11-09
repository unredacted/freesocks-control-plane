<script lang="ts">
  /**
   * A node page's section bar: one row of links over one scroll, sticky under
   * the page header. A link names its section in the URL (`?section=`) and
   * scrolls there (lib/nodeSectionState.svelte.ts).
   *
   * Props:
   *   sections: NodeSection[]
   *   current: NodeSection | null
   *   onPick: (id: NodeSection) => void
   */
  import { cn } from '@client/lib/utils';
  import { SECTION_LABELS, type NodeSection } from '../lib/nodeSections';
  import { sectionId } from '../lib/nodeSectionState.svelte';

  interface Props {
    sections: readonly NodeSection[];
    current: NodeSection | null;
    onPick: (id: NodeSection) => void;
  }
  let { sections, current, onPick }: Props = $props();
</script>

<nav
  aria-label="Sections"
  class="bg-background/95 supports-[backdrop-filter]:bg-background/80 sticky top-0 z-10 -mx-1 mb-6 flex gap-x-4 overflow-x-auto border-b px-1 backdrop-blur"
>
  {#each sections as id (id)}
    <a
      href={`#${sectionId(id)}`}
      aria-current={current === id ? 'location' : undefined}
      class={cn(
        'focus-visible:ring-ring/50 -mb-px inline-flex min-h-11 shrink-0 items-center border-b-2 text-sm whitespace-nowrap outline-none focus-visible:ring-3',
        current === id
          ? 'border-foreground text-foreground font-medium'
          : 'text-muted-foreground hover:text-foreground border-transparent',
      )}
      onclick={(e) => {
        e.preventDefault();
        onPick(id);
      }}
    >
      {SECTION_LABELS[id]}
    </a>
  {/each}
</nav>
