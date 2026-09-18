<script lang="ts">
  /**
   * The section's in-page header: `Nodes | Providers | Advanced`, one quiet row
   * of plain links at the top of every Edges page (the sidebar has a single
   * "Edges" leaf). The current page's link is emphasised; every technical page
   * (templates, probes, settings, setup, a relay) counts as Advanced.
   *
   * Props:
   *   current: SectionTab
   */
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import { edgesPaths, type SectionTab } from '../lib/routes';

  interface Props {
    current: SectionTab;
  }
  let { current }: Props = $props();

  const LINKS: Array<{ id: SectionTab; label: string; href: string }> = [
    { id: 'nodes', label: 'Nodes', href: edgesPaths.home() },
    { id: 'providers', label: 'Providers', href: edgesPaths.providers() },
    { id: 'advanced', label: 'Advanced', href: edgesPaths.advanced() },
  ];
</script>

<nav aria-label="Edges" class="border-border mb-6 flex flex-wrap items-center gap-x-5 border-b">
  {#each LINKS as l (l.id)}
    <Link
      href={l.href}
      aria-current={current === l.id ? 'page' : undefined}
      class={cn(
        'focus-visible:ring-ring/50 -mb-px inline-flex min-h-11 items-center border-b-2 text-sm outline-none focus-visible:ring-3',
        current === l.id
          ? 'border-foreground text-foreground font-medium'
          : 'text-muted-foreground hover:text-foreground border-transparent',
      )}
    >
      {l.label}
    </Link>
  {/each}
</nav>
