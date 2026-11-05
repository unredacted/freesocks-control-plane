<script lang="ts">
  /**
   * The Servers tab bar: one quiet row of plain links at the top of every
   * Servers AND Edges page (the sidebar has a single "Servers" leaf for both):
   *
   *   Nodes | Edges | Countries | Backends | Mode pools | Edge providers | Advanced
   *
   * Nodes, Backends and Mode pools are the Servers section (lib/routes.ts); Edges,
   * Countries, Edge providers and Advanced are the Edges section
   * (../../edges/lib/routes.ts). A node page counts as Nodes, an Edges origin's
   * page as Edges, every technical Edges page (templates, probes, settings, an
   * origin's details) as Advanced. The Nodes link keeps the selected backend server.
   *
   * Props:
   *   current: ServersTab | SectionTab
   *   instance?: string    the selected backend server's slug
   */
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import { edgesPaths, type SectionTab } from '../../edges/lib/routes';
  import { serversPaths, type ServersTab } from '../lib/routes';

  interface Props {
    current: ServersTab | SectionTab;
    instance?: string;
  }
  let { current, instance }: Props = $props();

  const links = $derived<Array<{ id: ServersTab | SectionTab; label: string; href: string }>>([
    { id: 'nodes', label: 'Nodes', href: serversPaths.home({ instance }) },
    { id: 'edges', label: 'Edges', href: edgesPaths.home() },
    { id: 'countries', label: 'Countries', href: edgesPaths.countries() },
    { id: 'backends', label: 'Backends', href: serversPaths.backends() },
    { id: 'pools', label: 'Mode pools', href: serversPaths.pools() },
    { id: 'providers', label: 'Edge providers', href: edgesPaths.providers() },
    { id: 'advanced', label: 'Advanced', href: edgesPaths.advanced() },
  ]);
</script>

<nav aria-label="Servers" class="border-border mb-6 flex flex-wrap items-center gap-x-5 border-b">
  {#each links as l (l.id)}
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
