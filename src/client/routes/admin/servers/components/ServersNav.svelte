<script lang="ts">
  /**
   * The Servers tab bar: one quiet row of plain links at the top of every
   * Servers page (the sidebar has a single "Servers" leaf):
   *
   *   Overview | Nodes | Countries | SNIs | Probes | Providers | Settings
   *
   * Which tab a page lights: `tabOf` in ../lib/routes.ts. The Nodes link keeps
   * the selected backend server.
   *
   * Props:
   *   current: ServersTab
   *   backend?: string    the selected backend server's slug
   */
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import { edgesPaths } from '../../edges/lib/routes';
  import { serversPaths, type ServersTab } from '../lib/routes';

  interface Props {
    current: ServersTab;
    backend?: string;
  }
  let { current, backend }: Props = $props();

  const links = $derived<Array<{ id: ServersTab; label: string; href: string }>>([
    { id: 'overview', label: 'Overview', href: serversPaths.overview() },
    { id: 'nodes', label: 'Nodes', href: serversPaths.nodes({ backend }) },
    { id: 'countries', label: 'Countries', href: edgesPaths.countries() },
    { id: 'snis', label: 'SNIs', href: edgesPaths.names() },
    { id: 'probes', label: 'Probes', href: edgesPaths.probes() },
    { id: 'providers', label: 'Providers', href: edgesPaths.providers() },
    { id: 'settings', label: 'Settings', href: edgesPaths.settings() },
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
