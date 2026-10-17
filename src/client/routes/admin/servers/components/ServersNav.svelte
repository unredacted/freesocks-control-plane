<script lang="ts">
  /**
   * The Servers leaf's tabs: `Backends | Nodes | Mode pools`, one quiet row of
   * plain links at the top of every Servers page (the sidebar has a single
   * "Servers" leaf). A node page counts as Nodes. The Nodes link keeps the
   * selected backend server.
   *
   * Props:
   *   current: ServersTab
   *   instance?: string    the selected backend server's slug
   */
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import { serversPaths, type ServersTab } from '../lib/routes';

  interface Props {
    current: ServersTab;
    instance?: string;
  }
  let { current, instance }: Props = $props();

  const links = $derived<Array<{ id: ServersTab; label: string; href: string }>>([
    { id: 'backends', label: 'Backends', href: serversPaths.backends() },
    { id: 'nodes', label: 'Nodes', href: serversPaths.home({ instance }) },
    { id: 'pools', label: 'Mode pools', href: serversPaths.pools() },
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
