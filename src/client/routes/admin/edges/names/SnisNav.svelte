<script lang="ts">
  /**
   * The SNIs tab's sub-views: the SNI lists, finding more SNIs, checks from
   * inside countries, and the numeric `edge.sni.*` knobs. A row of small links
   * under the tab bar, the same shape as the Settings and Countries tabs' own
   * sub-views.
   *
   * Props:
   *   current: 'lists' | 'find' | 'checks' | 'settings'
   */
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import { edgesPaths } from '../lib/routes';

  interface Props {
    current: 'lists' | 'find' | 'checks' | 'settings';
  }
  let { current }: Props = $props();

  const links = [
    { id: 'lists', label: 'Lists', href: edgesPaths.names() },
    { id: 'find', label: 'Find more', href: edgesPaths.findNames() },
    { id: 'checks', label: 'Checks from inside countries', href: edgesPaths.sniChecks() },
    { id: 'settings', label: 'More settings', href: edgesPaths.sniSettings() },
  ] as const;
</script>

<nav aria-label="SNIs" class="mb-6 flex flex-wrap gap-2">
  {#each links as l (l.id)}
    <Link
      href={l.href}
      aria-current={current === l.id ? 'page' : undefined}
      class={cn(
        'focus-visible:ring-ring/50 inline-flex min-h-9 items-center rounded-md px-3 text-sm outline-none focus-visible:ring-3',
        current === l.id
          ? 'bg-accent text-accent-foreground font-medium'
          : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
      )}
    >
      {l.label}
    </Link>
  {/each}
</nav>
