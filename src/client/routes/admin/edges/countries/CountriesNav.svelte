<script lang="ts">
  /**
   * The Countries tab's sub-views: the countries, and the country lists. A row
   * of small links under the tab bar, the same shape as the Settings tab's
   * (../../servers/components/SettingsNav.svelte).
   *
   * Props:
   *   current: 'countries' | 'lists'
   */
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import { edgesPaths } from '../lib/routes';

  interface Props {
    current: 'countries' | 'lists';
  }
  let { current }: Props = $props();

  const links = [
    { id: 'countries', label: 'Countries', href: edgesPaths.countries() },
    { id: 'lists', label: 'Lists', href: edgesPaths.lists() },
  ] as const;
</script>

<nav aria-label="Countries" class="mb-6 flex flex-wrap gap-2">
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
