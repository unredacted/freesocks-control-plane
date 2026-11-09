<script lang="ts">
  /**
   * The Settings tab's sub-views: every knob, the backend servers, and the
   * mode pools. A row of small links under the tab bar, the same shape as the
   * Countries tab's own sub-views.
   *
   * Props:
   *   current: 'settings' | 'backends' | 'pools'
   */
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import { edgesPaths } from '../../edges/lib/routes';
  import { serversPaths } from '../lib/routes';

  interface Props {
    current: 'settings' | 'backends' | 'pools';
  }
  let { current }: Props = $props();

  const links = [
    { id: 'settings', label: 'All settings', href: edgesPaths.settings() },
    { id: 'backends', label: 'Backends', href: serversPaths.backends() },
    { id: 'pools', label: 'Mode pools', href: serversPaths.pools() },
  ] as const;
</script>

<nav aria-label="Settings" class="mb-6 flex flex-wrap gap-2">
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
