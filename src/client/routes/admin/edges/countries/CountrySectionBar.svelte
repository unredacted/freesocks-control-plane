<script lang="ts">
  /**
   * The country page's section bar: Summary · Addresses for this country ·
   * SNIs · Lists · Probes · Checks from here · Exit. Each is a link to
   * `?section=` on the same page (a search-only change: the page is not
   * remounted). Scrolls sideways on a phone.
   *
   * Props:
   *   code: string               the country
   *   current: CountrySection
   */
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import { edgesPaths } from '../lib/routes';
  import { COUNTRY_SECTIONS, type CountrySection } from './sections';

  interface Props {
    code: string;
    current: CountrySection;
  }
  let { code, current }: Props = $props();
</script>

<nav aria-label="Sections" class="mb-6 flex gap-2 overflow-x-auto whitespace-nowrap">
  {#each COUNTRY_SECTIONS as s (s.id)}
    <Link
      href={edgesPaths.country(code, { section: s.id === 'summary' ? null : s.id })}
      aria-current={current === s.id ? 'page' : undefined}
      class={cn(
        'focus-visible:ring-ring/50 inline-flex min-h-9 shrink-0 items-center rounded-md px-3 text-sm outline-none focus-visible:ring-3',
        current === s.id
          ? 'bg-accent text-accent-foreground font-medium'
          : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
      )}
    >
      {s.label}
    </Link>
  {/each}
</nav>
