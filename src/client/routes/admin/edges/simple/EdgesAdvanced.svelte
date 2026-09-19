<script lang="ts">
  /**
   * Advanced (`/admin/edges/advanced`): a plain list of links to the technical
   * pages, which are unchanged and keep their addresses.
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import Link from '@client/components/Link.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';

  const LINKS: Array<{ label: string; hint: string; href: string }> = [
    {
      label: 'All relays',
      hint: 'The fleet dashboard: tiles, the attention list, readiness, every relay, reachability.',
      href: edgesPaths.overview(),
    },
    {
      label: 'Manual setup',
      hint: 'The step-by-step setup for any origin, including addresses described by hand.',
      href: edgesPaths.setup(),
    },
    {
      label: 'Templates',
      hint: 'The provisioning parameters each provider account creates addresses from.',
      href: edgesPaths.templates(),
    },
    {
      label: 'Probes',
      hint: 'Reachability from outside: the matrix, run history, probe now, custom targets.',
      href: edgesPaths.probes(),
    },
    {
      label: 'Server names',
      hint: 'Pools of names a REALITY node answers to: checked, rolled out, proven per node, judged per country.',
      href: edgesPaths.names(),
    },
    {
      label: 'Settings',
      hint: 'Every knob: pools, drains, the detector, rendering rules, probe budget.',
      href: edgesPaths.settings(),
    },
    {
      label: 'Maintenance',
      hint: 'Pause new edge work fleet-wide while running work finishes.',
      href: edgesPaths.settings({ section: 'maintenance' }),
    },
    {
      label: 'Delivery places',
      hint: 'Where members must receive a protected address, including places whose node is gone.',
      href: edgesPaths.settings({ section: 'delivery' }),
    },
  ];
</script>

<SectionHeader
  title="Advanced"
  description="The technical pages. Nothing here is needed day to day; the nodes page covers the usual work."
/>

<ul class="divide-border divide-y rounded-lg border" aria-label="Advanced pages">
  {#each LINKS as l (l.href)}
    <li>
      <Link
        href={l.href}
        class="hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 items-center gap-3 px-4 py-3 outline-none focus-visible:ring-3 focus-visible:ring-inset"
      >
        <span class="min-w-0 flex-1">
          <span class="block font-medium">{l.label}</span>
          <span class="text-muted-foreground block text-sm">{l.hint}</span>
        </span>
        <ChevronRight
          class="text-muted-foreground size-4 shrink-0 rtl:rotate-180"
          aria-hidden="true"
        />
      </Link>
    </li>
  {/each}
</ul>
