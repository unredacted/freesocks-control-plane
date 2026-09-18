<script lang="ts">
  /**
   * Fleet usage above the accounts table: totals, what auto-provisioning would
   * add, and per relay desired versus published.
   *
   * Props:
   *   usage: ProvidersUsageResponse
   */
  import Link from '@client/components/Link.svelte';
  import * as Table from '@client/components/ui/table';
  import * as Collapsible from '@client/components/ui/collapsible';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import type { ProvidersUsageResponse } from '../../../../../shared/contracts/edges';
  import { edgesPaths } from '../lib/routes';
  import { relativeTime } from '../lib/time';

  interface Props {
    usage: ProvidersUsageResponse;
  }
  let { usage }: Props = $props();

  const t = $derived(usage.totals);
  const tiles = $derived([
    { label: 'live edges', value: t.liveEdges, hint: 'Every edge that exists at a provider' },
    { label: 'published', value: t.published, hint: 'Served to members' },
    { label: 'standby', value: t.standby, hint: 'Ready to take over' },
    { label: 'draining', value: t.draining, hint: 'Retired, kept until clients move' },
  ]);
  const short = $derived(usage.relays.filter((r) => r.published < r.desiredPublished));
</script>

<div class="space-y-3">
  <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
    {#each tiles as tile (tile.label)}
      <div class="rounded-lg border border-border p-3" title={tile.hint}>
        <div class="font-display text-2xl font-bold tabular-nums">{tile.value}</div>
        <div class="text-xs text-muted-foreground">{tile.label}</div>
      </div>
    {/each}
  </div>

  <p class="text-sm text-muted-foreground">
    {#if t.plannedIfAutoProvision === 0}
      Every relay has the edges it asks for, so auto-provisioning would add none.
    {:else}
      Auto-provisioning would add {t.plannedIfAutoProvision} edge{t.plannedIfAutoProvision === 1
        ? ''
        : 's'} across {short.length} relay{short.length === 1 ? '' : 's'} to reach the desired pools.
      <Link href={edgesPaths.settings()} class="underline">Review it in Settings</Link>.
    {/if}
    <span class="whitespace-nowrap">Counted {relativeTime(usage.generatedAt)}.</span>
  </p>

  {#if usage.relays.length > 0}
    <Collapsible.Root open={short.length > 0}>
      <Collapsible.Trigger
        class="group flex items-center gap-1 text-sm font-medium text-muted-foreground hover:text-foreground"
      >
        <ChevronRight class="size-4 transition-transform group-data-[state=open]:rotate-90" />
        Per relay: desired and published
      </Collapsible.Trigger>
      <Collapsible.Content class="pt-2">
        <Table.Root class="text-sm">
          <Table.Header>
            <Table.Row>
              <Table.Head>Relay</Table.Head>
              <Table.Head>Published / desired</Table.Head>
              <Table.Head>Standby</Table.Head>
              <Table.Head>Draining</Table.Head>
              <Table.Head>Auto-provision would add</Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {#each usage.relays as r (r.id)}
              <Table.Row>
                <Table.Cell>
                  <Link href={edgesPaths.relay(r.slug)} class="font-medium hover:underline"
                    >{r.slug}</Link
                  >
                </Table.Cell>
                <Table.Cell class="tabular-nums">
                  <span
                    class={r.published < r.desiredPublished
                      ? 'text-amber-700 dark:text-amber-300'
                      : ''}>{r.published} / {r.desiredPublished}</span
                  >
                </Table.Cell>
                <Table.Cell class="tabular-nums">{r.standby}</Table.Cell>
                <Table.Cell class="tabular-nums">{r.draining}</Table.Cell>
                <Table.Cell class="tabular-nums">
                  {r.plannedIfAutoProvision === 0 ? 'None' : r.plannedIfAutoProvision}
                </Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      </Collapsible.Content>
    </Collapsible.Root>
  {/if}
</div>
