<script lang="ts">
  /**
   * Run history of one probe target (newest first).
   *
   * Props:
   *   targetKey: string      `edge:<id>` | `origin:<id>` | `custom:<id>`
   */
  import * as Table from '@client/components/ui/table';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AdminListState from '../../AdminListState.svelte';
  import { probeRunsQuery } from '../../../../lib/edgesApi';
  import { relativeTime } from '../lib/time';
  import {
    PROBE_CHECK_LABELS,
    PROBE_RUN_STATUS_LABELS,
    PROBE_SOURCE_LABELS,
    PROBE_TRIGGER_LABELS,
    countryLabel,
    countryTally,
    familyLabel,
  } from './matrix';

  interface Props {
    targetKey: string;
  }
  let { targetKey }: Props = $props();
  const runs = probeRunsQuery(() => targetKey);
</script>

{#if runs.isPending}
  <Skeleton class="h-10 w-full" />
{:else if runs.isError}
  <AdminListState error={runs.error} onRetry={() => void runs.refetch()} />
{:else if (runs.data?.runs ?? []).length === 0}
  <p class="text-xs text-muted-foreground">
    No runs recorded for this target yet. Use Probe now to request one.
  </p>
{:else}
  <Table.Root class="text-xs">
    <Table.Header>
      <Table.Row>
        <Table.Head>When</Table.Head>
        <Table.Head>Source</Table.Head>
        <Table.Head>Path</Table.Head>
        <Table.Head>Check</Table.Head>
        <Table.Head>Status</Table.Head>
        <Table.Head>Asked by</Table.Head>
        <Table.Head>Ok / failing</Table.Head>
        <Table.Head>Per country</Table.Head>
      </Table.Row>
    </Table.Header>
    <Table.Body>
      {#each runs.data?.runs ?? [] as r (r.id)}
        <Table.Row>
          <Table.Cell class="whitespace-nowrap" title={r.requestedAt}
            >{relativeTime(r.requestedAt)}</Table.Cell
          >
          <Table.Cell>{PROBE_SOURCE_LABELS[r.source] ?? r.source}</Table.Cell>
          <Table.Cell class="whitespace-nowrap">
            {familyLabel(r.ipVersion)}{r.port ? `, port ${r.port}` : ''}
          </Table.Cell>
          <Table.Cell>{PROBE_CHECK_LABELS[r.probeProtocol] ?? r.probeProtocol}</Table.Cell>
          <Table.Cell>{PROBE_RUN_STATUS_LABELS[r.status] ?? r.status}</Table.Cell>
          <Table.Cell>{PROBE_TRIGGER_LABELS[r.trigger] ?? r.trigger}</Table.Cell>
          <Table.Cell class="tabular-nums">{r.okVantages} / {r.failVantages}</Table.Cell>
          <Table.Cell>
            {#each countryTally(r.results) as n (n.country)}
              <span class="me-2 whitespace-nowrap">
                {countryLabel(n.country)}
                <span class={n.fail > 0 && n.ok === 0 ? 'text-destructive' : ''}
                  >{n.ok}/{n.fail}</span
                >
              </span>
            {/each}
          </Table.Cell>
        </Table.Row>
      {/each}
    </Table.Body>
  </Table.Root>
{/if}
