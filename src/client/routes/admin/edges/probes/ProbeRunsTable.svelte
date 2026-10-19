<script lang="ts">
  /**
   * Run history of one probe target (newest first), grouped by ROUND: the runs
   * one request made (every source, port and family). A round's heading says
   * when it was asked, whether it is still out and which control countries it
   * asked; for an edge, the round that decided each checked country says what
   * it found there, in words. Control vantages (uncensored countries asked in
   * the same measurement) are labelled "control" and counted apart. A failed
   * run says why in words.
   *
   * Props:
   *   targetKey: string      `edge:<id>` | `origin:<id>` | `custom:<id>`
   */
  import * as Table from '@client/components/ui/table';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { countryName } from '@client/lib/countries';
  import AdminListState from '../../AdminListState.svelte';
  import { edgeCountriesQuery, probeRunsQuery } from '../../../../lib/edgesApi';
  import { relativeTime } from '../lib/time';
  import { ROUND_RESULT_WORDS, countryReasonSentence, probeFailureWords } from '../lib/statusWords';
  import {
    PROBE_CHECK_LABELS,
    PROBE_RUN_STATUS_LABELS,
    PROBE_SOURCE_LABELS,
    PROBE_TRIGGER_LABELS,
    countryLabel,
    countryTally,
    familyLabel,
    groupRounds,
  } from './matrix';

  interface Props {
    targetKey: string;
  }
  let { targetKey }: Props = $props();
  const runs = probeRunsQuery(() => targetKey);
  const edgeId = $derived(targetKey.startsWith('edge:') ? targetKey.slice(5) : null);
  const countries = edgeCountriesQuery({ enabled: () => edgeId !== null });
  const rounds = $derived(groupRounds(runs.data?.runs ?? []));

  /** Per checked country, what the round said, when it is the one on record there. */
  function decided(roundId: string | null): Array<{ country: string; text: string }> {
    if (!roundId || !edgeId) return [];
    const edge = countries.data?.edges.find((e) => e.edgeId === edgeId);
    return (edge?.countries ?? [])
      .filter((c) => c.lastRound?.roundId === roundId)
      .map((c) => {
        const r = c.lastRound!;
        const why = countryReasonSentence(r.reason);
        return {
          country: c.country,
          text: `${ROUND_RESULT_WORDS[r.result].label}. ${why ?? ROUND_RESULT_WORDS[r.result].sentence} ${r.ok} ok, ${r.fail} failing on ${r.networks} ${r.networks === 1 ? 'network' : 'networks'}; ${r.controlsOk} ${r.controlsOk === 1 ? 'control' : 'controls'} reached it.`,
        };
      });
  }
  const controlsOf = (rs: { controls: string[] }[]) => [...new Set(rs.flatMap((r) => r.controls))];
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
      {#each rounds as round, i (round.roundId ?? `run-${round.runs[0]!.id}`)}
        {#if round.roundId}
          {@const controls = controlsOf(round.runs)}
          {@const verdicts = decided(round.roundId)}
          <Table.Row class="bg-muted/40 hover:bg-muted/40">
            <Table.Cell colspan={8}>
              <!-- Sticky and narrow: the matrix scrolls sideways, the heading stays readable. -->
              <div class="sticky left-0 max-w-xl whitespace-normal">
                <span class="font-medium">Round</span>
                <span title={round.requestedAt}>{relativeTime(round.requestedAt)}</span>,
                {round.runs.length}
                {round.runs.length === 1 ? 'run' : 'runs'}, {round.open
                  ? 'still checking'
                  : 'done'}.
                {#if controls.length > 0}
                  Controls asked: {controls.join(', ')}.
                {/if}
                {#if verdicts.length > 0}
                  <ul class="mt-1 space-y-0.5" aria-label={`Round ${i + 1}, what it found`}>
                    {#each verdicts as v (v.country)}
                      <li>
                        <span class="font-medium">{countryName(v.country, 'en')}:</span>
                        {v.text}
                      </li>
                    {/each}
                  </ul>
                {/if}
              </div>
            </Table.Cell>
          </Table.Row>
        {/if}
        {#each round.runs as r (r.id)}
          <Table.Row>
            <Table.Cell class="whitespace-nowrap" title={r.requestedAt}
              >{relativeTime(r.requestedAt)}</Table.Cell
            >
            <Table.Cell>{PROBE_SOURCE_LABELS[r.source] ?? r.source}</Table.Cell>
            <Table.Cell class="whitespace-nowrap">
              {familyLabel(r.ipVersion)}{r.port ? `, port ${r.port}` : ''}
            </Table.Cell>
            <Table.Cell>{PROBE_CHECK_LABELS[r.probeProtocol] ?? r.probeProtocol}</Table.Cell>
            <Table.Cell>
              {PROBE_RUN_STATUS_LABELS[r.status] ?? r.status}
              {#if r.error}
                {@const f = probeFailureWords(r.error)}
                <span class="text-muted-foreground block" title={f.sentence}>{f.label}</span>
              {/if}
            </Table.Cell>
            <Table.Cell>{PROBE_TRIGGER_LABELS[r.trigger] ?? r.trigger}</Table.Cell>
            <Table.Cell class="tabular-nums">{r.okVantages} / {r.failVantages}</Table.Cell>
            <Table.Cell>
              {#each countryTally(r.results) as n (`${n.control ? 'c' : 'v'}:${n.country}`)}
                <span class="me-2 whitespace-nowrap">
                  {countryLabel(n.country)}
                  {#if n.control}<span class="text-muted-foreground">control</span>{/if}
                  <span class={n.fail > 0 && n.ok === 0 ? 'text-destructive' : ''}
                    >{n.ok}/{n.fail}</span
                  >
                </span>
              {/each}
            </Table.Cell>
          </Table.Row>
        {/each}
      {/each}
    </Table.Body>
  </Table.Root>
{/if}
