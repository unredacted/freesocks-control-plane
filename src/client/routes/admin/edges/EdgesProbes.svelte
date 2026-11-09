<script lang="ts">
  /**
   * Probes (`/admin/servers/probes`; URL state `?target` = the target whose run
   * history is open, `?range` = the outcome chart's range, see
   * `probes/rangeParam.ts`). Reachability of FCP's own addresses as measured from the
   * configured countries: edges of every origin, origin nodes that opted in, and
   * operator-entered custom targets. Only edge evidence reaches the block
   * detector. No member data is involved anywhere on this page. Probe SETTINGS
   * live under Settings, not here.
   *
   * Sources: whether each enabled source brings back evidence (a failing one
   * says why). A target's run history groups its runs by round, with the
   * control countries labelled and, for an edge, what each round found there.
   */
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { router } from '../../../stores/router.svelte';
  import { searchParam } from '../../../lib/urlState.svelte';
  import { edgeConfigQuery, probeAuditQuery } from '../../../lib/edgesApi';
  import AdminListState from '../AdminListState.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import ProbeTimeChart from './components/ProbeTimeChart.svelte';
  import Timeline from './components/Timeline.svelte';
  import { edgesPaths } from './lib/routes';
  import ProbeMatrix from './probes/ProbeMatrix.svelte';
  import CustomTargets from './probes/CustomTargets.svelte';
  import SourcesCard from './probes/SourcesCard.svelte';
  import { decodeProbeRange, encodeProbeRange } from './probes/rangeParam';

  const target = searchParam('target');
  const rangeParam = searchParam('range');
  const range = $derived(decodeProbeRange(rangeParam.value));
  const cfg = edgeConfigQuery();
  const audit = probeAuditQuery();
  const settingsHref = edgesPaths.settings({ section: 'probes' });
  const probesOff = $derived(cfg.data ? cfg.data.config.probe.enabled === false : false);
</script>

<SectionHeader
  title="Probes"
  description="Whether FCP's edges, opted-in relay nodes and custom targets answer from the countries you watch."
>
  {#snippet actions()}
    <Button variant="outline" size="sm" onclick={() => router.navigate(settingsHref)}>
      Probe settings
    </Button>
  {/snippet}
</SectionHeader>

<div class="space-y-6">
  {#if probesOff}
    <div class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
      Scheduled probe rounds are off, so the matrix only changes when you use Probe now.
      <Link href={settingsHref} class="underline">Turn them on in Settings</Link>.
    </div>
  {/if}

  <Card>
    <CardHeader>
      <CardTitle class="text-base">Sources</CardTitle>
      <CardDescription>
        Whether each source brings back evidence. A failing source never reads as a block. Countries
        only it covers read as not known until it works again.
      </CardDescription>
    </CardHeader>
    <CardContent>
      <SourcesCard />
    </CardContent>
  </Card>

  <ProbeTimeChart bind:range={() => range, (r) => (rangeParam.value = encodeProbeRange(r))} />

  <Card>
    <CardHeader>
      <CardTitle class="text-base">Reachability matrix</CardTitle>
      <CardDescription>
        The last IPv4 verdict per target and country, with IPv6 and hostname results where probed. A
        fronted hostname gets a TLS handshake with its SNI. UDP listeners are not probed. Only edge
        rows feed the block detector. Open a row for its runs by round.
      </CardDescription>
    </CardHeader>
    <CardContent>
      <ProbeMatrix openTarget={target.value || null} onOpenTarget={(k) => (target.value = k)} />
    </CardContent>
  </Card>

  <Card>
    <CardHeader>
      <CardTitle class="text-base">Custom targets</CardTitle>
      <CardDescription>
        Any public host and port to watch from the configured countries, like a node's own address
        or a decoy site. Scheduled targets join every round. Others are probed on demand.
      </CardDescription>
    </CardHeader>
    <CardContent>
      <CustomTargets />
    </CardContent>
  </Card>

  <Card>
    <CardHeader>
      <CardTitle class="text-base">Probe activity</CardTitle>
      <CardDescription>
        Probe requests, finished runs, verdict changes and target and setting edits. Entries hold
        target references and codes, never addresses. The full log is under Audit log.
      </CardDescription>
    </CardHeader>
    <CardContent>
      {#if audit.isPending}
        <Skeleton class="h-16 w-full" />
      {:else if audit.isError}
        <AdminListState error={audit.error} onRetry={() => void audit.refetch()} />
      {:else}
        <Timeline
          entries={audit.data?.entries ?? []}
          max={15}
          label="Probe activity"
          emptyText="No probe activity yet. Use Probe now on a target above to request the first run."
          hrefFor={(e) =>
            e.targetId && /^(edge|relay|custom):/.test(e.targetId)
              ? edgesPaths.probes({ target: e.targetId })
              : null}
        />
      {/if}
    </CardContent>
  </Card>
</div>
