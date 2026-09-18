<script lang="ts">
  /**
   * Probes (`/admin/edges/probes`; URL state `?target` = the target whose run
   * history is open, `?range` = the outcome chart's range, see
   * `probes/rangeParam.ts`). Reachability of FCP's own addresses as measured from the
   * configured countries: edges of every relay, relay nodes that opted in, and
   * operator-entered custom targets. Only edge evidence reaches the block
   * detector. No member data is involved anywhere on this page. Probe SETTINGS
   * live under Settings, not here.
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
  description="Whether FCP's own addresses answer from the countries you watch. Edges, relay nodes that opted in, and custom targets."
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
      Scheduled probe rounds are switched off, so the matrix only changes when you use Probe now.
      <Link href={settingsHref} class="underline">Turn them on in Settings</Link>.
    </div>
  {/if}

  <ProbeTimeChart bind:range={() => range, (r) => (rangeParam.value = encodeProbeRange(r))} />

  <Card>
    <CardHeader>
      <CardTitle class="text-base">Reachability matrix</CardTitle>
      <CardDescription>
        The last verdict per target and country over IPv4, with the IPv6 and by-name paths noted
        where probed. A fronted hostname is probed by name with a TLS handshake. UDP listeners are
        not probed. Only edge rows feed the block detector.
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
        Any public host and port worth watching from the configured countries, such as a node's own
        address or a decoy site. Scheduled targets join every round, the others are probed on
        demand.
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
        Probe requests, finished runs and verdict changes, plus target and setting edits. Entries
        carry target references and codes only, never addresses. The full log is under Audit log.
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
