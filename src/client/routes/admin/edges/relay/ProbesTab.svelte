<script lang="ts">
  /**
   * The Probes tab: the reachability matrix narrowed to this origin's targets
   * (its origin when opted in, and each of its edges), plus "Probe now".
   *
   * Props: origin; edges
   */
  import type { EdgeAdmin, RelayAdmin } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import { invalidateProbes, probeRelay } from '@client/lib/edgesApi';
  import ProbeMatrix from '../probes/ProbeMatrix.svelte';
  import { edgesPaths } from '../lib/routes';
  import { relayAction } from './actions.svelte';
  import { relayProbeTargetKeys } from './relayLogic';

  interface Props {
    relay: RelayAdmin;
    edges: EdgeAdmin[];
  }
  let { relay, edges }: Props = $props();

  const act = relayAction(() => relay.slug);
  const keys = $derived(relayProbeTargetKeys(relay.id, edges));
  const filter = (targetKey: string): boolean => keys.has(targetKey);
  let openTarget = $state<string | null>(null);
</script>

<Card.Root>
  <Card.Header>
    <Card.Title>Reachability</Card.Title>
    <Card.Description>
      Whether outside networks in each country can reach the edges of this relay. Only published
      edges are probed on a schedule, and only their results feed the block detector.
      {#if !relay.probeNode}
        The origin itself is not probed; turn that on under Actions, Edit.
      {/if}
    </Card.Description>
    <Card.Action class="flex flex-wrap items-center gap-3">
      <Link href={edgesPaths.probes()} class="text-sm font-medium text-primary hover:underline">
        All probes
      </Link>
      <Button
        disabled={act.isPending}
        onclick={() =>
          act.mutate({
            run: () => probeRelay(relay.id),
            success: (res: { runIds: string[]; skipped: string[] }) =>
              res.runIds.length > 0
                ? `${res.runIds.length} probe run(s) requested${res.skipped.length > 0 ? `, ${res.skipped.length} target(s) skipped` : ''}. Results arrive within a minute or two.`
                : 'No probe was started. Check that probes are on, a source is enabled and the hourly budget is not used up.',
            also: invalidateProbes,
          })}
      >
        {act.isPending ? 'Requesting…' : 'Probe now'}
      </Button>
    </Card.Action>
  </Card.Header>
  <Card.Content>
    <ProbeMatrix
      {filter}
      compact
      {openTarget}
      onOpenTarget={(key) => (openTarget = key)}
      emptyText="Nothing of this relay is probed yet. Publish an edge, or turn on probing of the origin under Actions, Edit."
    />
  </Card.Content>
</Card.Root>
