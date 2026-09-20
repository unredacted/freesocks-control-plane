<script lang="ts">
  /**
   * Replace one PUBLISHED edge (rotate = normal drain, burn = short drain, for an
   * address believed blocked), behind a dry run that says whether the run would
   * start and what it would pick. Mount it while wanted (`{#if}`) with `open={true}`.
   *
   * Props: kind 'rotate' | 'burn'; origin; edge; onClose(); onStarted(rotationId)
   */
  import { createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { EdgeAdmin, OriginAdmin } from '@shared/contracts/edges';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import {
    burnRelayEdge,
    edgeKeys,
    invalidateRelay,
    preflightRelay,
    rotateRelayEdge,
  } from '@client/lib/edgesApi';
  import PreflightPanel from '../components/PreflightPanel.svelte';
  import ActionConfirm from './ActionConfirm.svelte';
  import { edgeAddress } from './relayLogic';

  interface Props {
    open: boolean;
    kind: 'rotate' | 'burn';
    relay: OriginAdmin;
    edge: EdgeAdmin;
    onClose: () => void;
    onStarted: (rotationId: string) => void;
  }
  let { open = $bindable(true), kind, relay, edge, onClose, onStarted }: Props = $props();

  const qc = useQueryClient();
  const preflight = createQuery(() => ({
    queryKey: [...edgeKeys.relay(relay.slug), 'preflight', 'replace', edge.id] as const,
    queryFn: () =>
      preflightRelay(relay.id, { kind: 'replace', edgeId: edge.id, trigger: 'manual' }),
    enabled: open,
    staleTime: 0,
    gcTime: 0,
  }));

  /** Limits an admin may override by hand; everything else has to be fixed first. */
  const FORCEABLE = new Set(['cooldown', 'daily_cap', 'hosts_operator_managed']);
  const blockers = $derived(preflight.data?.blockers ?? []);
  const forceable = $derived(blockers.length > 0 && blockers.every((b) => FORCEABLE.has(b.code)));
  const blocked = $derived(blockers.length > 0 && !forceable);
  let force = $state(false);

  const name = $derived(edgeAddress(edge) || edge.name);

  async function start(): Promise<void> {
    const body = { edgeId: edge.id, ...(force ? { force: true } : {}) };
    const res = await (kind === 'burn'
      ? burnRelayEdge(relay.id, body)
      : rotateRelayEdge(relay.id, body));
    toast.success(kind === 'burn' ? 'Burn started.' : 'Rotation started.');
    invalidateRelay(qc, relay.slug);
    onStarted(res.rotationId);
  }
</script>

<ActionConfirm
  bind:open
  title={kind === 'burn' ? `Burn ${name}?` : `Rotate ${name}?`}
  body={kind === 'burn'
    ? 'Use this when the address is believed blocked. A new edge takes its pool position, members are switched over, and the old edge drains for the short "burned" time before it is destroyed. Provisioning a replacement spends provider budget unless a compatible standby exists.'
    : 'A new edge takes the pool position of this one, members are switched over, and the old edge drains for the normal drain time before it is destroyed. Provisioning a replacement spends provider budget unless a compatible standby exists.'}
  confirmLabel={kind === 'burn' ? 'Burn and replace' : 'Rotate'}
  danger={kind === 'burn'}
  disabled={preflight.isPending || blocked || (forceable && !force)}
  {onClose}
  run={start}
>
  <PreflightPanel
    result={preflight.data}
    pending={preflight.isPending}
    error={preflight.error ?? undefined}
    onRetry={() => void preflight.refetch()}
    kind="replace"
  />
  {#if forceable}
    <div class="mt-3 flex items-start gap-2">
      <Checkbox id={`force-${edge.id}`} bind:checked={force} class="mt-0.5" />
      <div>
        <Label for={`force-${edge.id}`}>Override and start anyway</Label>
        <p class="text-xs text-muted-foreground">
          The limits above protect budget and members. Overriding is recorded in the audit log.
          {#if blockers.some((b) => b.code === 'hosts_operator_managed')}
            FCP will not write the panel Hosts of this relay: you must apply the new Hosts plan
            yourself right after, or members keep dialling the old edge.
          {/if}
        </p>
      </div>
    </div>
  {:else if blocked}
    <p class="mt-3 text-xs text-muted-foreground">
      Confirm stays off until the blockers above are fixed.
    </p>
  {/if}
</ActionConfirm>
