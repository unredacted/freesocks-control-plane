/**
 * The row actions of the origin columns (the old All origins table): Provision
 * an edge (billable, so the page confirms it first with `provisionRow`) and
 * Probe now. Call from a component's script (it creates mutations).
 *
 *   const actions = originRowActions(qc);
 *   actions.askProvision(row)   opens the confirm (`actions.provisionOpen`)
 *   actions.confirmProvision()  the confirm's action
 *   actions.probe(row)
 *   actions.busySlug            the origin whose action is in flight
 */
import { createMutation, type QueryClient } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import {
  invalidateProbes,
  invalidateRelay,
  probeRelay,
  provisionRelay,
} from '@client/lib/edgesApi';
import { openRotationOf } from '../lib/attentionCallDeps';
import { edgeErrorMessage } from '../lib/edgeErrors';
import type { OriginRow } from './derive';

export function originRowActions(qc: QueryClient) {
  let provisionRow = $state<OriginRow | null>(null);
  let provisionOpen = $state(false);

  const provision = createMutation(() => ({
    mutationFn: (row: OriginRow) => provisionRelay(row.relay.id),
    onSuccess: (res, row) => {
      toast.success('Provisioning started. Follow the run on the technical details.');
      invalidateRelay(qc, row.relay.slug);
      openRotationOf(row.relay.slug, res.rotationId);
    },
  }));
  const probe = createMutation(() => ({
    mutationFn: (row: OriginRow) => probeRelay(row.relay.id),
    onSuccess: (res, row) => {
      const started = res.runIds.length;
      const skipped = res.skipped.length;
      if (started === 0) {
        toast.message(
          skipped > 0
            ? `No probe started for ${row.relay.slug}: ${skipped} ${skipped === 1 ? 'target was' : 'targets were'} skipped for budget, spacing or probes off.`
            : `No probe started for ${row.relay.slug}: it has nothing to probe yet.`,
        );
      } else {
        toast.success(
          `${started} ${started === 1 ? 'probe' : 'probes'} started for ${row.relay.slug}${skipped > 0 ? `, ${skipped} skipped` : ''}.`,
        );
      }
      invalidateProbes(qc);
    },
    onError: (e) => toast.error(edgeErrorMessage(e)),
  }));

  return {
    get provisionRow() {
      return provisionRow;
    },
    get provisionOpen() {
      return provisionOpen;
    },
    set provisionOpen(v: boolean) {
      provisionOpen = v;
    },
    askProvision(row: OriginRow) {
      provisionRow = row;
      provision.reset();
      provisionOpen = true;
    },
    confirmProvision() {
      return provisionRow ? provision.mutateAsync(provisionRow) : undefined;
    },
    probe(row: OriginRow) {
      probe.mutate(row);
    },
    get busySlug(): string | null {
      if (provision.isPending) return provision.variables?.relay.slug ?? null;
      if (probe.isPending) return probe.variables?.relay.slug ?? null;
      return null;
    },
  };
}
