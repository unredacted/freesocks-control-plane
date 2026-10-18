/**
 * The app's AttentionCallDeps (lib/attentionCalls.ts): the edge API, toasts, the
 * router and the query cache. Kept apart from the pure runner so its tests load
 * no Svelte store.
 *
 * Exports: attentionCallDeps(qc, opts).
 */
import type { QueryClient } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { router } from '@client/stores/router.svelte';
import {
  invalidateConfig,
  invalidateOverview,
  invalidateProviders,
  invalidateRelay,
  provisionRelay,
  publishRelayEdge,
  qualifyEdge,
  rebalanceRelay,
  rotateRelayEdge,
  testProviderCredentials,
  thawMaintenance,
} from '@client/lib/edgesApi';
import type { AttentionCallDeps } from './attentionCalls';
import { edgeErrorMessage } from './edgeErrors';
import { edgesPaths } from './routes';

/**
 * A started rotation opens on its origin page (rotations tab, the run's drawer),
 * the same on every screen: the one place its steps are shown.
 */
export function openRotationOf(slug: string | null, rotationId: string): void {
  if (slug) router.navigate(edgesPaths.relay(slug, { tab: 'rotations', rotation: rotationId }));
}

export function attentionCallDeps(
  qc: QueryClient,
  opts: Pick<AttentionCallDeps, 'plain' | 'openTest' | 'goLive'>,
): AttentionCallDeps {
  return {
    ...opts,
    api: {
      publish: (relayId, edgeId) => publishRelayEdge(relayId, { edgeId }),
      rotate: (relayId, edgeId) => rotateRelayEdge(relayId, { edgeId }),
      provision: (relayId) => provisionRelay(relayId),
      qualify: (edgeId) => qualifyEdge(edgeId),
      testCredentials: (accountId) => testProviderCredentials(accountId),
      thaw: () => thawMaintenance(),
      rebalance: (relayId) => rebalanceRelay(relayId),
    },
    navigate: (href) => router.navigate(href),
    openRotation: (item, rotationId) => openRotationOf(item.relaySlug, rotationId),
    success: (message) => toast.success(message),
    error: (message) => toast.error(message),
    failed: (e) => toast.error(edgeErrorMessage(e)),
    refresh: {
      item: (item) => {
        if (item.relaySlug) invalidateRelay(qc, item.relaySlug);
        else invalidateOverview(qc);
      },
      config: () => {
        invalidateConfig(qc);
        invalidateOverview(qc);
      },
      providers: () => {
        invalidateProviders(qc);
        invalidateOverview(qc);
      },
    },
  };
}
