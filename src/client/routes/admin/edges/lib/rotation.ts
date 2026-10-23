/**
 * Rotation display helpers (pure).
 *
 * Exports: ROTATION_KIND_LABELS, ROTATION_TRIGGER_LABELS, stepStateTone(state),
 * standbyResultWords(code).
 */
import type { EdgeRotationAdmin } from '../../../../../shared/contracts/edges';
import type { Tone } from '../../../../lib/edgeCodes';

export const ROTATION_KIND_LABELS: Record<'provision' | 'publish' | 'replace', string> = {
  provision: 'Provision',
  publish: 'Publish',
  replace: 'Replace',
};

export const ROTATION_TRIGGER_LABELS: Record<'manual' | 'detector' | 'api' | 'reconcile', string> =
  {
    manual: 'An admin, by hand',
    detector: 'The block detector',
    api: 'An API token or automation',
    reconcile: 'The reconcile job',
  };

/** Provider step states are adapter-defined strings; tone by the common verbs. */
export function stepStateTone(state: string): Tone {
  const s = state.toLowerCase();
  if (['done', 'ok', 'complete', 'completed', 'succeeded', 'confirmed'].includes(s))
    return 'success';
  if (['failed', 'error', 'unresolved'].includes(s)) return 'danger';
  if (['running', 'claimed', 'in_progress', 'waiting', 'requested'].includes(s)) return 'info';
  if (['skipped', 'pending', 'planned'].includes(s)) return 'muted';
  return 'neutral';
}

/**
 * The toast when a run that should have put its edge in use ended with it
 * still a standby because of the pool (`standbyReason`).
 */
export function standbyResultWords(code: NonNullable<EdgeRotationAdmin['standbyReason']>): string {
  return code === 'pool_full'
    ? 'The edge stayed a standby: every pool slot is taken. Replace a published edge with it, or raise the published edges wanted.'
    : 'The edge stayed a standby: the free pool slot is held for an edge this origin still lacks (a listener, or a location of its provider set, with nothing published). Replace a published edge with it, or remove that location from the provider set.';
}
