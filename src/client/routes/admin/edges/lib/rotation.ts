/**
 * Rotation display helpers (pure).
 *
 * Exports: ROTATION_KIND_LABELS, ROTATION_TRIGGER_LABELS, stepStateTone(state).
 */
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
