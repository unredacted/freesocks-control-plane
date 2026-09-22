/**
 * The guided setup's DRAFT: the origin and the listeners the operator intends,
 * kept in this browser until step 4 creates the origin. It is not progress
 * state (the server judges every step); it only lets steps 1 to 3 be judged
 * against the intended listeners before an origin row exists.
 *
 * Storage is best effort: a private window or blocked site data simply means
 * the draft does not survive a reload.
 *
 * Exports:
 *   StoredDraft, emptyDraft()
 *   parseDraft(raw)                  tolerant parse of a stored string (null when unusable)
 *   loadDraft() / saveDraft(d) / clearDraft()
 *   toSetupDraft(d)                  the body of `POST setup-status`
 *   draftIsEmpty(d)
 */
import type { SetupDraftBody } from '@client/lib/edgesApi';
import { LISTENER_COMBOS } from '@shared/contracts/edgeProtocolIds';
import { emptyOrigin, toWireOrigin, type OriginDraft, type OriginKind } from '../forms/origin';
import { emptyListenerForm, toDraftListener, type ListenerForm } from '../forms/listenerForm';

export const DRAFT_STORAGE_KEY = 'fcp_edges_setup_draft_v1';

export interface StoredDraft {
  origin: OriginDraft | null;
  listeners: ListenerForm[];
}

export const emptyDraft = (): StoredDraft => ({ origin: null, listeners: [] });

const KINDS: readonly OriginKind[] = ['panel-node', 'backend-server', 'manual'];
const str = (v: unknown): string => (typeof v === 'string' ? v : '');

function parseOrigin(v: unknown): OriginDraft | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const kind = KINDS.find((k) => k === o['kind']);
  if (!kind) return null;
  return {
    ...emptyOrigin(kind),
    backendServerId: str(o['backendServerId']),
    backendSlug: str(o['backendSlug']),
    nodeName: str(o['nodeName']),
    nodeUuid: typeof o['nodeUuid'] === 'string' ? o['nodeUuid'] : null,
    address: str(o['address']),
  };
}

function parseListener(v: unknown): ListenerForm | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const combo = LISTENER_COMBOS.find((c) => c.key === o['combo']);
  if (!combo) return null;
  const base = emptyListenerForm();
  const out: Record<string, unknown> = { ...base };
  // Keep only fields whose stored type matches the form's (a stale shape falls back to defaults).
  for (const [k, def] of Object.entries(base)) {
    const got = o[k];
    if (Array.isArray(def)) {
      if (Array.isArray(got)) out[k] = got.filter((x): x is string => typeof x === 'string');
    } else if (typeof got === typeof def) out[k] = got;
  }
  out['combo'] = combo.key;
  return out as unknown as ListenerForm;
}

export function parseDraft(raw: string | null): StoredDraft | null {
  if (!raw) return null;
  try {
    const v: unknown = JSON.parse(raw);
    if (!v || typeof v !== 'object') return null;
    const o = v as Record<string, unknown>;
    const listeners = Array.isArray(o['listeners'])
      ? o['listeners'].map(parseListener).filter((l): l is ListenerForm => l !== null)
      : [];
    return { origin: parseOrigin(o['origin']), listeners: listeners.slice(0, 8) };
  } catch {
    return null;
  }
}

export function loadDraft(): StoredDraft {
  try {
    return parseDraft(localStorage.getItem(DRAFT_STORAGE_KEY)) ?? emptyDraft();
  } catch {
    return emptyDraft();
  }
}

export function saveDraft(d: StoredDraft): void {
  try {
    if (draftIsEmpty(d)) localStorage.removeItem(DRAFT_STORAGE_KEY);
    else localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(d));
  } catch {
    // Best effort only.
  }
}

export function clearDraft(): void {
  try {
    localStorage.removeItem(DRAFT_STORAGE_KEY);
  } catch {
    // Best effort only.
  }
}

export const draftIsEmpty = (d: StoredDraft): boolean =>
  d.origin === null && d.listeners.length === 0;

export function toSetupDraft(d: StoredDraft): SetupDraftBody {
  return { origin: toWireOrigin(d.origin), listeners: d.listeners.map(toDraftListener) };
}
