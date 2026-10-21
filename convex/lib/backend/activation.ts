/**
 * The node activation ladder (pure): revisions, evidence, the review hash,
 * how a change is classified, and what a stage change does to evidence. The
 * rows live in `panelNodeIntents` and `panelActivationRuns`
 * (docs/servers.md "Node lifecycle").
 *
 * Three revision sets exist: `desired` (what the next review approves),
 * `committed` (what members are served; moves only when a delivery commit
 * promotes a candidate) and, per activation run, an immutable candidate
 * snapshot with its own approval. `reviewHash` covers the delivery SHAPE,
 * never individual edge addresses.
 */
import { sha256Hex } from '../crypto';
import { canonicalJson } from './digest';

export const STAGES = [
  'registered',
  'bootstrap_available',
  'machine_applied',
  'machine_ready',
  'candidates_verified',
  'awaiting_approval',
  'activating',
  'live',
] as const;
export type Stage = (typeof STAGES)[number];

export function stageIndex(s: Stage): number {
  return STAGES.indexOf(s);
}

export function earlierStage(a: Stage, b: Stage): Stage {
  return stageIndex(a) <= stageIndex(b) ? a : b;
}

export interface Revisions {
  machineRevision: number;
  configRevision: string;
  authRevision?: string;
  deliveryRevision: string;
}

export interface Evidence {
  kind: string;
  machineRevision: number;
  configRevision?: string;
  authRevision?: string;
  deliveryRevision?: string;
  at: number;
}

/** Which revision each evidence kind is bound to. */
export const EVIDENCE_BINDING: Readonly<Record<string, (keyof Revisions)[]>> = {
  machine_applied: ['machineRevision'],
  machine_ready: ['machineRevision', 'configRevision'],
  ingress_verified: ['machineRevision'],
  dns_resolves: ['machineRevision'],
  direct_confirmed: ['machineRevision', 'configRevision', 'authRevision'],
  standbys_verified: ['machineRevision', 'configRevision', 'deliveryRevision'],
  templates_checked: ['configRevision', 'deliveryRevision'],
  tls_contract: ['machineRevision', 'deliveryRevision'],
};

/** Whether an evidence row still holds for the current revisions. */
export function evidenceHolds(e: Evidence, now: Revisions): boolean {
  const bound = EVIDENCE_BINDING[e.kind] ?? [
    'machineRevision',
    'configRevision',
    'deliveryRevision',
  ];
  return bound.every((k) => {
    const v = e[k];
    // Evidence that does not record a revision it is bound to never holds.
    if (v === undefined) return k === 'authRevision' && now.authRevision === undefined;
    return v === now[k];
  });
}

/** Drop the evidence rows a revision change invalidated. */
export function retainEvidence(rows: readonly Evidence[], now: Revisions): Evidence[] {
  return rows.filter((e) => evidenceHolds(e, now));
}

/** The stage the ladder falls back to when a revision changed: the earliest stage whose evidence is gone. */
export function stageAfterChange(current: Stage, retained: readonly Evidence[]): Stage {
  const has = (k: string) => retained.some((e) => e.kind === k);
  if (!has('machine_applied')) return earlierStage(current, 'bootstrap_available');
  if (!has('machine_ready')) return earlierStage(current, 'machine_applied');
  if (!has('direct_confirmed') && !has('standbys_verified'))
    return earlierStage(current, 'machine_ready');
  return earlierStage(current, 'candidates_verified');
}

export interface ReviewShape {
  /** The connection mode the node serves and its shape (transport + fronting). */
  mode: string;
  modeShape: { transport: string; fronting: string };
  ingress: unknown;
  configRevision: string;
  authRevision: string | null;
  /**
   * A fronted node's required listeners (sorted by key), each with the
   * provider account, location and template it is fronted by: every listener,
   * never one representative edge. A listener may hold several entries (one
   * per pick of the node's provider set). Empty for a direct node.
   */
  listeners: ReviewListener[];
  subscriptionTemplates: Record<string, string>;
  /** A direct node's addresses, one per family name; empty for a fronted node. */
  addressTuples: { address: string; port: number; sni: string | null }[];
}

export interface ReviewListener {
  listenerKey: string;
  accountId: string | null;
  /** The location the account fronts it from (null with no account: an adopted front). */
  locationId?: string | null;
  templateHash: string | null;
  /**
   * The certificate it is built with (lib/edges/choices.ts `certificateDigest`),
   * for a provider whose certificate is a node's option. Absent otherwise, and
   * on an approval taken before options (which then takes any certificate).
   */
  certificate?: string;
}

/** What one edge publication is, in the review's terms (the admission compares it to an approval). */
export interface PublicationShape {
  listenerKey: string;
  accountId: string | null;
  locationId: string | null;
  templateHash: string | null;
  certificate?: string;
}

/**
 * Whether a publication fits an approved review: its listener is one the
 * review names, fronted by the same account, from the same location, with the
 * same template. A replacement ADDRESS within that shape reuses the approval;
 * another account, location, template or listener needs a new review. An
 * approval whose shape predates the per-listener review (no `listeners`)
 * fits nothing, and so does an entry that names an account but no location:
 * it fails closed.
 */
export function publicationFits(
  approved: Pick<ReviewShape, 'listeners'> | null,
  pub: PublicationShape,
): boolean {
  return (approved?.listeners ?? []).some((l) => {
    if (l.listenerKey !== pub.listenerKey) return false;
    if ((l.accountId ?? null) !== (pub.accountId ?? null)) return false;
    if (l.accountId && l.locationId === undefined) return false;
    return (
      (l.locationId ?? null) === (pub.locationId ?? null) &&
      (l.templateHash ?? null) === (pub.templateHash ?? null) &&
      // Another authority or scope is a new review; an entry approved before
      // options names none and takes what the node is built with.
      (l.certificate === undefined || l.certificate === pub.certificate)
    );
  });
}

/** Review entries in their canonical order (the hash is taken over this order). */
/** One entry per distinct (listenerKey, accountId, locationId, templateHash), first kept. */
export function dedupeReviewListeners(rows: readonly ReviewListener[]): ReviewListener[] {
  const seen = new Set<string>();
  const out: ReviewListener[] = [];
  for (const r of rows) {
    const k = `${r.listenerKey}\u0000${r.locationId ?? ''}\u0000${r.accountId ?? ''}\u0000${r.templateHash ?? ''}\u0000${r.certificate ?? ''}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(r);
  }
  return out;
}

export function sortReviewListeners(rows: ReviewListener[]): ReviewListener[] {
  const k = (r: ReviewListener) =>
    `${r.listenerKey}\u0000${r.locationId ?? ''}\u0000${r.accountId ?? ''}\u0000${r.templateHash ?? ''}\u0000${r.certificate ?? ''}`;
  return [...rows].sort((a, b) => (k(a) < k(b) ? -1 : k(a) > k(b) ? 1 : 0));
}

/** The hash the review card is approved under. Stable across edge address changes. */
export async function reviewHashOf(shape: ReviewShape): Promise<string> {
  return sha256Hex(canonicalJson(shape));
}

export type ChangeKind = 'none' | 'preparable' | 'in_place';

export interface ChangeDescriptor {
  /** Machine settings that produce a NEW path beside the old (a second Caddy route, a new hostname). */
  addsPath?: boolean;
  /** Machine settings that rewrite the running path (a path or port rewrite, re-address, DNS content). */
  rewritesPath?: boolean;
  /** The shared profile changed under the node (bridged by the ledger). */
  profileChanged?: boolean;
  /** REALITY key or short id changed. */
  authChanged?: boolean;
  /** Provider account or template changed for a fronted node. */
  providerChanged?: boolean;
  /** The replacement would have to mutate a committed resource (Host tuple, listener pointer). */
  mutatesCommitted?: boolean;
}

/**
 * How a change is applied. Resource isolation is the condition: a change is
 * preparable only when its replacement can be built on separate candidate
 * resources with the committed rendering context untouched until the commit.
 */
export function classifyChange(d: ChangeDescriptor): ChangeKind {
  if (d.rewritesPath || d.profileChanged || d.authChanged || d.mutatesCommitted) return 'in_place';
  if (d.addsPath || d.providerChanged) return 'preparable';
  return 'none';
}

/** The disposition a node is served under; `staged` until its first commit. */
export type Disposition = 'staged' | 'activating' | 'live' | 'unavailable' | 'retiring';

/** Whether the gate is open for members at this disposition. */
export function gateOpen(d: Disposition): boolean {
  return d === 'live';
}

/**
 * Whether a publication may be admitted for a node. `committed` = the
 * publication's revisions equal the committed set; `candidateRun` = they equal
 * one specific activating run's approved candidate.
 */
export function publicationAdmitted(a: {
  disposition: Disposition;
  underMaintenance: boolean;
  matchesCommitted: boolean;
  matchesApprovedCandidate: boolean;
}): 'committed' | 'candidate' | null {
  if (a.underMaintenance) return null;
  if (a.disposition === 'retiring' || a.disposition === 'unavailable') return null;
  if (a.matchesApprovedCandidate && (a.disposition === 'activating' || a.disposition === 'live'))
    return 'candidate';
  if (a.matchesCommitted && a.disposition === 'live') return 'committed';
  return null;
}
