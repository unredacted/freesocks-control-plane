/**
 * Which nodes a key placed in two groups (a mode with a backup mode,
 * docs/backends.md "A key in two groups") may be pinned to, in order of
 * preference:
 *  1. the nodes serving the key's own mode beside their own
 *     (nodeExtraModes.ts, state `serving`): the body carries both entries;
 *  2. while none does (its address is closed for a re-check), the nodes of the
 *     key's backup mode: the member keeps the backup's entry.
 * Names are the intents' current names; the pinner adds the former ones.
 */
import type { DatabaseReader } from '../_generated/server';
import type { Doc } from '../_generated/dataModel';
import { poolFromConfig } from './remnawavePlacement';

export interface ExtraModeTiers {
  /** Nodes serving the key's own mode as an extra mode. */
  serving: string[];
  /** Nodes whose own mode is one of the key's backup groups' modes. */
  backup: string[];
}

/** Null for a key not in two groups, or whose own group is no mode's. */
export async function extraModeTiersOf(
  db: DatabaseReader,
  sub: Pick<
    Doc<'subscriptions'>,
    'backend' | 'backendServerId' | 'backendPlacement' | 'backendExtraPlacements'
  >,
): Promise<ExtraModeTiers | null> {
  const backendServerId = sub.backendServerId;
  if (!backendServerId || !sub.backendPlacement || !sub.backendExtraPlacements?.length) return null;
  const rows = await db
    .query('modePlacements')
    .withIndex('by_backend', (q) => q.eq('backend', sub.backend))
    .collect();
  const modeOf = (placement: string) =>
    rows.find((r) => poolFromConfig(r.config).includes(placement))?.modeSlug;
  const slug = modeOf(sub.backendPlacement);
  if (!slug) return null;
  const backupModes = new Set(
    sub.backendExtraPlacements.map(modeOf).filter((m): m is string => !!m),
  );
  const intents = await db
    .query('panelNodeIntents')
    .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
    .collect();
  // A node whose delivery gate is closed is never a candidate (nodeIntents
  // `blockedNamesOf`; the pinner also skips the held names).
  const open = intents.filter((i) => i.delivery.disposition === 'live' && !i.maintenance);
  return {
    serving: open
      .filter((i) => (i.extraModes ?? []).some((m) => m.slug === slug && m.state === 'serving'))
      .map((i) => i.name),
    backup: open.filter((i) => backupModes.has(i.mode)).map((i) => i.name),
  };
}

/** The first tier with a node outside `blocked`, else null (nothing narrows). */
export function preferredTier(
  tiers: ExtraModeTiers,
  blocked: ReadonlySet<string>,
): string[] | null {
  for (const tier of [tiers.serving, tiers.backup]) {
    const open = tier.filter((n) => !blocked.has(n));
    if (open.length > 0) return open;
  }
  return null;
}

/**
 * The nodes "Switch server" may move a two-group key's pin to: those of the
 * tier the pinner picks from, other than the key's pin. Null for a key not in
 * two groups (its group's node count decides).
 */
export async function otherPinTargetsOf(
  db: DatabaseReader,
  sub: Parameters<typeof extraModeTiersOf>[1] & Pick<Doc<'subscriptions'>, 'pinnedNode'>,
): Promise<string[] | null> {
  const tiers = await extraModeTiersOf(db, sub);
  if (!tiers) return null;
  return (preferredTier(tiers, new Set()) ?? []).filter((n) => n !== sub.pinnedNode);
}
