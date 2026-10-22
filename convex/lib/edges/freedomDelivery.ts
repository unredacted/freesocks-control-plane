/**
 * Freedom modes only through edges (docs/edges.md "Freedom modes only through
 * edges"). While `edge.freedom.edgesOnly` is on, a key on a freedom-family
 * connection mode is never handed a node's own address: the node it resolves
 * to serves it only through a delivery binding (an origin whose render hands
 * out edges, never the node), and a node no binding covers is withheld from it
 * the way the delivery gate withholds an enrolled node that is not live (the
 * pinner never picks it while another exists, the route answers
 * `node_unprotected`, a mirror holds the unavailable stub, the raw backend URL
 * is not shown).
 *
 * The switch is ONE appSettings row, written only by `freedomDelivery.setEdgesOnly`
 * (a preview, a confirm when members are affected, an audit): it is in neither
 * SETTINGS_DEFAULTS nor EDGE_KEYS, so no generic settings write reaches it.
 * A deployment the seed has not reached reads it off; `seedCutover` stores it
 * on for a deployment with no members and off for one that has members, once.
 *
 * Which keys are held: what a key is handed is decided by its placement (the
 * group the backend serves it, so the nodes in its body) and the node it
 * resolves to, so those are the signals, and EITHER is enough (the opposite of
 * `memberFamilyOf`, which fails closed toward no country handling): a mode
 * whose pool holds its placement is freedom-family, or the enrolled node it
 * resolves to serves a freedom mode. The member's stored (or default) mode is
 * not a signal: a member who never chose, on a privacy group, would be cut off
 * by a freedom default, and a key with no placement has no node to hand out.
 */
import type { DatabaseReader } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';
import type { FreedomWithheldReason } from '../../../src/shared/contracts/edgeCodes';
import type { EdgeLayer } from '../../../src/shared/contracts/edges';
import type { ModeFronting } from '../../../src/shared/contracts/servers';
import { currentNodeName } from '../backend/nodeAliases';
import { resolveModeCatalog } from '../connectionModes';
import { modesOfPlacement } from '../memberFamily';

export const FREEDOM_EDGES_ONLY_KEY = 'edge.freedom.edgesOnly';

/** The family slug whose modes reach members only through edges. */
export const FREEDOM_FAMILY = 'freedom';

/** Whether freedom modes are only served through edges. Absent or unreadable: off. */
export async function freedomEdgesOnly(db: DatabaseReader): Promise<boolean> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', FREEDOM_EDGES_ONLY_KEY))
    .unique();
  if (!row) return false;
  try {
    return JSON.parse(row.value) === true;
  } catch {
    return false;
  }
}

/** The edge layer a mode's fronting needs; null when it names none (`direct`, unknown). */
export function layerOfFronting(fronting: ModeFronting | null | undefined): EdgeLayer | null {
  if (fronting === 'edge-l4') return 'l4';
  if (fronting === 'edge-l7') return 'l7';
  return null;
}

/** The fronting of each mode a backend is set up for (none: not set up, or a mode it does not carry). */
export async function setupFrontings(
  db: DatabaseReader,
  backendServerId: Id<'backendServers'>,
): Promise<Map<string, ModeFronting>> {
  const setup = await db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
    .unique();
  return new Map((setup?.modes ?? []).map((m) => [m.slug, m.shape.fronting]));
}

/** The enrolled node at a name (a name it had before a rename included), or null. */
export async function intentAt(
  db: DatabaseReader,
  backendServerId: Id<'backendServers'>,
  nodeName: string,
): Promise<Doc<'panelNodeIntents'> | null> {
  for (const name of [nodeName, await currentNodeName(db, backendServerId, nodeName)]) {
    if (!name) continue;
    const intent = await db
      .query('panelNodeIntents')
      .withIndex('by_server_name', (q) => q.eq('backendServerId', backendServerId).eq('name', name))
      .first();
    if (intent) return intent;
  }
  return null;
}

/** The freedom mode a key is held to, and the layer its node must be covered at (null: any). */
export interface FreedomHold {
  mode: string;
  fronting: ModeFronting | null;
  layer: EdgeLayer | null;
}

type HoldSub = Pick<Doc<'subscriptions'>, 'backend' | 'backendPlacement' | 'backendServerId'>;

/**
 * Whether a key is held to the rule at `node` (the node its body resolved to,
 * or its stored pin), and to which mode: the enrolled node's own mode first,
 * then its placement's. Null for a key neither places on a freedom mode, and
 * for a backend without connection modes (Outline). Does not read the switch.
 */
export async function freedomHoldOf(
  db: DatabaseReader,
  sub: HoldSub,
  node: string | null | undefined,
): Promise<FreedomHold | null> {
  if (sub.backend !== 'remnawave') return null;
  const { modes } = await resolveModeCatalog(db);
  const freedom = (slug: string | null | undefined): slug is string =>
    !!slug && modes.find((m) => m.id === slug)?.family === FREEDOM_FAMILY;
  const held: string[] = [];
  if (sub.backendServerId && node) {
    const intent = await intentAt(db, sub.backendServerId, node);
    if (intent && freedom(intent.mode)) held.push(intent.mode);
  }
  if (sub.backendPlacement)
    for (const slug of await modesOfPlacement(db, sub.backendPlacement))
      if (freedom(slug)) held.push(slug);
  const mode = held[0];
  if (!mode) return null;
  const fronting = sub.backendServerId
    ? ((await setupFrontings(db, sub.backendServerId)).get(mode) ?? null)
    : null;
  return { mode, fronting, layer: layerOfFronting(fronting) };
}

/** What covers a node: a delivery binding, and the layers of the live edges its origin hands out. */
export interface NodeProtection {
  bound: boolean;
  layers: ReadonlySet<EdgeLayer>;
}

/**
 * Why a node of a freedom mode's pool is withheld from the mode's members, or
 * null when it may serve them: covered by a binding whose origin hands out a
 * live edge of the mode's layer (any layer when the mode names none).
 */
export function withheldReason(p: {
  protection: NodeProtection;
  enrolled: boolean;
  fronting: ModeFronting | null;
}): FreedomWithheldReason | null {
  const layer = layerOfFronting(p.fronting);
  if (p.protection.bound) {
    const live = layer ? p.protection.layers.has(layer) : p.protection.layers.size > 0;
    return live ? null : 'withheld_no_edge';
  }
  if (p.fronting === 'direct') return 'withheld_direct_mode';
  return p.enrolled ? 'withheld_unprotected' : 'withheld_unmanaged';
}

/** The backends (slugs) that set a mode up `direct`. */
export async function directSetupsOf(db: DatabaseReader, slug: string): Promise<string[]> {
  const out: string[] = [];
  for (const setup of await db.query('panelSetups').collect())
    if (setup.modes.some((m) => m.slug === slug && m.shape.fronting === 'direct'))
      out.push((await db.get(setup.backendServerId))?.slug ?? String(setup.backendServerId));
  return out.sort();
}

/**
 * While freedom modes are only served through edges, a freedom-family mode is
 * never made servable while a backend sets it up `direct` (its members would
 * be handed the nodes' own addresses, or nothing): the plain reason why, or
 * null. The switch is read by the caller.
 */
export async function freedomDirectRefusal(
  db: DatabaseReader,
  slug: string,
): Promise<string | null> {
  const where = await directSetupsOf(db, slug);
  if (where.length === 0) return null;
  return `Freedom modes are only served through edges, and "${slug}" is set up direct on ${where.join(', ')}. Keep it in another family, or set up a mode behind an edge for it`;
}
