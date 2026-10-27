/**
 * Where each name of a family stands on its way to members, and what a
 * transport's names add up to (docs/edges.md "A transport's names"). Pure: the
 * transports view (`convex/sniTransports.ts`) and the family page read the same
 * answer, so every count agrees.
 *
 * A name reaches members in steps (§ Rollout and acceptance): it qualifies
 * against the target, a rollout puts it on the backend, and a receipt on a node
 * activates it there. So, per name:
 *
 *   in_use        handed to the members of every node of the transport
 *   waiting_test  on the backend in the newest confirmed rollout, not yet
 *                 handed out on some node: a test there proves it
 *   to_send       qualified, bound, not on the backend: the next rollout adds it
 *   idle          qualified but on no way to members now: the family is bound to
 *                 nothing, or the backend lists it outside any confirmed rollout,
 *                 or no node is protected (the next rollout covers it)
 *   checking      waiting for its first qualification
 *   failing       its last qualification failed, or it is suspended
 *   off           retired or burned
 */

export type NameDelivery =
  | 'in_use'
  | 'waiting_test'
  | 'to_send'
  | 'idle'
  | 'checking'
  | 'failing'
  | 'off';

export interface DeliveryName {
  name: string;
  status: 'active' | 'suspended' | 'retired' | 'burned';
  qualification: 'pending' | 'ok' | 'failed';
}

export interface DeliveryFacts {
  /** A transport is bound to the family. */
  bound: boolean;
  /** The names the bound transport lists on the backend, as last read. */
  onBackend: ReadonlySet<string>;
  /** The names of the newest rollout the backend was seen to hold (a test can prove them). */
  provable: ReadonlySet<string>;
  /** Per node (listener) of the transport: the names handed to its members. */
  nodes: ReadonlyArray<ReadonlySet<string>>;
}

export interface NameDeliveryView {
  state: NameDelivery;
  /** On how many nodes members are handed it. */
  inUseOn: number;
  /** How many nodes the transport has (protected listeners). */
  nodes: number;
}

/** A name that qualifies: the only kind a rollout writes or a receipt activates. */
export const usableName = (n: Pick<DeliveryName, 'status' | 'qualification'>) =>
  n.status === 'active' && n.qualification === 'ok';

export function nameDelivery(n: DeliveryName, f: DeliveryFacts): NameDeliveryView {
  const nodes = f.nodes.length;
  const inUseOn = f.nodes.filter((s) => s.has(n.name)).length;
  const view = (state: NameDelivery) => ({ state, inUseOn, nodes });
  if (n.status === 'retired' || n.status === 'burned') return view('off');
  if (n.status === 'suspended' || n.qualification === 'failed') return view('failing');
  if (n.qualification === 'pending') return view('checking');
  if (nodes > 0 && inUseOn === nodes) return view('in_use');
  // Some node still lacks it: a test there proves it, when a confirmed rollout carries it.
  if (nodes > 0 && f.provable.has(n.name)) return view('waiting_test');
  if (inUseOn > 0) return view('in_use');
  if (f.bound && !f.onBackend.has(n.name)) return view('to_send');
  return view('idle');
}

/**
 * One name of a family bound to several transports: each transport answers
 * for itself (`nameDelivery` with its own backend, rollout and nodes), and the
 * name shows the step still needed somewhere (a test, then a send), else in
 * use, with the nodes of every transport counted together. Bound to none: the
 * `unbound` answer.
 */
export function combineDeliveries(
  views: readonly NameDeliveryView[],
  unbound: NameDeliveryView,
): NameDeliveryView {
  if (views.length === 0) return unbound;
  const inUseOn = views.reduce((n, v) => n + v.inUseOn, 0);
  const nodes = views.reduce((n, v) => n + v.nodes, 0);
  const order: NameDelivery[] = [
    'off',
    'failing',
    'checking',
    'waiting_test',
    'to_send',
    'in_use',
    'idle',
  ];
  const state = order.find((s) => views.some((v) => v.state === s)) ?? 'idle';
  return { state, inUseOn, nodes };
}

export interface TransportCounts {
  inUse: number;
  waitingTest: number;
  toSend: number;
  idle: number;
  checking: number;
  failing: number;
  off: number;
}

export function countDeliveries(states: readonly NameDelivery[]): TransportCounts {
  const c: TransportCounts = {
    inUse: 0,
    waitingTest: 0,
    toSend: 0,
    idle: 0,
    checking: 0,
    failing: 0,
    off: 0,
  };
  const key: Record<NameDelivery, keyof TransportCounts> = {
    in_use: 'inUse',
    waiting_test: 'waitingTest',
    to_send: 'toSend',
    idle: 'idle',
    checking: 'checking',
    failing: 'failing',
    off: 'off',
  };
  for (const s of states) c[key[s]]++;
  return c;
}

/** One node: how many usable names its members get, and how many a test there would add. */
export function nodeCounts(
  names: readonly DeliveryName[],
  provable: ReadonlySet<string>,
  handedOut: ReadonlySet<string>,
): { inUse: number; waitingTest: number } {
  let inUse = 0;
  let waitingTest = 0;
  for (const n of names) {
    if (!usableName(n)) continue;
    if (handedOut.has(n.name)) inUse++;
    else if (provable.has(n.name)) waitingTest++;
  }
  return { inUse, waitingTest };
}

/**
 * The network to keep a transport's names on, when one is plain: the only
 * network that holds every address the target resolves to AND every address
 * in use on the transport. A family on a network fails every name whose target
 * is off it, so a network the target is not on is never suggested.
 */
export function suggestNetwork<N extends { slug: string }>(
  targetAddresses: readonly string[],
  edgeAddresses: readonly string[],
  networks: readonly N[],
  onNetwork: (ip: string, n: N) => boolean,
): N | null {
  if (targetAddresses.length === 0) return null;
  const fits = networks.filter((n) =>
    [...targetAddresses, ...edgeAddresses].every((ip) => onNetwork(ip, n)),
  );
  return fits.length === 1 ? fits[0]! : null;
}

/**
 * A network's place for the timing checks, from where a node is: its country
 * code, and the city a backend's location label starts with ("Kansas City, MO"
 * -> "Kansas City"). Null when the country is not a two-letter code; a label
 * that is not a plain place name gives no city.
 */
export function placeFromNode(
  countryCode: string | null | undefined,
  locationLabel: string | null | undefined,
): { country: string; city?: string } | null {
  const country = (countryCode ?? '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(country)) return null;
  const city = (locationLabel ?? '').split(',')[0]!.trim().replace(/\s+/g, ' ').slice(0, 60);
  return city && /^[\p{L}\p{M} .'-]+$/u.test(city) ? { country, city } : { country };
}

/** A family's short id for a transport: `VLESS_REALITY` -> `vless-reality`, made unique by the caller. */
export function familySlugForTransport(tag: string): string {
  const base = tag
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 34)
    .replace(/-+$/, '');
  return base || 'names';
}
