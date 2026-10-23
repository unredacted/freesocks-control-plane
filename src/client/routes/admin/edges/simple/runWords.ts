/**
 * The protect flow's small pure helpers (unit-tested).
 *
 * Exports:
 *   TestItem, runTestItems(run)      the test card's lines from a run's `testLinks`
 *   runTestLines(run)                every line of the card, the ones already ticked included
 *   TEST_PROFILE_NOTE                under every test link: a short test only, remove the profile after
 *   replaceWords(item)               the "Doesn't work" confirmation: the address it removes and replaces
 *   needButtons(code)                the one button (at most one secondary, and a quiet third) of an interruption
 *   automationOn(config)             the four switches `POST automation` sets, read back as one
 *   automationState(config), automationNote(state)   what those switches mean apart
 *   nodeAutomationWords(config, node)  the node page's automatic-replacement card
 *   spareInUseWords(config, node, slot?), heldSpareWords(slot)  whether a spare would go in use
 *   upkeepAddsMissing(config, node)  whether automatic upkeep adds what a node still lacks
 *   providerPickWords(view, opts)    the node's provider set card in words
 *   planWords(plan)                  the review sentence pieces of a plan
 *   hideButton(n), moreDirectWords(n)  the "hide the unsupported direct addresses" words
 */
import type {
  ProviderSetView,
  SetupRunAdmin,
  SetupPlanResponse,
} from '../../../../../shared/contracts/edges';
import { transportName } from '../lib/format';

export interface TestItem {
  edgeId: string;
  listenerKey: string;
  /** The transport in words (never the key); null when not known. */
  name: string | null;
  /** Empty for a named-connection retest of an address already in use. */
  link: string;
  method: 'test_link' | 'named_connection';
  endpoint: string;
  listenerRevision: number;
  configHash: string;
}

/** A run listener's transport in words, by key (null when the run predates it). */
export function runListenerName(
  run: Pick<SetupRunAdmin, 'listeners'>,
  listenerKey: string,
): string | null {
  const t = run.listeners.find((l) => l.listenerKey === listenerKey)?.transport;
  return t ? transportName(t) : null;
}

/**
 * One test line's name: the transport in words, and where the address is when
 * the run protects the node from more than one location ("REALITY in Region B").
 */
export function runLineName(
  run: Pick<SetupRunAdmin, 'listeners'> & Partial<Pick<SetupRunAdmin, 'picks'>>,
  edgeId: string,
  listenerKey: string,
): string | null {
  const base = runListenerName(run, listenerKey);
  const picks = run.picks ?? [];
  if (picks.length <= 1) return base;
  const where = run.listeners.find((l) => l.edgeId === edgeId)?.locationId ?? null;
  const label = picks.find((p) => p.locationId === where)?.label;
  return label ? `${base ?? 'Address'} in ${label}` : base;
}

/** "Not checked from outside over IPv6": a family no outside source could test. */
export function notCheckedWords(families: ReadonlyArray<4 | 6>): string {
  if (families.includes(4) && families.includes(6)) return 'Not checked from outside';
  return `Not checked from outside over IPv${families.includes(6) ? 6 : 4}`;
}

/**
 * The addresses the outside check passed with a family nothing could test
 * (FCP's own server has no IPv6, a source takes no IPv6 literal): one line
 * each, so the gap stays visible without stopping the run.
 */
export function runNotCheckedLines(
  run: Pick<SetupRunAdmin, 'listeners'> & Partial<Pick<SetupRunAdmin, 'picks'>>,
): Array<{ key: string; text: string }> {
  return run.listeners
    .filter((l): l is typeof l & { edgeId: string } => l.edgeId !== null && l.notChecked.length > 0)
    .map((l) => {
      const words = notCheckedWords(l.notChecked);
      return {
        key: `${l.listenerKey}:${l.edgeId}`,
        text: `${runLineName(run, l.edgeId, l.listenerKey) ?? 'New address'}: ${words[0]!.toLowerCase()}${words.slice(1)}.`,
      };
    });
}

export function runTestItems(
  run: Pick<SetupRunAdmin, 'testLinks'> & Partial<Pick<SetupRunAdmin, 'listeners' | 'picks'>>,
): TestItem[] {
  return run.testLinks.map((l) => ({
    edgeId: l.edgeId,
    listenerKey: l.listenerKey,
    name: run.listeners
      ? runLineName({ listeners: run.listeners, picks: run.picks }, l.edgeId, l.listenerKey)
      : null,
    link: l.link,
    method: l.method,
    endpoint: l.binding.endpoint,
    listenerRevision: l.binding.listenerRevision,
    configHash: l.binding.configHash,
  }));
}

/**
 * The whole test card of a run: the lines still to test (`testLinks`) and the
 * ones already ticked (`testedEndpoints`), in the run's listener order. Each
 * tick is saved on its own, so between a tick and the rebuilt card the ticked
 * line is still among the links: a line counts as done when its tick is newer
 * than its link. A link issued after the tick (a retest) is pending again.
 */
export function runTestLines(
  run: Pick<SetupRunAdmin, 'testLinks' | 'testedEndpoints' | 'listeners'> &
    Partial<Pick<SetupRunAdmin, 'picks'>>,
): { items: TestItem[]; done: Set<string> } {
  const current = run.listeners.filter((l) => l.layer === 'l4' && l.edgeId !== null);
  const linkOf = new Map(run.testLinks.map((l) => [l.edgeId, l]));
  const tickOf = new Map(run.testedEndpoints.map((t) => [t.edgeId, t]));
  const items: TestItem[] = [];
  const done = new Set<string>();
  for (const l of current) {
    const edgeId = l.edgeId!;
    const link = linkOf.get(edgeId);
    const tick = tickOf.get(edgeId);
    const ticked =
      tick !== undefined && (!link || Date.parse(tick.at) >= Date.parse(link.binding.issuedAt));
    if (link)
      items.push(
        runTestItems({ testLinks: [link], listeners: run.listeners, picks: run.picks })[0]!,
      );
    else if (ticked)
      items.push({
        edgeId,
        listenerKey: tick.listenerKey,
        name: runLineName(run, edgeId, tick.listenerKey),
        link: '',
        method: 'test_link',
        endpoint: tick.endpoint,
        listenerRevision: 0,
        configHash: '',
      });
    if (ticked) done.add(edgeId);
  }
  return { items, done };
}

/**
 * Under every test link: the profile is for one short test. Left connected in
 * a client, it keeps using the test account until the backend limits it.
 */
export const TEST_PROFILE_NOTE =
  'For a short test only. Remove this profile from the client once you have tried it: left connected, it uses up the test account.';

/**
 * The "Doesn't work" confirmation of one test line: it names the address (and
 * its transport when known) and says it is removed and replaced, for good.
 */
export function replaceWords(item: Pick<TestItem, 'name' | 'endpoint'>): {
  title: string;
  body: string;
} {
  const what = item.name ? `${item.name} at ${item.endpoint}` : item.endpoint;
  return {
    title: `Replace ${item.endpoint}?`,
    body: `${what} is removed at the provider and a new address is created in its place, to test here again. A removed address cannot be brought back. If no new address can be created now, nothing is removed.`,
  };
}

export type NeedAction =
  | 'retry'
  | 'retry_another_address'
  | 'check_again'
  | 'accept_partial'
  | 'choose_account'
  | 'test_account'
  | 'thaw'
  | 'manual_setup'
  | 'choose_mode'
  | 'continue'
  | 'review'
  | 'family'
  | 'quarantine'
  | 'approve';

export interface NeedButton {
  label: string;
  action: NeedAction;
}
export interface NeedButtons {
  primary: NeedButton;
  secondary?: NeedButton;
  /** A quiet third choice (a link under the buttons): only where the card has three ways on. */
  more?: NeedButton;
  /** A sentence instead of a second button. */
  hint?: string;
}

const B = (label: string, action: NeedAction): NeedButton => ({ label, action });

/**
 * One card, one sentence, one button, at most one secondary (plan 1.3). The
 * two cards the outside check stops on also offer the check again, quietly.
 */
export function needButtons(code: string): NeedButtons {
  switch (code) {
    case 'account_untested':
      return {
        primary: B('Test again', 'test_account'),
        secondary: B('Choose another account', 'choose_account'),
      };
    case 'account_incompatible':
      return { primary: B('Choose another account', 'choose_account') };
    case 'maintenance':
      return { primary: B('Resume new work', 'thaw') };
    case 'too_many_inbounds':
    case 'use_manual_setup':
      return { primary: B('Open its origin', 'manual_setup') };
    case 'choose_mode':
      return { primary: B('Choose connection mode', 'choose_mode') };
    case 'provider_failed':
      return {
        primary: B('Try again', 'retry'),
        secondary: B('Choose another account', 'choose_account'),
      };
    case 'address_unreachable':
      // A new load balancer can take a while to answer: the same address,
      // checked afresh, before a new one is bought.
      return {
        primary: B('Check again', 'check_again'),
        secondary: B('Try another address', 'retry_another_address'),
        more: B('Go live anyway', 'accept_partial'),
      };
    case 'blocked_in':
      // Its first check found the address blocked in a censored country while
      // it works from elsewhere: a new one is likely in another range.
      return {
        primary: B('Try another address', 'retry_another_address'),
        secondary: B('Use it anyway', 'accept_partial'),
        more: B('Check again', 'check_again'),
        hint: 'A new address may land in a range that country does not block.',
      };
    case 'try_it':
      // Per line on the test card: each tick is saved on its own, "Doesn't work"
      // replaces that one address; the run carries on once every line works.
      return {
        primary: B('Works', 'continue'),
        secondary: B('Doesn’t work', 'retry_another_address'),
        hint: 'Each tick is saved right away. The run carries on by itself once every address works.',
      };
    case 'review_changed':
      return { primary: B('Review the change', 'review') };
    case 'hide_failed':
      return {
        primary: B('Check again', 'retry'),
        hint: 'Or hide them in the backend yourself, then check again.',
      };
    case 'family_disabled':
      return { primary: B('Turn on for that family', 'family') };
    case 'quarantined':
      return { primary: B('Review', 'quarantine') };
    case 'node_not_approved':
      // The approval card below carries this button. No retry: the run would only
      // park here again, and it carries on by itself once the node is approved.
      return {
        primary: B('Approve go-live', 'approve'),
        hint: 'The run carries on by itself once you approve.',
      };
    case 'coverage_incomplete':
    case 'rehearsal_failed':
    default:
      return { primary: B('Try again', 'retry') };
  }
}

type AutomationConfig = {
  enabled: boolean;
  autoRotate: boolean;
  autoProvisionToDesired: boolean;
  probe: { enabled: boolean };
};

/** A missing address as the providers view names it (`ProviderSetView['missing']`). */
type MissingPlace = { locationId: string | null; label: string | null; accountName: string | null };

/**
 * Where a spare stands against the pool (the providers view, and the dry run
 * for a new one): whether putting it in use would get it a slot now (null: not
 * known), and what the held slots wait for.
 */
export interface SpareSlot {
  takesSlot: boolean | null;
  missing: ReadonlyArray<MissingPlace>;
  /** Free slots held for `missing` (the view's `pool.held`). */
  held?: number;
}

/** "A (Acct)", "A (Acct) or B (Acct)": the distinct named locations of what is missing. */
function missingPlaces(missing: ReadonlyArray<MissingPlace>): string[] {
  const out: string[] = [];
  for (const m of missing) {
    if (!m.label) continue;
    const name = m.accountName ? `${m.label} (${m.accountName})` : m.label;
    if (!out.includes(name)) out.push(name);
  }
  return out;
}

const orList = (xs: string[]): string =>
  xs.length <= 1 ? (xs[0] ?? '') : `${xs.slice(0, -1).join(', ')} or ${xs[xs.length - 1]}`;

/**
 * Why a tested spare would stay a spare: the free slot is held for what the
 * node still lacks (reserved allocation), and the two ways on: Replace address
 * (swap one in use for it), or remove the location that lacks an address.
 */
export function heldSpareWords(slot: Pick<SpareSlot, 'missing' | 'held'>): string {
  const places = missingPlaces(slot.missing);
  const slots = (slot.held ?? 1) > 1 ? 'free slots are' : 'free slot is';
  if (places.length === 0)
    return `It stays a spare: the ${slots} held for an address this node still lacks. To use this one, replace an address in use with it (Replace address).`;
  return `It stays a spare: the ${slots} held for an address in ${orList(places)}, which this node still lacks. To use this one, replace an address in use with it (Replace address), or remove ${places.length === 1 ? 'that location' : 'those locations'} from the node.`;
}

/**
 * Whether a spare stays a spare: with automatic publishing on, a node that
 * wants more addresses in use than it has gets a tested spare put in use by
 * the next upkeep pass (every 5 minutes), so "keep" or "add" a spare can mean
 * one more address in use. The sentence says so, or null when it stays a spare.
 * A spare that would get no slot (`slot.takesSlot` false: the free slots are
 * held for what the node still lacks) stays a spare whatever the switches, and
 * the sentence says why (`heldSpareWords`).
 */
export function spareInUseWords(
  config: { enabled: boolean; autoPublishStandby: boolean },
  node: {
    enabled: boolean;
    setupOwned: boolean;
    desiredPublished: number;
    publishedEdgeIds: ReadonlyArray<string | null>;
  },
  slot: SpareSlot | null = null,
): string | null {
  if (!node.enabled || node.setupOwned) return null;
  const published = node.publishedEdgeIds.filter(Boolean).length;
  const wanted = node.desiredPublished;
  if (wanted <= published) return null;
  if (slot?.takesSlot === false) return heldSpareWords(slot);
  if (!config.enabled || !config.autoPublishStandby) return null;
  return `It may be put in use at once: this node wants ${wanted} ${wanted === 1 ? 'address' : 'addresses'} in use and has ${published}.`;
}

/**
 * Whether automatic upkeep provisions what a node still lacks: the master
 * switch and `edge.autoProvisionToDesired` (convex/edgeReconcile.ts step 5),
 * on a node that is switched on and that no guided setup owns.
 */
export function upkeepAddsMissing(
  config: { enabled: boolean; autoProvisionToDesired: boolean },
  node: { enabled: boolean; setupOwned: boolean },
): boolean {
  return config.enabled && config.autoProvisionToDesired && node.enabled && !node.setupOwned;
}

/** The four switches `POST automation {on}` sets, read back as one. */
export function automationOn(config: AutomationConfig): boolean {
  return (
    config.enabled && config.autoRotate && config.autoProvisionToDesired && config.probe.enabled
  );
}

/**
 * What the four switches mean apart (a test deployment keeps spares by hand,
 * docs/beta-deploy.md "Walking automatic rotation"):
 *   replaces    a blocked address can be replaced on its own: the master switch
 *               and automatic rotation (each node also opts in)
 *   makesSpares upkeep makes new spares and fills pools (billable)
 *   probes      reachability probes run
 */
export interface AutomationState {
  replaces: boolean;
  makesSpares: boolean;
  probes: boolean;
}
export function automationState(config: AutomationConfig): AutomationState {
  return {
    replaces: config.enabled && config.autoRotate,
    makesSpares: config.enabled && config.autoProvisionToDesired,
    probes: config.probe.enabled,
  };
}

/** The Edges home's line under the switch when replacement is on but not all of it. */
export function automationNote(state: AutomationState): string | null {
  if (!state.replaces) return null;
  if (!state.makesSpares && !state.probes)
    return 'FCP does not make new spares on its own, and reachability probes are off.';
  if (!state.makesSpares)
    return 'FCP does not make new spares on its own: each replacement uses a spare you added and tested.';
  if (!state.probes)
    return 'Reachability probes are off, so the detector only has member reports to go on.';
  return null;
}

/**
 * The node page's "Replace addresses automatically on this node" card: what
 * actually decides whether this node's blocked address is replaced (the master
 * switch, automatic rotation, a setup run that owns the node, this node's own
 * switch), and on its own line whether spares come back by themselves.
 * `runLive: false` = no setup run is working on a setup-owned node (a cancelled
 * or failed one left it): it is simply not live yet.
 */
export function nodeAutomationWords(
  config: AutomationConfig,
  node: { autoRotate: boolean; setupOwned: boolean; runLive?: boolean },
): { line: string; spares: string | null } {
  const spares = config.autoProvisionToDesired
    ? null
    : 'FCP does not make new spares on its own (Edges, Settings). Each replacement uses one tested spare; add and test the next one yourself.';
  if (!config.enabled)
    return {
      line: 'Edge automation is off for every node. Turn on automatic protection from the Edges page for this to act.',
      spares: null,
    };
  if (!config.autoRotate)
    return {
      line: 'Automatic rotation is off for every node (Edges, Settings). This switch acts once it is on.',
      spares: null,
    };
  if (node.setupOwned && node.runLive === false)
    return {
      line: 'This node is not live yet. Automatic replacement starts once it goes live.',
      spares: null,
    };
  if (node.setupOwned)
    return {
      line: 'A setup run is working on this node. Automatic replacement starts once it is done.',
      spares: null,
    };
  if (!node.autoRotate)
    return {
      line: 'Off for this node: an address that looks blocked shows under Needs you and waits for you to replace it.',
      spares: null,
    };
  return {
    line: 'When an address looks blocked, FCP switches members to a tested spare on its own.',
    spares,
  };
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
const direct = (n: number) => plural(n, 'direct address', 'direct addresses');

/** The button that consents to hiding `n` unsupported direct addresses (Hosts). */
export const hideButton = (n: number): string => `Protect and hide ${direct(n)}`;

/** "N more direct addresses ... cannot carry:", for Hosts found after the review. */
export function moreDirectWords(n: number): string {
  return `${n === 1 ? 'One more direct address' : `${n} more direct addresses`} on the backend ${n === 1 ? 'uses' : 'use'} a transport the new address cannot carry:`;
}

export interface PlanWords {
  /** The one review sentence. */
  sentence: string;
  /** The uncovered direct Hosts, or null when nothing needs consent. */
  uncovered: { count: number; remarks: string[]; uuids: string[]; statement: string } | null;
  /** The fleet-wide rendering consequence, or null. */
  renderGlobal: string | null;
  /** The primary button label. */
  button: string;
  /** Which subscription formats the protected transports cover. */
  formats: string;
}

export function planWords(
  plan: Pick<
    SetupPlanResponse,
    'nodeName' | 'inbounds' | 'requiredListeners' | 'directHosts' | 'renderGlobal'
  >,
  accountName: string,
  /** How many addresses the run creates (a set may need more than one per transport). */
  addresses: number = plan.requiredListeners.length,
): PlanWords {
  const required = addresses;
  const sentence = `FCP creates ${plural(required, 'address', 'addresses')} in ${accountName}, checks ${required === 1 ? 'it' : 'each one'} from outside and with you, then moves ${plan.nodeName} behind ${required === 1 ? 'it' : 'them'}.`;
  const unc = plan.directHosts.filter((h) => !h.covered);
  const uncovered =
    unc.length === 0
      ? null
      : {
          count: unc.length,
          remarks: unc.map((h) => h.remark),
          uuids: unc.map((h) => h.uuid),
          statement: `${direct(unc.length)} on the backend ${unc.length === 1 ? 'uses' : 'use'} a transport the new address cannot carry. Protecting the node hides ${unc.length === 1 ? 'it' : 'them'}, so members who rely on ${unc.length === 1 ? 'it' : 'them'} must switch to a supported one.`,
        };
  const others = plan.renderGlobal.affectedRelays;
  const renderGlobal = !plan.renderGlobal.willEnable
    ? null
    : others.length === 0
      ? 'Going live also turns on protected delivery.'
      : `Going live also turns on protected delivery for ${plural(others.length, 'other node', 'other nodes')} that ${others.length === 1 ? 'is' : 'are'} ready for it (${others.join(', ')}).`;
  const button = uncovered ? hideButton(uncovered.count) : 'Protect this node';
  // The protected transports only: on a node with more than one run takes, the
  // plan lists every frontable one but the run carries the chosen ones.
  const protectedOnes = plan.inbounds.filter(
    (i) => i.frontable && plan.requiredListeners.includes(i.listenerKey),
  );
  const all = (k: 'links' | 'singbox' | 'clash') =>
    protectedOnes.length > 0 && protectedOnes.every((i) => i.formats[k]);
  const names = [
    all('links') ? 'link' : null,
    all('singbox') ? 'sing-box' : null,
    all('clash') ? 'Clash' : null,
  ].filter((n): n is string => n !== null);
  const formats =
    names.length === 3
      ? 'Works for every subscription format.'
      : names.length === 0
        ? 'No subscription format is fully covered yet.'
        : `Works for ${names.join(' and ')} subscriptions; other formats keep the direct address.`;
  return { sentence, uncovered, renderGlobal, button, formats };
}

/** What a chosen set of picks makes, in words (the protect sheet's summary). */
export interface SetWords {
  /** One line per pick: how many addresses it gets. */
  lines: Array<{ locationId: string; text: string }>;
  /** Transports no picked location carries, or null. */
  uncovered: string | null;
  /** Transports with no backup at another provider, or null. */
  reduced: string | null;
  /** Too many addresses for one node, or null. */
  tooLarge: string | null;
  /** Where the addresses go, for the review sentence. */
  where: string;
}

export function setWords(
  set: {
    picks: Array<{ locationId: string; accountId: string; label: string }>;
    targets: Array<{ listenerKey: string; locationId: string }>;
    reduced: Array<{ listenerKey: string }>;
    uncovered: string[];
    tooLarge: boolean;
  },
  nameOf: (listenerKey: string) => string,
  accountNameOf: (accountId: string) => string,
): SetWords {
  const lines = set.picks.map((p) => {
    const n = set.targets.filter((t) => t.locationId === p.locationId).length;
    return {
      locationId: p.locationId,
      text: `${plural(n, 'address', 'addresses')} in ${p.label} (${accountNameOf(p.accountId)}).`,
    };
  });
  const names = (keys: string[]) => [...new Set(keys)].map(nameOf).join(', ');
  const uncovered =
    set.uncovered.length > 0
      ? `No picked location carries ${names(set.uncovered)}. Add one that can.`
      : null;
  const reduced =
    set.reduced.length > 0
      ? `Members on ${names(set.reduced.map((r) => r.listenerKey))} have no backup at another provider.`
      : null;
  const tooLarge = set.tooLarge
    ? 'These locations need more addresses than one node can use.'
    : null;
  const where =
    set.picks.length === 1
      ? `${accountNameOf(set.picks[0]!.accountId)} (${set.picks[0]!.label})`
      : `${set.picks.length} locations`;
  return { lines, uncovered, reduced, tooLarge, where };
}

/** Per pick of a run: how many of its addresses are made and published, in words. */
export function runPickLines(
  run: Pick<SetupRunAdmin, 'listeners' | 'picks'>,
): Array<{ locationId: string; text: string }> {
  if (run.picks.length <= 1) return [];
  return run.picks
    .filter((p): p is typeof p & { locationId: string } => p.locationId !== null)
    .map((p) => {
      const mine = run.listeners.filter((l) => l.locationId === p.locationId);
      const published = mine.filter((l) => l.published).length;
      const where = `${p.label ?? 'A location'}${p.accountName ? ` (${p.accountName})` : ''}`;
      return {
        locationId: p.locationId,
        text:
          published === mine.length && mine.length > 0
            ? `${where}: ${plural(mine.length, 'address', 'addresses')}, in use.`
            : `${where}: ${plural(mine.length, 'address', 'addresses')}, ${published} in use.`,
      };
    });
}

/**
 * A node's provider set in words (the node page's card): per location, then the
 * locations that hold one of its addresses outside the set (`outside`: the set
 * changes only when a run goes live, so the spare of a re-protect that failed
 * sits there), then what members miss. What is still missing names its
 * locations, and says who adds it: automatic upkeep only when `upkeepAdds`
 * (`upkeepAddsMissing`), else nothing on its own, with the two ways on.
 */
export function providerPickWords(
  view: Pick<
    ProviderSetView,
    'picks' | 'reduced' | 'coolingOnly' | 'uncarried' | 'deficit' | 'hasSet'
  > &
    Partial<Pick<ProviderSetView, 'outside' | 'missing'>>,
  opts: { nameOf?: (listenerKey: string) => string; now?: number; upkeepAdds?: boolean } = {},
): {
  picks: Array<{ locationId: string; counts: string; cooling: string | null }>;
  outside: Array<{ locationId: string; counts: string; why: string }>;
  notes: string[];
} {
  const nameOf = opts.nameOf ?? ((k: string) => k);
  const now = opts.now ?? Date.now();
  const picks = view.picks.map((p) => {
    const left = p.coolingUntil
      ? Math.max(1, Math.ceil((Date.parse(p.coolingUntil) - now) / 60_000))
      : 0;
    return {
      locationId: p.locationId,
      counts: `${p.inUse} in use, ${p.spare} spare.`,
      cooling:
        left > 0
          ? `An address here was just blocked: automatic work keeps away for about ${plural(left, 'minute', 'minutes')}.`
          : null,
    };
  });
  const outside = (view.outside ?? []).map((o) => ({
    locationId: o.locationId,
    counts: `${o.inUse} in use, ${o.spare} spare.`,
    why:
      o.inUse > 0
        ? "Not one of this node's locations, though members are given its address here. The node's locations change only when a run goes live."
        : "Not one of this node's locations: a run that did not go live, or a spare added by hand, left it here. The node's locations change only when a run goes live: add this location to keep it, or delete the spare.",
  }));
  const names = (keys: string[]) => [...new Set(keys)].map(nameOf).join(', ');
  const notes: string[] = [];
  if (view.uncarried.length > 0)
    notes.push(`No location here carries ${names(view.uncarried)}. Add one that can.`);
  if (view.coolingOnly.length > 0)
    notes.push(`Every location for ${names(view.coolingOnly)} is cooling after a block.`);
  if (view.reduced.length > 0)
    notes.push(
      `Members on ${names(view.reduced.map((r) => r.listenerKey))} have no backup at another provider.`,
    );
  if (view.hasSet && view.deficit > 0) {
    const places = [...new Set((view.missing ?? []).map((m) => m.label).filter((l) => !!l))];
    const what = `${plural(view.deficit, 'address is', 'addresses are')} still missing${places.length > 0 ? ` (${places.join(', ')})` : ''}`;
    const it = view.deficit === 1 ? 'it' : 'them';
    notes.push(
      opts.upkeepAdds
        ? `${what}; automatic upkeep adds ${it}.`
        : places.length > 0
          ? `${what}. Nothing adds ${it} on its own: add a spare address there, or remove ${places.length === 1 ? 'the location' : 'those locations'}.`
          : `${what}. Nothing adds ${it} on its own: add a spare address.`,
    );
  }
  return { picks, outside, notes };
}
