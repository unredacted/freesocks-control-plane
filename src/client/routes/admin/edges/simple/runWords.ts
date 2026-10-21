/**
 * The protect flow's small pure helpers (unit-tested).
 *
 * Exports:
 *   TestItem, runTestItems(run)      the test card's lines from a run's `testLinks`
 *   runTestLines(run)                every line of the card, the ones already ticked included
 *   needButtons(code)                the one button (and at most one secondary) of an interruption
 *   automationOn(config)             the four switches `POST automation` sets, read back as one
 *   automationState(config), automationNote(state)   what those switches mean apart
 *   nodeAutomationWords(config, node)  the node page's automatic-replacement card
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

export type NeedAction =
  | 'retry'
  | 'retry_another_address'
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
  /** A sentence instead of a second button. */
  hint?: string;
}

const B = (label: string, action: NeedAction): NeedButton => ({ label, action });

/** One card, one sentence, one button, at most one secondary (plan 1.3). */
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
      return {
        primary: B('Try another address', 'retry_another_address'),
        secondary: B('Go live anyway', 'accept_partial'),
      };
    case 'blocked_in':
      // Its first check found the address blocked in a censored country while
      // it works from elsewhere: a new one is likely in another range.
      return {
        primary: B('Try another address', 'retry_another_address'),
        secondary: B('Use it anyway', 'accept_partial'),
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

/** A node's provider set in words (the node page's card): per location, then what members miss. */
export function providerPickWords(
  view: Pick<
    ProviderSetView,
    'picks' | 'reduced' | 'coolingOnly' | 'uncarried' | 'deficit' | 'hasSet'
  >,
  nameOf: (listenerKey: string) => string = (k) => k,
  now: number = Date.now(),
): {
  picks: Array<{ locationId: string; counts: string; cooling: string | null }>;
  notes: string[];
} {
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
  if (view.hasSet && view.deficit > 0)
    notes.push(
      `${plural(view.deficit, 'address is', 'addresses are')} still missing; automatic upkeep adds ${view.deficit === 1 ? 'it' : 'them'}.`,
    );
  return { picks, notes };
}
