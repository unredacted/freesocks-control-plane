/**
 * The protect flow's small pure helpers (unit-tested).
 *
 * Exports:
 *   TestItem, runTestItems(run)      the test card's lines from a run's `testLinks`
 *   runTestLines(run)                every line of the card, the ones already ticked included
 *   needButtons(code)                the one button (and at most one secondary) of an interruption
 *   automationOn(config)             the four switches `POST automation` sets, read back as one
 *   planWords(plan)                  the review sentence pieces of a plan
 *   hideButton(n), moreDirectWords(n)  the "hide the unsupported direct addresses" words
 */
import type { SetupRunAdmin, SetupPlanResponse } from '../../../../../shared/contracts/edges';

export interface TestItem {
  edgeId: string;
  listenerKey: string;
  /** Empty for a named-connection retest of an address already in use. */
  link: string;
  method: 'test_link' | 'named_connection';
  endpoint: string;
  listenerRevision: number;
  configHash: string;
}

export function runTestItems(run: Pick<SetupRunAdmin, 'testLinks'>): TestItem[] {
  return run.testLinks.map((l) => ({
    edgeId: l.edgeId,
    listenerKey: l.listenerKey,
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
  run: Pick<SetupRunAdmin, 'testLinks' | 'testedEndpoints' | 'listeners'>,
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
    if (link) items.push(runTestItems({ testLinks: [link] })[0]!);
    else if (ticked)
      items.push({
        edgeId,
        listenerKey: tick.listenerKey,
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
      return { primary: B('Use manual setup', 'manual_setup') };
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

/** The four switches `POST automation {on}` sets, read back as one. */
export function automationOn(config: {
  enabled: boolean;
  autoRotate: boolean;
  autoProvisionToDesired: boolean;
  probe: { enabled: boolean };
}): boolean {
  return (
    config.enabled && config.autoRotate && config.autoProvisionToDesired && config.probe.enabled
  );
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
): PlanWords {
  const required = plan.requiredListeners.length;
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
  const renderGlobal = plan.renderGlobal.willEnable
    ? `Going live also turns on protected delivery for ${plural(plan.renderGlobal.affectedRelays.length, 'other node', 'other nodes')} that ${plan.renderGlobal.affectedRelays.length === 1 ? 'is' : 'are'} ready for it${plan.renderGlobal.affectedRelays.length > 0 ? ` (${plan.renderGlobal.affectedRelays.join(', ')})` : ''}.`
    : null;
  const button = uncovered ? hideButton(uncovered.count) : 'Protect this node';
  const frontable = plan.inbounds.filter((i) => i.frontable);
  const all = (k: 'links' | 'singbox' | 'clash') =>
    frontable.length > 0 && frontable.every((i) => i.formats[k]);
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
