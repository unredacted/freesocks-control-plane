/**
 * A REALITY transport's names on a node's page (docs/edges.md "A transport's
 * names"; pure, unit-tested): one status line and ONE next step at a time,
 * the way the node's edges show theirs. The steps follow a name's way to
 * members: managed by FCP, checked against the cover site, sent to the node
 * (the backend), proven on the node by a test, then handed to its members.
 *
 * Words: a family is a "name list", its target the "cover site" (the real site
 * the port shows anyone without a member's key).
 */
import {
  usableCandidate,
  type SniCandidateRow,
  type SniHuntCertRead,
  type SniImportResult,
  type SniManaged,
  type SniRolloutPlan,
  type SniTransport,
  type SniTransportNode,
  type SniTransportsView,
  type SniAutoTest,
} from '../../../../../../shared/contracts/sni';
import type { Dot } from './words';
import { CLIENT_CHECK_COPY, CLIENT_CHECK_ENGINE_LABELS } from '../../../../../lib/edgeCodes';

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export type NamesStep =
  /** `edge.sni.enabled` is off: FCP manages no names. */
  | { kind: 'names_off' }
  /** Names set by hand: hand them to FCP. */
  | { kind: 'manage' }
  /** Its name list is switched off: nothing new is sent. */
  | { kind: 'list_off' }
  /** A send to the backend is running. */
  | { kind: 'sending' }
  /** Checked names are not on the node yet. */
  | { kind: 'send' }
  /** The last send did not go through, and names still wait for one. */
  | { kind: 'send_again' }
  /** Names wait for a send that a switch holds back. */
  | { kind: 'send_blocked'; why: 'backend_changes_off' | 'not_set_up' }
  /** Names on the node wait for a test here, through one of these addresses. */
  | { kind: 'test'; node: SniTransportNode }
  /** Names wait for a test here, but no address of this node is proven yet. */
  | { kind: 'test_needs_address'; node: SniTransportNode }
  /** For every node at once (a name list's page): names wait for a test on these nodes. */
  | { kind: 'test_nodes'; nodes: number }
  /** No protected node hands the names out: on this node's page (here) or behind the port at all. */
  | { kind: 'unprotected'; here: boolean }
  /** Found names the cover site serves, ready to add. */
  | { kind: 'add_suggestions'; count: number }
  /** Names are being checked against the cover site (minutes). */
  | { kind: 'checking'; count: number }
  /** Nothing to do. */
  | { kind: 'done' };

/** This node's place behind the transport (a protected listener), if it has one. */
export function nodeOf(t: SniTransport, nodeUuid: string | null): SniTransportNode | null {
  if (!nodeUuid) return null;
  return t.nodes.find((n) => n.nodeUuid === nodeUuid) ?? null;
}

/**
 * The one next step for a transport as one node's page shows it. A send comes
 * before a test: one test after the send proves everything new at once.
 */
export function namesStep(
  t: SniTransport,
  switches: SniTransportsView['switches'],
  nodeUuid: string | null,
): NamesStep {
  if (!switches.names) return { kind: 'names_off' };
  if (!t.list) return { kind: 'manage' };
  if (!t.list.enabled) return { kind: 'list_off' };
  if (t.send?.phase === 'writing') return { kind: 'sending' };
  const c = t.list.counts;
  if (c.toSend > 0) {
    if (!switches.backendChanges) return { kind: 'send_blocked', why: 'backend_changes_off' };
    if (!switches.backendSetUp) return { kind: 'send_blocked', why: 'not_set_up' };
    return t.send?.phase === 'failed' ? { kind: 'send_again' } : { kind: 'send' };
  }
  const node = nodeOf(t, nodeUuid);
  if (node && node.waitingTest > 0 && t.send?.phase === 'panel_confirmed')
    return node.testable.length > 0 ? { kind: 'test', node } : { kind: 'test_needs_address', node };
  // Every node at once: the test is per node, listed with each one.
  const waiting = t.nodes.filter((n) => n.waitingTest > 0).length;
  if (nodeUuid === null && waiting > 0 && t.send?.phase === 'panel_confirmed')
    return { kind: 'test_nodes', nodes: waiting };
  if (t.list.suggestions > 0) return { kind: 'add_suggestions', count: t.list.suggestions };
  if (c.checking > 0) return { kind: 'checking', count: c.checking };
  // Names reach members only through protected addresses: nothing is "in use" without them.
  if (nodeUuid !== null && !node) return { kind: 'unprotected', here: true };
  if (t.nodes.length === 0) return { kind: 'unprotected', here: false };
  return { kind: 'done' };
}

/** The button for a step, or null when the step is waiting or done. */
export const STEP_BUTTON: Partial<Record<NamesStep['kind'], string>> = {
  manage: 'Manage these names with FCP',
  send: 'Send to the node',
  send_again: 'Send again',
  test: 'Test one name',
  add_suggestions: 'Add suggestions',
};

/** The status line: what this node's members get and what waits, in one line. */
export function namesStatus(t: SniTransport, nodeUuid: string | null): { dot: Dot; text: string } {
  if (!t.list) {
    return {
      dot: 'grey',
      text: t.listed === 0 ? 'No server names yet' : `${plural(t.listed, 'name')} set by hand`,
    };
  }
  const c = t.list.counts;
  const node = nodeOf(t, nodeUuid);
  // No protected node (here, or behind the port): the names are on the port, handed out by none.
  const unprotected = nodeUuid !== null ? !node : t.nodes.length === 0;
  const inUse = node ? node.inUse : c.inUse;
  const waiting = node ? node.waitingTest : c.waitingTest;
  const parts = [
    unprotected ? `${plural(t.listed, 'name')} on the port` : `${plural(inUse, 'name')} in use`,
  ];
  if (waiting) parts.push(`${waiting} waiting for a test`);
  if (c.toSend) parts.push(`${c.toSend} to send`);
  if (c.checking) parts.push(`${c.checking} being checked`);
  if (c.failing) parts.push(`${c.failing} failing`);
  if (t.list.suggestions) parts.push(plural(t.list.suggestions, 'suggestion'));
  const dot: Dot = unprotected
    ? 'grey'
    : !t.list.enabled || inUse === 0
      ? inUse === 0 && c.checking + c.toSend + waiting > 0
        ? 'amber'
        : 'grey'
      : c.failing > 0 || waiting + c.toSend > 0
        ? 'amber'
        : 'green';
  return { dot, text: parts.join(' · ') };
}

/** One node behind a port, on the name list's page. */
export function nodeLineWords(n: SniTransportNode): { dot: Dot; text: string } {
  const parts = [`${plural(n.inUse, 'name')} in use`];
  if (n.waitingTest)
    parts.push(
      n.testable.length > 0
        ? `${n.waitingTest} waiting for a test`
        : `${n.waitingTest} waiting for a test: try one of its addresses first`,
    );
  const auto = n.waitingTest > 0 && n.autoTest ? AUTO_SHORT[n.autoTest.state] : null;
  if (auto) parts.push(auto);
  return {
    dot: n.waitingTest > 0 ? 'amber' : n.inUse > 0 ? 'green' : 'grey',
    text: parts.join(' · '),
  };
}

/** The sentence under the status line: what holds the next step, or what it does. */
export function stepWords(step: NamesStep, t: SniTransport): string {
  const nodes = t.profileNodes.length;
  const shared =
    nodes > 1 ? ` The ${nodes} nodes on the profile ${t.profileName} share these names.` : '';
  switch (step.kind) {
    case 'names_off':
      return 'Server names are off, so FCP does not manage these names.';
    case 'manage':
      return `Its names are set by hand. FCP can check each one against the cover site, suggest more that site serves, and get them to members.${shared}`;
    case 'list_off':
      return 'Its name list is off, so nothing new is sent. Members keep the names they have.';
    case 'sending':
      return 'Sending the names to the backend. The node restarts Xray once to take them.';
    case 'send':
      return `${plural(t.list?.counts.toSend ?? 0, 'checked name')} ${(t.list?.counts.toSend ?? 0) === 1 ? 'is' : 'are'} not on the node yet.${shared}`;
    case 'send_again':
      return 'The last send did not go through. See Servers, Recent changes, then send again.';
    case 'send_blocked':
      return step.why === 'backend_changes_off'
        ? 'Changes to the backend are off, so these names cannot reach the node.'
        : 'This backend is not set up yet, so these names cannot reach the node.';
    case 'test':
      return 'The node has the new names. Members get them once one test proves the node accepts them.';
    case 'test_nodes':
      return `The new names are on the node. Members get them once a test proves the node accepts them: test one on ${step.nodes === 1 ? 'the node' : `each of the ${step.nodes} nodes`} below.`;
    case 'unprotected':
      return step.here
        ? "This node is not protected, so FCP hands its members none of these names: they get the one name on each of the node's own addresses. Protect it to hand them out."
        : 'No node behind this port is protected, so FCP hands these names to no member yet: members get names only through protected addresses.';
    case 'test_needs_address':
      return 'The node has the new names, but none of its addresses has been tried yet. Try one on its Edges first: a name is tested through an address that already works.';
    case 'add_suggestions':
      return `FCP found ${plural(step.count, 'more name')} the cover site serves.`;
    case 'checking':
      return `Checking ${plural(step.count, 'name')} against the cover site. This takes a few minutes.`;
    case 'done':
      return t.list
        ? 'Every name this list can use is in use.'
        : 'This port lists no names to manage.';
  }
}

/** What managing a port's names did, in one sentence. */
export function managedWords(done: SniManaged): string {
  const taken = done.imported.added;
  const parts = [
    taken > 0
      ? `FCP manages these names now: ${plural(taken, 'name')} taken in, each checked against the cover site first.`
      : 'FCP manages these names now.',
  ];
  // An existing list already holds the port's names: they are in it, not left out.
  const already = done.imported.lines.filter((l) => l.verdict === 'duplicate').length;
  if (already)
    parts.push(`${plural(already, 'name')} ${already === 1 ? 'was' : 'were'} already in the list.`);
  const left = leftOutWords({
    ...done.imported,
    lines: done.imported.lines.filter((l) => l.verdict !== 'duplicate'),
  }).trim();
  if (left) parts.push(left);
  if (done.cert?.ok)
    parts.push(
      `The cover site's certificate lists ${plural(done.cert.listed, 'name')}: new ones show up as suggestions once checked.`,
    );
  return parts.join(' ');
}

/** What "Send to the node" does, read from the plan before the write. */
export function sendPlanWords(p: SniRolloutPlan, t: SniTransport): string[] {
  if (!p.changed) return ['The backend already lists exactly these names. Nothing to send.'];
  const out: string[] = [];
  if (p.added.length) out.push(`${plural(p.added.length, 'name')} will be added.`);
  if (p.removed.length)
    out.push(
      `${plural(p.removed.length, 'name')} will be removed. No member is given ${p.removed.length === 1 ? 'it' : 'any of them'} any more.`,
    );
  if (p.overflow)
    out.push(`${plural(p.overflow, 'checked name')} will wait: the port's list is full for now.`);
  const nodes = t.profileNodes.length;
  out.push(
    nodes > 1
      ? `Every node on the profile ${t.profileName} (${nodes} nodes) restarts Xray once. People connected there reconnect within a few seconds.`
      : 'The node restarts Xray once. People connected there reconnect within a few seconds.',
  );
  if (p.added.length)
    out.push(
      p.witness
        ? 'Members get the new names once a test on the node proves it accepts them. One test proves all of them.'
        : 'Members get the new names once a test on the node proves it accepts them. Each has been on this port before, so each needs its own test.',
    );
  const checking = t.list?.counts.checking ?? 0;
  if (checking)
    out.push(
      `${plural(checking, 'name')} still being checked ${checking === 1 ? 'waits' : 'wait'} for the next send.`,
    );
  return out;
}

/**
 * Which name a test on a node presents: the send's witness while it still
 * waits there (one test of it proves the whole send), else one of the names
 * still waiting there (each proves only itself, so the operator may pick).
 */
export function testNameChoice(
  send: Pick<NonNullable<SniTransport['send']>, 'witness'>,
  node: Pick<SniTransportNode, 'pending'>,
): { kind: 'witness' } | { kind: 'pick'; names: string[] } {
  if (send.witness && node.pending.includes(send.witness)) return { kind: 'witness' };
  return { kind: 'pick', names: [...node.pending] };
}

// --- FCP's own test of a send (docs/edges.md "FCP's own test of a send") ---------------------------

/** The node's line on the name list's page, in a few words. */
const AUTO_SHORT: Partial<Record<SniAutoTest['state'], string>> = {
  testing: 'FCP is testing one now',
  failed: "FCP's test did not pass",
  could_not_check: 'FCP could not test it',
  stopped: 'FCP stopped testing: test one yourself',
};

/** Why FCP set a test aside (`check.code` of a voided receipt). */
const VOID_WORDS: Record<string, string> = {
  'edge.sni.binding_changed': 'the address changed while it ran',
  'edge.sni.profile_moved': 'the profile changed on the backend',
  'edge.sni.superseded': 'a newer send replaced this one',
  'edge.sni.receipt_expired': 'it ran too long',
  already_proven: 'a test by hand proved the names first',
  switched_off: 'testing by FCP was switched off while it ran',
  list_off: 'its name list was switched off while it ran',
};

/** The clients that did not get in with the name: `sing-box: Refused by REALITY; Xray: Timed out`. */
function refusedWords(t: SniAutoTest): string {
  return t.engines
    .filter((e) => e.code !== 'ok')
    .map(
      (e) =>
        `${CLIENT_CHECK_ENGINE_LABELS[e.engine]}: ${(CLIENT_CHECK_COPY as Record<string, { label: string }>)[e.code]?.label ?? e.code}`,
    )
    .join('; ');
}

/** Why a test learned nothing, in a few words. */
function couldNotWords(t: SniAutoTest): string {
  if (t.verdict === 'node_unreachable') return 'no client got through with any name';
  if (t.code === 'lapsed') return 'the test did not finish';
  const code = (t.code ?? '').split(':')[0]!;
  const copy = (CLIENT_CHECK_COPY as Record<string, { label: string }>)[code];
  return copy ? copy.label.toLowerCase() : 'it could not run';
}

const AGAIN = 'It tries again in about 10 minutes. You can test one now.';

/**
 * The line about FCP's own test under a node's "Test one name" step, or null
 * when testing by FCP is off. A person's "Test one name" stays the button
 * whatever FCP's test says.
 */
export function autoTestWords(
  step: NamesStep,
  service: SniTransportsView['switches']['autoTest'],
): string | null {
  if (service === 'off') return null;
  if (step.kind === 'test_needs_address')
    return 'FCP tests names by itself only through an address that already works, so its test waits for one too.';
  if (step.kind !== 'test') return null;
  const t = step.node.autoTest;
  if (t?.state === 'testing')
    return `FCP is testing ${t.sni} on this node now with its own clients.`;
  if (service === 'not_configured')
    return "Testing by FCP is on, but FCP's client check is not set up here, so it tests nothing.";
  if (service === 'unhealthy')
    return "Testing by FCP is on, but FCP's client check is not answering, so it is not testing now.";
  if (!t) return 'FCP tests one name here by itself within a few minutes. You can test one now.';
  switch (t.state) {
    case 'passed':
      return `FCP's test proved ${t.sni}. It tests the next name shortly.`;
    case 'failed':
      return t.verdict === 'egress_mismatch'
        ? `FCP's test with ${t.sni} came out of another node, not this one. Nothing changed for members. ${AGAIN}`
        : `FCP's test did not pass: the node did not accept ${t.sni}${refusedWords(t) ? ` (${refusedWords(t)})` : ''}. Nothing changed for members. ${AGAIN}`;
    case 'could_not_check':
      return `FCP could not test a name here: ${couldNotWords(t)}. ${AGAIN}`;
    case 'voided':
      return `FCP set its last test aside: ${VOID_WORDS[t.code ?? ''] ?? 'something it was bound to changed'}. ${AGAIN}`;
    case 'stopped':
      return `FCP's test did not pass ${plural(t.failures, 'time')}, so it stopped trying for this send. Test one name yourself.`;
  }
}

/** After "It connected". */
export function provenWords(activated: number, nodeName: string): string {
  return activated === 0
    ? `Recorded. ${nodeName} had nothing new to hand out.`
    : `${plural(activated, 'name')} ${activated === 1 ? 'is' : 'are'} now given to members on ${nodeName}.`;
}

/** After "Look for more names": the cover site's certificate, and certificate logs. */
export function lookedWords(
  cert: Extract<SniHuntCertRead, { ok: true }>,
  ct: { queued: number } | null,
): string {
  const parts = [
    `The cover site's certificate lists ${plural(cert.listed, 'name')}, ${cert.added} new.`,
  ];
  if (ct)
    parts.push(
      ct.queued > 0
        ? 'Certificate logs are being read too.'
        : 'Certificate logs were read in full this week.',
    );
  parts.push('New names show up as suggestions once checked.');
  return parts.join(' ');
}

// --- the suggestions dialog -----------------------------------------------------------------------

/** What adding suggestions did, in one sentence. */
export function addedWords(r: SniImportResult, onPort = true): string {
  // Only a list a port uses has a node to send to.
  const next = onPort
    ? 'Each is checked against the cover site, then goes to the node with the next send.'
    : 'Each is checked against the cover site first.';
  return `${plural(r.added, 'name')} added. ${next}${leftOutWords(r)}`;
}

/** Why lines of an import were not added, each reason with its count (empty when none was). */
export function leftOutWords(r: SniImportResult): string {
  const count = (v: SniImportResult['lines'][number]['verdict']) =>
    r.lines.filter((l) => l.verdict === v).length;
  const why = [
    [count('duplicate'), 'already listed'],
    [count('in_other_family'), 'in another list'],
    [count('burned'), 'burned'],
    [count('invalid'), 'not a host name'],
  ]
    .filter(([n]) => (n as number) > 0)
    .map(([n, what]) => `${n} ${what}`);
  return why.length > 0 ? ` Left out: ${why.join(', ')}.` : '';
}

/**
 * Why a suggestion is worth adding, in one line: only what was measured or is
 * known, never the score itself (that stays under Details).
 */
export function suggestionReason(c: SniCandidateRow): string {
  const parts: string[] = [];
  if (c.rank !== null && c.rank <= 100_000) parts.push('a popular site');
  else if (c.rank !== null) parts.push('a known site');
  if (c.timing) parts.push(`${c.timing.connectMs} ms from the node`);
  const ok = c.countries.filter((r) => r.reading === 'ok').map((r) => r.cc);
  const bad = c.countries.filter((r) => r.reading === 'interference').map((r) => r.cc);
  const ooniBad = (c.ooni?.exact ?? [])
    .filter((o) => o.status === 'blocked' || o.status === 'likely_blocked')
    .map((o) => o.cc);
  if (bad.length + ooniBad.length > 0)
    parts.push(`may be blocked in ${[...new Set([...bad, ...ooniBad])].join(', ')}`);
  else if (ok.length > 0) parts.push(`works in ${ok.join(', ')}`);
  if (c.sources.includes('cert')) parts.push("on the cover site's certificate");
  else if (c.sources.includes('ct')) parts.push('in certificate logs');
  if (parts.length === 0) return 'The cover site serves it.';
  const s = parts.join(', ');
  return `${s[0]!.toUpperCase()}${s.slice(1)}.`;
}

/** Suggestions to offer: usable ones (the overview's rule), best first as the server sorts them. */
export const offerable = (rows: readonly SniCandidateRow[]) => rows.filter(usableCandidate);

// --- Servers home "Needs you" ---------------------------------------------------------------------

export interface NamesAttention {
  key: string;
  text: string;
  /** The node page it leads to, when it concerns one node. */
  nodeUuid?: string;
  /** The name list page it leads to. */
  family?: string;
}

/** What a backend's transports need from an operator, one line each. */
export function namesNeedsYou(view: SniTransportsView): NamesAttention[] {
  const out: NamesAttention[] = [];
  if (!view.switches.names) return out;
  for (const t of view.transports) {
    if (!t.list || !t.list.enabled) continue;
    const c = t.list.counts;
    const first = t.nodes[0]?.nodeUuid ?? t.profileNodes[0]?.nodeUuid ?? undefined;
    if (c.toSend > 0 && (!view.switches.backendChanges || !view.switches.backendSetUp))
      out.push({
        key: `names-blocked:${t.transportUuid}`,
        text: `${t.tag}: ${plural(c.toSend, 'checked name')} cannot reach the nodes: ${
          view.switches.backendChanges
            ? 'this backend is not set up yet'
            : 'changes to the backend are off'
        }.`,
        ...(first ? { nodeUuid: first } : {}),
      });
    else if (c.toSend > 0 && t.send?.phase !== 'writing')
      out.push({
        key: `names-send:${t.transportUuid}`,
        text: `${t.tag}: ${plural(c.toSend, 'checked name')} to send to the node.`,
        ...(first ? { nodeUuid: first } : {}),
      });
    if (t.send?.phase === 'panel_confirmed')
      for (const n of t.nodes)
        if (n.waitingTest > 0)
          out.push({
            key: `names-test:${t.transportUuid}:${n.relaySlug}`,
            text: `${t.tag} on ${n.nodeName}: ${plural(n.waitingTest, 'name')} ${n.waitingTest === 1 ? 'waits' : 'wait'} for a test.${n.autoTest?.state === 'testing' ? ' FCP is testing one now.' : ''}`,
            ...(n.nodeUuid ? { nodeUuid: n.nodeUuid } : {}),
          });
    if (t.list.suggestions > 0)
      out.push({
        key: `names-suggest:${t.transportUuid}`,
        text: `${t.tag}: ${plural(t.list.suggestions, 'suggested name')} to add.`,
        ...(first ? { nodeUuid: first } : {}),
      });
    if (c.failing > 0)
      out.push({
        key: `names-failing:${t.transportUuid}`,
        text: `${t.tag}: ${plural(c.failing, 'name')} no longer served by the cover site.`,
        family: t.list.slug,
      });
  }
  return out;
}
