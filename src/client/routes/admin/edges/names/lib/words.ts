/**
 * Wording and small decisions for Admin -> Edges -> Server names (pure;
 * unit-tested). A name goes through three separate facts and the page never
 * blurs them: the target site serves it (checked), a node accepts it (proven
 * by a test link), and it works from a country (the operator's judgement).
 */
import type {
  SniFamilySummary,
  SniImportResult,
  SniNameRow,
  SniRolloutPlan,
  SniRolloutStatus,
} from '../../../../../../shared/contracts/sni';

export type Dot = 'green' | 'amber' | 'red' | 'grey';

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** One line under a family's name in the list. */
export function familyLine(f: SniFamilySummary): string {
  const c = f.counts;
  const parts = [`${plural(c.ready, 'name')} ready`];
  if (c.waiting) parts.push(`${c.waiting} waiting for a check`);
  if (c.failing) parts.push(`${c.failing} failing`);
  if (c.suspended) parts.push(`${c.suspended} suspended`);
  parts.push(
    f.bindings === 0 ? 'not used by any inbound' : `used by ${plural(f.bindings, 'inbound')}`,
  );
  return parts.join(' · ');
}

export function familyDot(f: SniFamilySummary): Dot {
  if (!f.enabled) return 'grey';
  if (f.counts.ready === 0) return f.counts.total === 0 ? 'grey' : 'red';
  return f.counts.failing + f.counts.suspended > 0 ? 'amber' : 'green';
}

/** Why a name failed its check (`judgeHandshake` in convex/lib/edges/sni/family.ts). */
export const CHECK_WORDS: Record<string, string> = {
  q_timeout: 'The target site did not answer in time.',
  q_private_target: 'The target site resolves to a private address.',
  q_resolve: 'The target site could not be resolved.',
  q_cert: 'The target site has no valid certificate for this name.',
  q_unreachable: 'The target site could not be reached.',
  q_tls12: 'The target site does not offer TLS 1.3 for this name.',
  q_no_h2: 'The target site does not offer HTTP/2 for this name.',
};

/** One name's state in words. */
export function nameWords(n: SniNameRow): { dot: Dot; sentence: string } {
  if (n.status === 'burned')
    return { dot: 'red', sentence: 'Burned. It is never used again, here or in any other family.' };
  if (n.status === 'retired') return { dot: 'grey', sentence: 'Retired by an operator.' };
  if (n.status === 'suspended')
    return {
      dot: 'amber',
      sentence:
        `Suspended: it kept failing its check. ${(n.code && CHECK_WORDS[n.code]) ?? ''}`.trim(),
    };
  if (n.qualification === 'pending')
    return { dot: 'grey', sentence: 'Waiting for its first check against the target site.' };
  if (n.qualification === 'failed')
    return {
      dot: 'amber',
      sentence: (n.code && CHECK_WORDS[n.code]) ?? 'Its last check against the target site failed.',
    };
  return { dot: 'green', sentence: 'The target site serves this name.' };
}

/** The report hint under a name. It suggests; the operator judges. */
export function suspectWords(countries: readonly string[]): string {
  return `Members in ${countries.join(', ')} report problems with this name more than with the others. It may be blocked there.`;
}

export const NAME_FILTERS = ['all', 'ready', 'problems', 'off'] as const;
export type NameFilter = (typeof NAME_FILTERS)[number];
export const FILTER_LABEL: Record<NameFilter, string> = {
  all: 'All',
  ready: 'Ready',
  problems: 'Problems',
  off: 'Retired or burned',
};
export function matchesFilter(n: SniNameRow, f: NameFilter): boolean {
  const off = n.status === 'retired' || n.status === 'burned';
  if (f === 'all') return true;
  if (f === 'off') return off;
  const ready = n.status === 'active' && n.qualification === 'ok';
  // A suspected name is a problem to look at even though it is still ready.
  if (f === 'problems') return (!ready && !off) || (!off && n.suspectIn.length > 0);
  return ready;
}

/** What an import did, in one sentence per kind of line. */
export function importWords(r: SniImportResult): string[] {
  const count = (v: SniImportResult['lines'][number]['verdict']) =>
    r.lines.filter((l) => l.verdict === v).length;
  const out = [`${plural(r.added, 'name')} added. Each is checked against the target site first.`];
  const dup = count('duplicate');
  if (dup) out.push(`${plural(dup, 'line')} skipped: already in this family, or repeated.`);
  const other = count('in_other_family');
  if (other) out.push(`${plural(other, 'name')} skipped: already in another family.`);
  const burned = count('burned');
  if (burned) out.push(`${plural(burned, 'name')} skipped: burned names are never used again.`);
  const invalid = count('invalid');
  if (invalid) out.push(`${plural(invalid, 'line')} skipped: not a plain host name.`);
  return out;
}

/** What pressing "Write to the panel" would do. */
export function planWords(p: SniRolloutPlan): string[] {
  if (!p.changed) return ['The panel already lists exactly the names this family wants there.'];
  const out: string[] = [];
  if (p.added.length) out.push(`${plural(p.added.length, 'name')} will be added to the inbound.`);
  if (p.removed.length)
    out.push(
      `${plural(p.removed.length, 'name')} will be removed. None of them is still given to members.`,
    );
  if (p.overflow)
    out.push(`${plural(p.overflow, 'ready name')} will wait: the inbound's list is full for now.`);
  if (p.added.length)
    out.push(
      p.witness
        ? 'One test per node will prove all of the new names at once, because one of them has never been on this inbound before.'
        : 'Every new name has been on this inbound before, so each has to be tested by itself on each node.',
    );
  out.push(
    'The panel pushes this to every node on the profile. People connected there are cut off for a few seconds.',
  );
  return out;
}

export function rolloutWords(s: SniRolloutStatus): { dot: Dot; sentence: string } {
  switch (s.phase) {
    case 'writing':
      return { dot: 'amber', sentence: 'Being written to the panel.' };
    case 'failed':
      return { dot: 'red', sentence: 'The write did not go through. See Servers, Recent changes.' };
    case 'superseded':
      return { dot: 'grey', sentence: 'Replaced by a newer write.' };
    case 'panel_confirmed': {
      const pending = s.nodes.reduce((n, x) => n + x.pending, 0);
      if (s.added === 0) return { dot: 'green', sentence: 'On the panel. Nothing new to prove.' };
      return pending === 0
        ? { dot: 'green', sentence: 'On the panel, and every node has proven the new names.' }
        : {
            dot: 'amber',
            sentence:
              'On the panel. Members do not get a new name from a node until that node has proven it with a test link.',
          };
    }
  }
}

export function nodeLine(n: SniRolloutStatus['nodes'][number]): string {
  if (n.pending === 0) return `${plural(n.proven, 'name')} proven`;
  return `${n.proven} proven, ${n.pending} waiting for a test`;
}

/** Refusals of this section, in words. */
const ERROR_WORDS: Record<string, string> = {
  'edge.sni.bad_target': 'The target has to be a public host name and a port.',
  'edge.sni.cap': 'This family is full.',
  'edge.sni.disabled': 'Server name families are turned off. Turn them on first.',
  'edge.sni.family_in_use': 'An inbound still uses this family. Unbind it first.',
  'edge.sni.target_mismatch':
    "The inbound's target site is not this family's target. Every name must be one the target really serves.",
  'edge.sni.binding_changed': 'This inbound changed since the page loaded. Reload and look again.',
  'edge.sni.profile_moved':
    'The profile changed on the panel since this was written. Write the names again before testing.',
  'edge.sni.rollout_not_confirmed': 'The names are not on the panel yet.',
  'edge.sni.receipt_expired': 'That test link has expired. Make a new one.',
  'edge.sni.superseded': 'A newer write replaced this one. Test against the newer one.',
  'edge.sni.country_not_curated':
    'That country is not on the list of countries names are judged for.',
  'servers.manage_disabled': 'Changing panels is turned off under Servers.',
  'servers.handoff_missing': 'The node role has not handed this panel over yet.',
  'servers.op_running': 'Another change to this profile is still running.',
  'servers.op_uncertain':
    'An earlier change to this profile has an unknown outcome. Settle it under Servers.',
  'servers.name_in_use': 'Members are still given one of the names being removed.',
  'edge.panel_op_running': 'A server change is still running on this relay.',
  conflict: 'That already exists, or it is already settled. Reload and look again.',
  not_found: 'That no longer exists. Reload and look again.',
  validation: 'Something in the form is not valid.',
};
export const WORDED_CODES: readonly string[] = Object.keys(ERROR_WORDS);
export function sniErrorWords(code: string | null | undefined): string {
  return (code && ERROR_WORDS[code]) || 'That did not work. Try again in a moment.';
}
