/**
 * Timeline helpers (pure).
 *
 * Exports:
 *   subjectOf(row)      the row's subject, inferred from the action prefix when the
 *                       server did not tag it (plain AuditEntry rows)
 *   actorLabel(row)     'System', 'An admin', 'An API token or automation', ...
 */
import type { TimelineRow, TimelineSubject } from './types';

export function subjectOf(row: TimelineRow): TimelineSubject {
  if (row.subject) return row.subject;
  const a = row.action;
  if (a.startsWith('probe.')) return 'probe';
  if (a.startsWith('relay.listener.') || a.startsWith('relay.host.')) return 'listener';
  if (a.startsWith('relay.')) return 'relay';
  if (/^(admin\.)?edge\.(rotat|rolled_back|burn|quarantin|provision|test_provision|cancel)/.test(a))
    return 'rotation';
  if (a.startsWith('edge.') || a.startsWith('admin.edge.')) return 'edge';
  return 'other';
}

const ACTOR_LABELS: Record<TimelineRow['actorType'], string> = {
  system: 'System',
  admin: 'An admin',
  member: 'A member',
  anonymous: 'Anonymous',
  webhook: 'A webhook',
};
export function actorLabel(row: TimelineRow): string {
  return ACTOR_LABELS[row.actorType] ?? 'System';
}
