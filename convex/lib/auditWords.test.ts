import { describe, expect, test } from 'vitest';
import {
  auditActionLabel,
  hasAuditActionWords,
  plainAuditActionLabel,
} from '../../src/client/lib/edgeCodes';
import { AUDIT_PAYLOAD_ALLOWLIST } from './audit';

/** The actions the edge activity lists show (Overview, a node's Activity, Timeline). */
const EDGE_ACTIONS = Object.keys(AUDIT_PAYLOAD_ALLOWLIST).filter((a) =>
  /^(edge|admin\.edge|relay|probe)\./.test(a),
);

describe('audit action words', () => {
  test('every edge, origin and probe action the server audits has its own words', () => {
    expect(EDGE_ACTIONS.length).toBeGreaterThan(100);
    expect(EDGE_ACTIONS.filter((a) => !hasAuditActionWords(a))).toEqual([]);
  });

  test('the plain words never show a code or an old word', () => {
    for (const a of EDGE_ACTIONS) {
      const plain = plainAuditActionLabel(a);
      expect(plain, a).not.toMatch(/_|\brelay\b|\borigin\b/i);
      expect(auditActionLabel(a), a).not.toMatch(/_/);
    }
  });

  test('the per-country actions read as what happened', () => {
    expect(plainAuditActionLabel('edge.relay.pick_audience')).toBe(
      'Location kept for some countries',
    );
    expect(plainAuditActionLabel('edge.relay.own_pool')).toBe("A country's own addresses switched");
  });
});
