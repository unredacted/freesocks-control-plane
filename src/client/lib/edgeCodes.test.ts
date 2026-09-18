import { describe, expect, test } from 'vitest';
import {
  ATTENTION_ACTIONS,
  ATTENTION_KINDS,
  DELIVERY_UNAVAILABLE_CODES,
  LAYER_EXCLUSION_CODES,
  PREFLIGHT_BLOCKER_CODES,
  PREFLIGHT_WARNING_CODES,
  SETUP_BLOCKER_CODES,
  SETUP_STEP_IDS,
  SETUP_STEP_STATUSES,
} from '../../shared/contracts/edgeCodes';
import {
  ATTENTION_ACTION_LABELS,
  EDGE_CODE_COPY,
  EDGE_REFUSAL_COPY,
  EDGE_STATUS_LABELS,
  ROTATION_PHASE_LABELS,
  SETUP_STATUS_LABELS,
  SETUP_STEP_TITLES,
  auditActionLabel,
  codeExplain,
  codeFix,
  codeLabel,
  edgeStatusLabel,
  humanizeCode,
  isTerminalPhase,
  phaseLabel,
} from './edgeCodes';

const EVERY_CODE = [
  ...SETUP_BLOCKER_CODES,
  ...PREFLIGHT_BLOCKER_CODES,
  ...PREFLIGHT_WARNING_CODES,
  ...ATTENTION_KINDS,
  ...LAYER_EXCLUSION_CODES,
  ...DELIVERY_UNAVAILABLE_CODES,
];

const EM_DASH = '—';

describe('EDGE_CODE_COPY', () => {
  test('every tuple literal has a label and an explanation', () => {
    const missing = EVERY_CODE.filter((c) => {
      const e = EDGE_CODE_COPY[c];
      return !e || !e.label.trim() || !e.explain.trim();
    });
    expect(missing).toEqual([]);
  });

  test('no copy contains an em-dash or an API path', () => {
    const offenders: string[] = [];
    for (const [code, e] of Object.entries(EDGE_CODE_COPY)) {
      for (const text of [e.label, e.explain, e.fix ?? '']) {
        if (text.includes(EM_DASH) || text.includes('/api/')) offenders.push(`${code}: ${text}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  test('labels are short and explanations are sentences', () => {
    for (const e of Object.values(EDGE_CODE_COPY)) {
      expect(e.label.split(/\s+/).length).toBeLessThanOrEqual(6);
      expect(e.explain.trim().endsWith('.')).toBe(true);
      if (e.fix) expect(e.fix.trim().endsWith('.')).toBe(true);
    }
  });
});

describe('EDGE_REFUSAL_COPY', () => {
  const REFUSALS = [
    'host_adopt_required',
    'host_adopt_mismatch',
    'listener_in_use',
    'needs_rotation',
    'origin_address_locked',
    'match_rule_overlap',
    'node_already_bound',
    'server_already_bound',
    'throttled',
  ];

  test('every refusal the pages meet is worded, and is part of the shared table', () => {
    for (const code of REFUSALS) {
      expect(EDGE_REFUSAL_COPY[code]?.label.trim()).toBeTruthy();
      expect(EDGE_REFUSAL_COPY[code]?.explain.trim()).toBeTruthy();
      expect(EDGE_CODE_COPY[code]).toBe(EDGE_REFUSAL_COPY[code]);
    }
    expect(codeLabel('needs_rotation')).toBe('Needs a rotation');
    expect(codeFix('host_adopt_required')).toContain('Adopt a Host');
  });

  test('no refusal copy contains an em-dash or an API path, and every part is a sentence', () => {
    const offenders: string[] = [];
    for (const [code, e] of Object.entries(EDGE_REFUSAL_COPY)) {
      for (const text of [e.label, e.explain, e.fix ?? '']) {
        if (text.includes(EM_DASH) || text.includes('/api/')) offenders.push(`${code}: ${text}`);
      }
      expect(e.explain.trim().endsWith('.')).toBe(true);
      if (e.fix) expect(e.fix.trim().endsWith('.')).toBe(true);
    }
    expect(offenders).toEqual([]);
  });
});

describe('code helpers', () => {
  test('known codes resolve through the table', () => {
    expect(codeLabel('pool_empty')).toBe('Pool empty');
    expect(codeExplain('pool_empty')).toMatch(/published/);
    expect(codeFix('pool_empty')).toBe('Publish an edge.');
    expect(codeFix('not_found')).toBeUndefined();
  });

  test('unknown codes are humanised, never returned bare', () => {
    expect(codeLabel('some_new_server_code')).toBe('Some new server code');
    expect(codeLabel('edge.needs_rotation')).toBe('Edge needs rotation');
    expect(codeExplain('some_new_server_code')).toBe('The server reported Some new server code.');
    expect(codeFix('some_new_server_code')).toBeUndefined();
    expect(codeLabel(null)).toBe('');
    expect(codeLabel(undefined)).toBe('');
  });

  test('humanizeCode keeps the acronyms operators read', () => {
    expect(humanizeCode('l7_auto_select_blocked')).toBe('L7 auto select blocked');
    expect(humanizeCode('dns_zone_missing')).toBe('DNS zone missing');
    expect(humanizeCode('origin-tls-mismatch')).toBe('Origin TLS mismatch');
    expect(humanizeCode('')).toBe('');
  });
});

describe('phase, status and step maps', () => {
  test('every documented rotation phase has a label and a terminal verdict', () => {
    const phases = [
      'select',
      'provisioning',
      'verifying',
      'publishing',
      'host_flipping',
      'confirming',
      'finalizing',
      'rolling_back',
      'done',
      'failed',
      'rolled_back',
      'quarantined',
      'cancelled',
    ];
    for (const p of phases) expect(ROTATION_PHASE_LABELS[p]).toBeTruthy();
    expect(phases.filter(isTerminalPhase)).toEqual([
      'done',
      'failed',
      'rolled_back',
      'quarantined',
      'cancelled',
    ]);
    expect(phaseLabel('host_flipping')).toBe('Flipping Hosts');
    expect(phaseLabel('brand_new_phase')).toBe('Brand new phase');
  });

  test('every live edge status has a label', () => {
    const statuses = [
      'planning',
      'provisioning',
      'verifying',
      'standby',
      'active',
      'draining',
      'destroying',
      'destroyed',
      'failed',
      'cancelled',
      'quarantined',
      'needs_operator',
    ];
    for (const s of statuses) expect(EDGE_STATUS_LABELS[s]).toBeTruthy();
    expect(edgeStatusLabel('needs_operator')).toBe('Needs operator');
  });

  test('setup steps, statuses and attention actions are fully labelled', () => {
    for (const id of SETUP_STEP_IDS) expect(SETUP_STEP_TITLES[id]).toBeTruthy();
    for (const s of SETUP_STEP_STATUSES) expect(SETUP_STATUS_LABELS[s]).toBeTruthy();
    for (const a of ATTENTION_ACTIONS) expect(ATTENTION_ACTION_LABELS[a]).toBeTruthy();
  });

  test('audit actions map to words with a fallback', () => {
    expect(auditActionLabel('edge.published')).toBe('Edge published');
    expect(auditActionLabel('admin.edge.something_odd')).toBe('Edge something odd');
    expect(auditActionLabel('probe.new_thing')).toBe('Probe new thing');
  });
});
