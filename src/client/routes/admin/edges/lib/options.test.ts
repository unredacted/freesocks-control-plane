import { describe, expect, it } from 'vitest';
import type { EdgeTemplateField } from '../../../../../shared/contracts/edges';
import {
  deepMerge,
  fieldProblem,
  groupsOf,
  kvToText,
  optionProblems,
  optionSummary,
  overrides,
  pickBase,
  problemLine,
  textToKv,
  valueWords,
  visibleFields,
} from './options';

const fields: EdgeTemplateField[] = [
  { key: 'size', label: 'Size', type: 'string', group: 'Load balancer', prominent: true },
  {
    key: 'check.type',
    label: 'Check type',
    type: 'select',
    group: 'Health check',
    default: 'TCP',
    options: [
      { value: 'TCP', label: 'TCP' },
      { value: 'HTTP', label: 'HTTP' },
    ],
  },
  {
    key: 'check.path',
    label: 'Check path',
    type: 'string',
    group: 'Health check',
    when: { key: 'check.type', in: ['HTTP'] },
  },
  { key: 'old', label: 'Old', type: 'number', group: 'Health check', hidden: true },
  { key: 'tags', label: 'Tags', type: 'key-value', group: 'Load balancer' },
  { key: 'cap', label: 'Cap', type: 'number', unit: 's', group: 'Member' },
];

describe('visibleFields', () => {
  it('drops hidden fields and shows a when-field only while its condition holds', () => {
    const keys = (v: Record<string, unknown>, b: Record<string, unknown> = {}) =>
      visibleFields(fields, v, b).map((f) => f.key);
    expect(keys({})).toEqual(['size', 'check.type', 'tags', 'cap']);
    expect(keys({ check: { type: 'HTTP' } })).toContain('check.path');
    // The base (a template) can meet the condition too.
    expect(keys({}, { check: { type: 'HTTP' } })).toContain('check.path');
  });
});

describe('groupsOf', () => {
  it('keeps the order groups first appear in', () => {
    expect(groupsOf(fields).map((g) => g.group)).toEqual([
      'Load balancer',
      'Health check',
      'Member',
    ]);
    expect(groupsOf(fields)[0]!.fields.map((f) => f.key)).toEqual(['size', 'tags']);
  });
});

describe('key/value text', () => {
  it('round-trips objects and pairs', () => {
    expect(kvToText({ a: '1', b: '' })).toBe('a=1\nb=');
    expect(textToKv('a=1\n b = 2 \n\nc', false)).toEqual({ a: '1', b: '2', c: '' });
    expect(kvToText([{ key: 'k', value: 'v' }])).toBe('k=v');
    expect(textToKv('k=v=w', true)).toEqual([{ key: 'k', value: 'v=w' }]);
  });
});

describe('overrides and words', () => {
  it('keeps only what differs from the inherited values', () => {
    expect(
      overrides(
        { size: 'big', check: { type: 'TCP' }, cap: 5 },
        { size: 'small', check: { type: 'TCP' } },
        fields,
      ),
    ).toEqual({ size: 'big', cap: 5 });
  });

  it('says each chosen value in words', () => {
    expect(optionSummary(fields, { check: { type: 'HTTP' }, cap: 30, tags: { a: 'b' } })).toEqual([
      'Check type: HTTP',
      'Tags: 1 label',
      'Cap: 30 s',
    ]);
    expect(valueWords(fields[0]!, undefined)).toBe('not set');
    expect(deepMerge({ a: { b: 1 } }, { a: { c: 2 } })).toEqual({ a: { b: 1, c: 2 } });
  });
});

describe('pickBase', () => {
  it('lays the template, the regional values and the account defaults over the declared ones', () => {
    const base = pickBase(
      { fields, defaults: { size: 's', cap: 1000, authority: 'certainly' } },
      { size: 's' },
      [
        { id: 't1', provider: 'p', accountId: null, isDefault: true, params: { size: 'm' } },
        {
          id: 't2',
          provider: 'p',
          accountId: null,
          isDefault: false,
          params: { size: 'l', cap: 5 },
        },
      ],
      { id: 'a', provider: 'p', defaultTemplateId: null, optionDefaults: { authority: 'other' } },
      { defaultTemplateId: 't2', regionalParams: { size: 'xl' } },
    );
    expect(base).toEqual({ size: 'xl', cap: 5, authority: 'other' });
  });
});

describe('pickBase fallback', () => {
  it('without any default, the earliest unscoped template, as the server picks it', () => {
    const base = pickBase(
      { fields, defaults: { size: 's' } },
      {},
      [
        {
          id: 'b',
          provider: 'p',
          accountId: null,
          isDefault: false,
          params: { size: 'late' },
          createdAt: '2026-10-02T00:00:00.000Z',
        },
        {
          id: 'a',
          provider: 'p',
          accountId: null,
          isDefault: false,
          params: { size: 'early' },
          createdAt: '2026-10-01T00:00:00.000Z',
        },
        { id: 'x', provider: 'p', accountId: 'other', isDefault: true, params: { size: 'theirs' } },
      ],
      { id: 'mine', provider: 'p', defaultTemplateId: null },
      null,
    );
    expect(base.size).toBe('early');
  });
});

describe('option problems beside their field', () => {
  const healthy: EdgeTemplateField = {
    key: 'healthMonitor.maxRetries',
    label: 'Healthy after',
    type: 'number',
    min: 1,
    max: 10,
  };
  it('fieldProblem: the bound in plain words, nothing for an inherited value', () => {
    expect(fieldProblem(healthy, 11)).toBe('at most 10');
    expect(fieldProblem(healthy, 0)).toBe('at least 1');
    expect(fieldProblem(healthy, 5)).toBeNull();
    expect(fieldProblem(healthy, undefined)).toBeNull();
    expect(fieldProblem(healthy, Number.NaN)).toBe('a number');
    expect(fieldProblem({ type: 'string', pattern: '^[a-z]+$' }, 'A1')).toBe(
      'not in the expected form',
    );
    expect(fieldProblem({ type: 'string', pattern: '^[a-z]+$' }, '')).toBeNull();
    expect(fieldProblem({ type: 'string-list', maxItems: 1 }, ['a', 'b'])).toBe('at most 1 entry');
  });
  it('optionProblems: only shown fields with a chosen value, worded as one line each', () => {
    const fields: EdgeTemplateField[] = [
      healthy,
      { key: 'other', label: 'Other', type: 'number', max: 3 },
      { key: 'gated', label: 'Gated', type: 'number', max: 1, when: { key: 'on', in: [true] } },
    ];
    const problems = optionProblems(fields, {
      healthMonitor: { maxRetries: 11 },
      gated: 5,
    });
    expect(problems).toEqual([
      { key: 'healthMonitor.maxRetries', label: 'Healthy after', words: 'at most 10' },
    ]);
    expect(problems.map(problemLine)).toEqual(['Healthy after: at most 10.']);
    for (const line of problems.map(problemLine)) expect(line).not.toMatch(/—|[<>]=?/);
  });
});
