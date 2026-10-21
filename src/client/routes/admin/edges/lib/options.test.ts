import { describe, expect, it } from 'vitest';
import type { EdgeTemplateField } from '../../../../../shared/contracts/edges';
import {
  deepMerge,
  groupsOf,
  kvToText,
  optionSummary,
  overrides,
  pickBase,
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
