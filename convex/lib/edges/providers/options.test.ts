import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  builtTemplateHash,
  deepMerge,
  defaultsOf,
  describeFields,
  getPath,
  parseOptionValues,
  pickKeys,
  setKeys,
  setPath,
  splitChoices,
  wireBody,
  type OptionField,
} from './options';
import { canonicalJson } from './template';

const schema = z.object({
  size: z.enum(['s', 'm', 'l']).default('s'),
  timeoutMs: z.number().int().min(1000).max(60_000).default(5000),
  check: z
    .object({
      delay: z.number().int().min(1).max(600).default(10),
      retries: z.number().int().min(1).max(10).optional(),
    })
    .default({ delay: 10 }),
  tags: z.record(z.string(), z.string()).default({}),
  cap: z.number().int().min(0).max(500_000).optional(),
});

const fields: OptionField[] = [
  { key: 'size', label: 'Size', type: 'select', wire: { resource: 'lb', field: 'flavor' } },
  {
    key: 'timeoutMs',
    label: 'Timeout',
    type: 'number',
    wire: { resource: 'listener', field: 'timeout', manual: true },
  },
  {
    key: 'check.delay',
    label: 'Delay',
    type: 'number',
    wire: { resource: 'pool', field: 'hm.delay' },
  },
  { key: 'check.retries', label: 'Retries', type: 'number', default: 3 },
  { key: 'tags', label: 'Tags', type: 'key-value' },
  {
    key: 'cap',
    label: 'Cap',
    type: 'number',
    default: 1000,
    wire: { resource: 'member', field: 'max_sessions' },
  },
  { key: 'authority', label: 'Authority', type: 'select', kind: 'certificate' },
];

describe('describeFields', () => {
  it('completes declarations from the schema without overriding what they say', () => {
    const d = describeFields(schema, fields);
    const by = (k: string) => d.find((f) => f.key === k)!;
    expect(by('size').default).toBe('s');
    expect(by('size').options?.map((o) => o.value)).toEqual(['s', 'm', 'l']);
    expect(by('timeoutMs')).toMatchObject({ min: 1000, max: 60_000, default: 5000 });
    expect(by('check.delay')).toMatchObject({ min: 1, max: 600, default: 10 });
    // An optional field's default comes from the declaration (the parse never materialises it).
    expect(by('check.retries')).toMatchObject({ min: 1, max: 10, default: 3 });
    expect(by('cap').default).toBe(1000);
    expect(by('authority').default).toBeUndefined();
  });
});

describe('paths and merging', () => {
  it('sets and reads dotted paths immutably', () => {
    const a = { check: { delay: 10 } };
    const b = setPath(a, 'check.retries', 4);
    expect(a).toEqual({ check: { delay: 10 } });
    expect(getPath(b, 'check.retries')).toBe(4);
    expect(getPath(b, 'missing.deep')).toBeUndefined();
  });

  it('merges objects key by key and replaces everything else', () => {
    expect(
      deepMerge({ a: 1, n: { x: 1, y: 2 }, l: [1] }, { n: { y: 3 }, l: [2], u: undefined }),
    ).toEqual({ a: 1, n: { x: 1, y: 3 }, l: [2] });
  });

  it('lists the keys a value object sets, stopping at map-valued fields', () => {
    expect(setKeys({ size: 'm', check: { delay: 5 }, tags: { a: 'b' } }, fields).sort()).toEqual([
      'check.delay',
      'size',
      'tags',
    ]);
    expect(
      pickKeys({ size: 'm', check: { delay: 5, retries: 2 } }, ['check.delay', 'nope']),
    ).toEqual({ check: { delay: 5 } });
  });

  it('collects the defaults of every field', () => {
    expect(defaultsOf(describeFields(schema, fields))).toEqual({
      size: 's',
      timeoutMs: 5000,
      check: { delay: 10, retries: 3 },
      tags: {},
      cap: 1000,
    });
  });
});

describe('wireBody', () => {
  it('writes each bound value of one resource at its wire path, scaled, skipping manual ones', () => {
    const v = { size: 'l', timeoutMs: 9000, check: { delay: 7 }, cap: 2 };
    expect(wireBody(fields, 'lb', v)).toEqual({ flavor: 'l' });
    expect(wireBody(fields, 'listener', v)).toEqual({});
    expect(wireBody(fields, 'pool', v)).toEqual({ hm: { delay: 7 } });
    expect(wireBody(fields, 'member', v)).toEqual({ max_sessions: 2 });
    expect(
      wireBody(
        [
          {
            key: 's',
            label: 'S',
            type: 'number',
            wire: { resource: 'x', field: 'ms', scale: 1000 },
          },
        ],
        'x',
        { s: 3 },
      ),
    ).toEqual({ ms: 3000 });
  });

  it('sends nothing for an unset value, so the provider default applies', () => {
    expect(wireBody(fields, 'member', {})).toEqual({});
  });
});

describe('builtTemplateHash', () => {
  it('is the template hash itself when the pick chose nothing', () => {
    expect(builtTemplateHash({ size: 's' }, 'base', undefined)).toBe('base');
    expect(builtTemplateHash({ size: 's' }, 'base', {})).toBe('base');
  });

  it('hashes the template with the choices laid over it otherwise', () => {
    const a = builtTemplateHash({ size: 's', check: { delay: 10 } }, 'base', { size: 'm' });
    const b = builtTemplateHash({ check: { delay: 10 }, size: 's' }, 'other', { size: 'm' });
    expect(a).not.toBe('base');
    expect(a).toBe(b);
    expect(a).not.toBe(builtTemplateHash({ size: 's' }, 'base', { size: 'l' }));
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
});

describe('stored choices', () => {
  it('reads a stored blob back, anything unusable being empty', () => {
    expect(parseOptionValues('{"size":"m"}')).toEqual({ size: 'm' });
    expect(parseOptionValues('[1]')).toEqual({});
    expect(parseOptionValues('nope')).toEqual({});
    expect(parseOptionValues(undefined)).toEqual({});
  });

  it('splits a pick into its tuning and certificate parts', () => {
    expect(splitChoices(fields, { size: 'm', authority: 'x', check: { delay: 3 } })).toEqual({
      tuning: { size: 'm', check: { delay: 3 } },
      certificate: { authority: 'x' },
    });
  });
});
