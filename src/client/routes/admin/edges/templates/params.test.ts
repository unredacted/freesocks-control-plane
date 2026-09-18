import { describe, expect, it } from 'vitest';
import {
  changedKeys,
  deepEqual,
  differsFromDefault,
  effectiveTemplate,
  formatParams,
  getPath,
  issueInWords,
  listToText,
  numberFromInput,
  parseParamsJson,
  qualificationState,
  resetField,
  setPath,
  textToList,
  unsetPath,
} from './params';

const defaults = { plan: 'small', healthCheck: { interval: 5, fall: 3 }, tags: [] as string[] };

describe('paths', () => {
  it('reads and writes dotted keys without mutating', () => {
    const next = setPath(defaults, 'healthCheck.interval', 9);
    expect(getPath(next, 'healthCheck.interval')).toBe(9);
    expect(getPath(next, 'healthCheck.fall')).toBe(3);
    expect(defaults.healthCheck.interval).toBe(5);
    expect(getPath(next, 'nope.deeper')).toBeUndefined();
  });
  it('creates missing parents and removes keys', () => {
    expect(setPath({}, 'a.b', 1)).toEqual({ a: { b: 1 } });
    expect(unsetPath({ a: { b: 1, c: 2 } }, 'a.b')).toEqual({ a: { c: 2 } });
  });
});

describe('diff against defaults', () => {
  it('ignores key order and absent values', () => {
    expect(deepEqual({ a: 1, b: [1, 2] }, { b: [1, 2], a: 1 })).toBe(true);
    expect(differsFromDefault({}, defaults, 'plan')).toBe(false);
    expect(differsFromDefault({ plan: 'large' }, defaults, 'plan')).toBe(true);
  });
  it('lists changed descriptor keys and resets one', () => {
    const p = { plan: 'large', healthCheck: { interval: 5, fall: 4 } };
    const fields = [{ key: 'plan' }, { key: 'healthCheck.interval' }, { key: 'healthCheck.fall' }];
    expect(changedKeys(p, defaults, fields)).toEqual(['plan', 'healthCheck.fall']);
    expect(changedKeys(resetField(p, defaults, 'plan'), defaults, fields)).toEqual([
      'healthCheck.fall',
    ]);
    expect(resetField({ extra: 1 }, defaults, 'extra')).toEqual({});
  });
});

describe('form <-> JSON', () => {
  it('round-trips through the JSON text', () => {
    const parsed = parseParamsJson(formatParams(defaults));
    expect(parsed).toEqual({ ok: true, params: defaults });
  });
  it('refuses broken JSON and non-objects in words', () => {
    expect(parseParamsJson('{')).toMatchObject({ ok: false });
    expect(parseParamsJson('[1]')).toMatchObject({ ok: false });
    expect(parseParamsJson('  ')).toEqual({ ok: true, params: {} });
  });
  it('maps lists and numbers', () => {
    expect(textToList('a.example, b.example\n\n c.example')).toEqual([
      'a.example',
      'b.example',
      'c.example',
    ]);
    expect(listToText(['a', 'b'])).toBe('a\nb');
    expect(numberFromInput('')).toBeUndefined();
    expect(numberFromInput('12')).toBe(12);
    expect(numberFromInput('x')).toBeNaN();
  });
  it('names the field in a validation issue', () => {
    const fields = [{ key: 'healthCheck.interval', label: 'Health check interval (s)' }];
    expect(issueInWords('healthCheck.interval: Too big', fields)).toBe(
      'Health check interval (s): Too big',
    );
    expect(issueInWords('(root): Expected object', fields)).toBe('Expected object');
  });
});

describe('qualification state', () => {
  const tpl = (id: string, over: Partial<Parameters<typeof effectiveTemplate>[0][number]>) => ({
    id,
    provider: 'upcloud' as const,
    accountId: null,
    isDefault: false,
    paramsHash: `h-${id}`,
    name: id,
    ...over,
  });
  const templates = [
    tpl('global', { isDefault: true }),
    tpl('mine', { accountId: 'a1', isDefault: true }),
  ];
  const account = {
    id: 'a1',
    provider: 'upcloud',
    defaultTemplateId: null,
    qualified: true,
    qualifiedTemplateHash: 'h-mine',
  };
  it('prefers the named template, then the account default, then the provider default', () => {
    expect(effectiveTemplate(templates, account)?.id).toBe('mine');
    expect(effectiveTemplate(templates, { ...account, defaultTemplateId: 'global' })?.id).toBe(
      'global',
    );
    expect(effectiveTemplate(templates, { ...account, id: 'other' })?.id).toBe('global');
  });
  it('reports stale when the hash moved', () => {
    expect(qualificationState(account, templates).state).toBe('qualified');
    expect(qualificationState({ ...account, qualifiedTemplateHash: 'old' }, templates).state).toBe(
      'stale',
    );
    expect(qualificationState({ ...account, qualified: false }, templates).state).toBe(
      'unqualified',
    );
  });
});
