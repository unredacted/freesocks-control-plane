/**
 * Pure helpers for the descriptor-driven template editor (unit-tested).
 * A template's `params` is a nested object; each field descriptor addresses one
 * value in it with a dotted `key` (`healthCheck.interval`).
 *
 * Exports:
 *   getPath(obj, key) / setPath(obj, key, value) / unsetPath(obj, key)   (immutable)
 *   asParams(unknown)                       a plain object out of whatever the server stored
 *   deepEqual(a, b)                         key-order independent
 *   differsFromDefault(params, defaults, key)
 *   changedKeys(params, defaults, fields)   the descriptor keys that differ from the default
 *   resetField(params, defaults, key)       one field back to its default
 *   listToText(v) / textToList(s)           `string-list` fields as one entry per line
 *   numberFromInput(s)                      '' -> undefined, otherwise a finite number or NaN
 *   formatParams(params) / parseParamsJson(text)
 *   issueInWords(issue, fields)             "path: message" -> "Label: message"
 *   effectiveTemplate(templates, account)   the template an account provisions from
 *   qualificationState(account, templates)  qualified / stale / unqualified, in words
 */
import type { EdgeTemplateAdmin, EdgeTemplateField } from '../../../../../shared/contracts/edges';

export type Params = Record<string, unknown>;

const isObject = (v: unknown): v is Params =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

export const asParams = (v: unknown): Params => (isObject(v) ? v : {});

export function getPath(obj: unknown, key: string): unknown {
  let cur: unknown = obj;
  for (const part of key.split('.')) {
    if (!isObject(cur)) return undefined;
    cur = cur[part];
  }
  return cur;
}

export function setPath(obj: Params, key: string, value: unknown): Params {
  const [head, ...rest] = key.split('.');
  if (head === undefined || head === '') return obj;
  if (rest.length === 0) return { ...obj, [head]: value };
  return { ...obj, [head]: setPath(asParams(obj[head]), rest.join('.'), value) };
}

export function unsetPath(obj: Params, key: string): Params {
  const [head, ...rest] = key.split('.');
  if (head === undefined || !(head in obj)) return obj;
  if (rest.length === 0) {
    const { [head]: _gone, ...kept } = obj;
    return kept;
  }
  return { ...obj, [head]: unsetPath(asParams(obj[head]), rest.join('.')) };
}

export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  }
  if (isObject(a) && isObject(b)) {
    const ka = Object.keys(a).filter((k) => a[k] !== undefined);
    const kb = Object.keys(b).filter((k) => b[k] !== undefined);
    return ka.length === kb.length && ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

/** An absent value means "the default applies", so it never differs. */
export function differsFromDefault(params: Params, defaults: Params, key: string): boolean {
  const v = getPath(params, key);
  if (v === undefined) return false;
  return !deepEqual(v, getPath(defaults, key));
}

export function changedKeys(
  params: Params,
  defaults: Params,
  fields: readonly Pick<EdgeTemplateField, 'key'>[],
): string[] {
  return fields.map((f) => f.key).filter((k) => differsFromDefault(params, defaults, k));
}

export function resetField(params: Params, defaults: Params, key: string): Params {
  const d = getPath(defaults, key);
  return d === undefined ? unsetPath(params, key) : setPath(params, key, d);
}

export const listToText = (v: unknown): string =>
  Array.isArray(v) ? v.filter((x) => typeof x === 'string').join('\n') : '';
export const textToList = (s: string): string[] =>
  s
    .split(/[\n,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

export function numberFromInput(s: string): number | undefined {
  const t = s.trim();
  if (t === '') return undefined;
  const n = Number(t);
  return Number.isFinite(n) ? n : Number.NaN;
}

export const formatParams = (params: unknown): string => JSON.stringify(asParams(params), null, 2);

export type ParsedJson = { ok: true; params: Params } | { ok: false; error: string };
export function parseParamsJson(text: string): ParsedJson {
  if (text.trim() === '') return { ok: true, params: {} };
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return { ok: false, error: 'This is not valid JSON. Check for a missing quote or comma.' };
  }
  if (!isObject(v)) {
    return { ok: false, error: 'The parameters must be a JSON object, in curly braces.' };
  }
  return { ok: true, params: v };
}

/** The server reports "dotted.path: message"; name the field instead of the path. */
export function issueInWords(
  issue: string,
  fields: readonly Pick<EdgeTemplateField, 'key' | 'label'>[],
): string {
  const at = issue.indexOf(': ');
  if (at === -1) return issue;
  const path = issue.slice(0, at);
  const message = issue.slice(at + 2);
  if (path === '(root)') return message;
  const field = fields.find((f) => f.key === path);
  return `${field ? field.label : `"${path}"`}: ${message}`;
}

type TemplateLike = Pick<
  EdgeTemplateAdmin,
  'id' | 'provider' | 'accountId' | 'isDefault' | 'paramsHash' | 'name'
>;
interface AccountLike {
  id: string;
  provider: string;
  defaultTemplateId: string | null;
  qualified: boolean;
  qualifiedTemplateHash: string | null;
}

/** The account's named template, else its own default, else the provider's default. */
export function effectiveTemplate<T extends TemplateLike>(
  templates: readonly T[],
  account: Pick<AccountLike, 'id' | 'provider' | 'defaultTemplateId'>,
): T | null {
  const own = templates.filter((t) => t.provider === account.provider);
  return (
    own.find((t) => t.id === account.defaultTemplateId) ??
    own.find((t) => t.isDefault && t.accountId === account.id) ??
    own.find((t) => t.isDefault && t.accountId === null) ??
    null
  );
}

export type QualificationState = 'qualified' | 'stale' | 'unqualified';
export function qualificationState(
  account: AccountLike,
  templates: readonly TemplateLike[],
): { state: QualificationState; words: string } {
  if (!account.qualified) {
    return { state: 'unqualified', words: 'Not qualified. Ordinary provisioning skips it.' };
  }
  const tpl = effectiveTemplate(templates, account);
  if (tpl && account.qualifiedTemplateHash && tpl.paramsHash !== account.qualifiedTemplateHash) {
    return {
      state: 'stale',
      words: `Qualified with older parameters than "${tpl.name}" has now. Qualify it again.`,
    };
  }
  return { state: 'qualified', words: 'Qualified with the template it provisions from.' };
}
