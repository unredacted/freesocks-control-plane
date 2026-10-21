/**
 * Pure helpers for the provider OPTION forms (unit-tested): the template
 * editor, an account's defaults, a node's pick and one address all render the
 * same descriptors (`EdgeTemplateField`, served as `optionSchemas`).
 *
 * `values` is what this level sets; `base` is what applies without it (the
 * template and the account's defaults for a node's pick, the provider's
 * defaults for a template). Absent = inherited.
 *
 * Exports:
 *   visibleFields(fields, values, base)    hidden ones and unmet `when`s dropped
 *   groupsOf(fields)                       [{ group, fields }] in declaration order
 *   kvToText(v) / textToKv(s, pairs)       key/value fields as `key=value` lines
 *   overrides(values, base, fields)        only what differs from the base
 *   optionSummary(fields, values)          "Label value" phrases for a chip line
 *   valueWords(field, value)               one value in words
 */
import type { EdgeTemplateField } from '../../../../../shared/contracts/edges';
import { deepEqual, getPath, setPath, type Params } from '../templates/params';

const isObject = (v: unknown): v is Params =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** `over` laid onto `base`, objects key by key. */
export function deepMerge(base: Params, over: Params): Params {
  const out: Params = { ...base };
  for (const [k, v] of Object.entries(over)) {
    if (v === undefined) continue;
    out[k] = isObject(v) && isObject(base[k]) ? deepMerge(base[k] as Params, v) : v;
  }
  return out;
}

/** The fields to show: never a hidden one, and a `when` only while it holds. */
export function visibleFields(
  fields: readonly EdgeTemplateField[],
  values: Params,
  base: Params,
): EdgeTemplateField[] {
  const effective = deepMerge(base, values);
  return fields.filter((f) => {
    if (f.hidden) return false;
    if (!f.when) return true;
    const v = getPath(effective, f.when.key) ?? fields.find((x) => x.key === f.when!.key)?.default;
    return f.when.in.some((x) => x === v);
  });
}

/** Fields under their resource's heading, headings in the order they first appear. */
export function groupsOf(
  fields: readonly EdgeTemplateField[],
): Array<{ group: string; fields: EdgeTemplateField[] }> {
  const out: Array<{ group: string; fields: EdgeTemplateField[] }> = [];
  for (const f of fields) {
    const name = f.group ?? 'Settings';
    const g = out.find((x) => x.group === name);
    if (g) g.fields.push(f);
    else out.push({ group: name, fields: [f] });
  }
  return out;
}

/** A key/value value as `key=value` lines (an object, or `[{key, value}]` pairs). */
export function kvToText(v: unknown): string {
  if (Array.isArray(v))
    return v
      .filter((x): x is { key: string; value: string } => isObject(x) && typeof x.key === 'string')
      .map((x) => `${x.key}=${String(x.value ?? '')}`)
      .join('\n');
  if (isObject(v))
    return Object.entries(v)
      .map(([k, x]) => `${k}=${String(x ?? '')}`)
      .join('\n');
  return '';
}

/** `key=value` lines back to the field's shape; a line without `=` is a key with an empty value. */
export function textToKv(
  s: string,
  pairs: boolean,
): Record<string, string> | Array<{ key: string; value: string }> {
  const rows = s
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const at = line.indexOf('=');
      return at === -1
        ? { key: line, value: '' }
        : { key: line.slice(0, at).trim(), value: line.slice(at + 1).trim() };
    })
    .filter((r) => r.key.length > 0);
  return pairs ? rows : Object.fromEntries(rows.map((r) => [r.key, r.value]));
}

/** Only the keys of `values` that differ from `base` (what a level actually chooses). */
export function overrides(
  values: Params,
  base: Params,
  fields: readonly Pick<EdgeTemplateField, 'key'>[],
): Params {
  let out: Params = {};
  for (const f of fields) {
    const v = getPath(values, f.key);
    if (v === undefined) continue;
    if (!deepEqual(v, getPath(base, f.key))) out = setPath(out, f.key, v);
  }
  return out;
}

/** One value in words: a choice's label, On/Off, a number with its unit, a count of entries. */
export function valueWords(field: EdgeTemplateField, value: unknown): string {
  if (value === undefined || value === null || value === '') return 'not set';
  if (field.type === 'select')
    return field.options?.find((o) => o.value === value)?.label ?? String(value);
  if (field.type === 'boolean') return value === true ? 'on' : 'off';
  if (field.type === 'number') return field.unit ? `${String(value)} ${field.unit}` : String(value);
  if (field.type === 'string-list')
    return Array.isArray(value) ? `${value.length} entr${value.length === 1 ? 'y' : 'ies'}` : '';
  if (field.type === 'key-value') {
    const n = Array.isArray(value) ? value.length : isObject(value) ? Object.keys(value).length : 0;
    return `${n} label${n === 1 ? '' : 's'}`;
  }
  return String(value);
}

/** "Label: value" for every option `values` sets, in declaration order. */
export function optionSummary(fields: readonly EdgeTemplateField[], values: Params): string[] {
  const out: string[] = [];
  for (const f of fields) {
    if (f.hidden) continue;
    const v = getPath(values, f.key);
    if (v === undefined) continue;
    out.push(`${f.label}: ${valueWords(f, v)}`);
  }
  return out;
}

interface TemplateLike {
  id: string;
  provider: string;
  accountId: string | null;
  isDefault: boolean;
  params: unknown;
  createdAt?: string;
}

/**
 * What one location builds with when a node chooses nothing: the template it
 * resolves (its own, else the account's, else the provider's default) over the
 * provider's defaults, its regional values, and the account's certificate
 * defaults over the declared ones. The server is authoritative; this is what
 * the forms show as inherited.
 */
export function pickBase(
  schema: { fields: readonly EdgeTemplateField[]; defaults: Params },
  templateDefaults: Params,
  templates: readonly TemplateLike[],
  account: {
    id: string;
    provider: string;
    defaultTemplateId: string | null;
    optionDefaults?: Record<string, unknown>;
  },
  location: { defaultTemplateId: string | null; regionalParams: Record<string, string> } | null,
): Params {
  const own = templates.filter((t) => t.provider === account.provider);
  // The server's order (`resolveBaseTemplate`): the location's, the account's,
  // the account's own default, the provider's default, else the earliest
  // unscoped template.
  const unscoped = own
    .filter((t) => t.accountId === null)
    .sort((a, b) => (a.createdAt ?? '').localeCompare(b.createdAt ?? ''));
  const tpl =
    own.find((t) => t.id === location?.defaultTemplateId) ??
    own.find((t) => t.id === account.defaultTemplateId) ??
    own.find((t) => t.isDefault && t.accountId === account.id) ??
    unscoped.find((t) => t.isDefault) ??
    unscoped[0] ??
    null;
  let out = deepMerge(schema.defaults, templateDefaults);
  if (tpl && isObject(tpl.params)) out = deepMerge(out, tpl.params);
  for (const [k, v] of Object.entries(location?.regionalParams ?? {})) out = setPath(out, k, v);
  return deepMerge(out, (account.optionDefaults ?? {}) as Params);
}
