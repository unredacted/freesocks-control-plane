/**
 * Provider OPTIONS, the generic half (isolate-safe, no SDK imports): what one
 * settable field of one provider resource looks like to FCP, wherever it is
 * chosen. The per-provider declarations live in `templates.ts`; docs/edges.md
 * § "Provider options" has the model.
 *
 * Two kinds, each with one home for its default:
 *  - TUNING options configure the resources an edge is built from (a load
 *    balancer's size, a listener timeout, a backend's IPv6 preference). Their
 *    defaults live in TEMPLATES, which are in the template hash as before.
 *  - CERTIFICATE options decide the certificate a CDN front serves (the
 *    authority). Their defaults live on the ACCOUNT (`optionDefaults`) and are
 *    frozen in the L7 intent, outside the template hash, as the authority
 *    always was.
 * Any option may be chosen for one node's pick (`relays.providerSet[i]
 * .options`): tuning choices are laid over the template and enter the edge's
 * template hash; certificate choices replace the account's.
 *
 * The HASH RULE: an option added after a provider's first schema is
 * `.optional()` and its default is applied where it is sent, never by the
 * parse. A stored template then parses to exactly the object it did before, so
 * no template hash, location trust or in-flight provision moves on deploy
 * (`templates.test.ts` pins the hash of every provider's empty template).
 */
import { z } from 'zod';
import { canonicalJson } from './template';

export type OptionType =
  | 'string'
  | 'number'
  | 'boolean'
  | 'select'
  | 'string-list'
  | 'key-value';

export type OptionKind = 'tuning' | 'certificate';

/** What a change of the value would take on a live resource (informational: FCP never applies one). */
export type OptionLiveChange = 'in_place' | 'new_version' | 'rebuild';

/** Lists a select is filled from instead of a fixed `options` list: the location's inventory. */
export type OptionSource = 'flavors';

/** Where the value goes in the provider's API. */
export interface WireBinding {
  /** The resource the value configures (`loadbalancer`, `listener`, `backend`, ...). */
  resource: string;
  /** The request-body field, dotted for a nested object (`properties.timeout_client`). */
  field: string;
  /** Multiplier applied before sending (a field kept in seconds for an API in milliseconds). */
  scale?: number;
  /** The adapter's own body builder writes it (fields that predate `wireBody`). */
  manual?: boolean;
}

/** One option as the forms and the server see it. */
export interface OptionField {
  /** Dotted path into the option values (`healthMonitor.delay`). */
  key: string;
  label: string;
  type: OptionType;
  /** Plain words: what it changes and when to touch it. */
  help?: string;
  options?: Array<{ value: string; label: string }>;
  required?: boolean;
  /** The value differs per region (a flavor id): each location can set its own (`regionalParams`). */
  regional?: boolean;
  /** The resource it belongs to, as the form heads its section. */
  group?: string;
  unit?: string;
  /** Folded away until the operator asks for every option. */
  advanced?: boolean;
  /** Offered first when choosing for one node. */
  prominent?: boolean;
  /**
   * Kept only so stored templates parse to the object they always did: the
   * provider has no such setting, so it is never shown and never sent.
   */
  hidden?: boolean;
  /** A `key-value` field stored as `[{key, value}]` instead of an object. */
  pairs?: boolean;
  /** Absent = tuning. */
  kind?: OptionKind;
  min?: number;
  max?: number;
  pattern?: string;
  maxItems?: number;
  /** The value that applies when nothing sets one: what FCP sent before the option existed. */
  default?: unknown;
  /** Shown only while another option holds one of these values. */
  when?: { key: string; in: Array<string | number | boolean> };
  from?: OptionSource;
  wire?: WireBinding;
  live?: OptionLiveChange;
}

/** Where a value is being set; each level accepts a different part of a provider's options. */
export type OptionLevel = 'template' | 'account' | 'pick';

// --- paths ---------------------------------------------------------------------------------------

export type Values = Record<string, unknown>;

const isObject = (v: unknown): v is Values =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

export function getPath(obj: unknown, key: string): unknown {
  let cur: unknown = obj;
  for (const part of key.split('.')) {
    if (!isObject(cur)) return undefined;
    cur = cur[part];
  }
  return cur;
}

export function setPath(obj: Values, key: string, value: unknown): Values {
  const [head, ...rest] = key.split('.');
  if (head === undefined || head === '') return obj;
  if (rest.length === 0) return { ...obj, [head]: value };
  const inner = isObject(obj[head]) ? (obj[head] as Values) : {};
  return { ...obj, [head]: setPath(inner, rest.join('.'), value) };
}

/** `over` laid onto `base`: objects merge key by key, anything else replaces. */
export function deepMerge(base: Values, over: Values): Values {
  const out: Values = { ...base };
  for (const [k, v] of Object.entries(over)) {
    if (v === undefined) continue;
    out[k] = isObject(v) && isObject(base[k]) ? deepMerge(base[k] as Values, v) : v;
  }
  return out;
}

/**
 * The option keys a value object sets, as dotted paths: descends into plain
 * objects except where a field's value IS an object (a key/value map).
 */
export function setKeys(values: Values, fields: readonly Pick<OptionField, 'key' | 'type'>[]): string[] {
  const leaf = new Set(fields.map((f) => f.key));
  const out: string[] = [];
  const walk = (v: Values, prefix: string) => {
    for (const [k, x] of Object.entries(v)) {
      if (x === undefined) continue;
      const key = prefix ? `${prefix}.${k}` : k;
      if (!leaf.has(key) && isObject(x)) walk(x, key);
      else out.push(key);
    }
  };
  walk(values, '');
  return out;
}

/** Only the given dotted keys of `values` (absent ones skipped). */
export function pickKeys(values: Values, keys: readonly string[]): Values {
  let out: Values = {};
  for (const k of keys) {
    const v = getPath(values, k);
    if (v !== undefined) out = setPath(out, k, v);
  }
  return out;
}

// --- descriptors ----------------------------------------------------------------------------------

type JsonNode = {
  type?: string;
  enum?: unknown[];
  default?: unknown;
  minimum?: number;
  maximum?: number;
  pattern?: string;
  maxItems?: number;
  properties?: Record<string, JsonNode>;
  anyOf?: JsonNode[];
};

function nodeAt(root: JsonNode, key: string): JsonNode | undefined {
  let cur: JsonNode | undefined = root;
  for (const part of key.split('.')) {
    while (cur?.anyOf) cur = cur.anyOf.find((n) => n.type !== 'null');
    cur = cur?.properties?.[part];
  }
  while (cur?.anyOf) cur = cur.anyOf.find((n) => n.type !== 'null');
  return cur;
}

/**
 * The declared fields completed from the schema: default, bounds, pattern and
 * (for a select without its own labels) the enum values. The schema stays the
 * one source of what a value may be; a declaration only says what it means.
 */
export function describeFields(schema: z.ZodType, fields: readonly OptionField[]): OptionField[] {
  const root = z.toJSONSchema(schema, { io: 'input', unrepresentable: 'any' }) as JsonNode;
  return fields.map((f) => {
    const n = nodeAt(root, f.key);
    if (!n) return { ...f };
    return {
      ...f,
      ...(f.default === undefined && n.default !== undefined ? { default: n.default } : {}),
      ...(f.min === undefined && n.minimum !== undefined ? { min: n.minimum } : {}),
      ...(f.max === undefined && n.maximum !== undefined ? { max: n.maximum } : {}),
      ...(f.pattern === undefined && n.pattern !== undefined ? { pattern: n.pattern } : {}),
      ...(f.maxItems === undefined && n.maxItems !== undefined ? { maxItems: n.maxItems } : {}),
      ...(f.type === 'select' && !f.options && n.enum
        ? { options: n.enum.map((e) => ({ value: String(e), label: String(e) })) }
        : {}),
    };
  });
}

/** Every field's default as one value object (what applies when nothing is set). */
export function defaultsOf(fields: readonly OptionField[]): Values {
  let out: Values = {};
  for (const f of fields) if (f.default !== undefined) out = setPath(out, f.key, f.default);
  return out;
}

// --- wire ----------------------------------------------------------------------------------------

/**
 * The body fragment of one resource from the option values: every field bound
 * to `resource` that has a value (its default when the field says FCP sent one
 * before the option existed), scaled, at its wire path. Fields an adapter
 * writes itself (`manual`) are left out.
 */
export function wireBody(
  fields: readonly OptionField[],
  resource: string,
  values: Values,
): Values {
  let out: Values = {};
  for (const f of fields) {
    if (!f.wire || f.wire.manual || f.wire.resource !== resource) continue;
    const v = getPath(values, f.key);
    if (v === undefined || v === null || v === '') continue;
    const sent = typeof v === 'number' && f.wire.scale ? v * f.wire.scale : v;
    out = setPath(out, f.wire.field, sent);
  }
  return out;
}

// --- hashing -------------------------------------------------------------------------------------

/** FNV-1a 64-bit as 16 hex chars (the same function the template hash uses). */
function fnv1a64Hex(input: string): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (let i = 0; i < input.length; i++) {
    h ^= BigInt(input.charCodeAt(i));
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

/**
 * The template hash of what a node's pick builds: the template's own hash when
 * the pick chose no tuning value (so an edge built for a pick without choices
 * is exactly what it was before options existed), else the hash of the
 * template with the choices laid over it.
 */
export function builtTemplateHash(
  baseParams: Values,
  baseHash: string,
  tuningChoices: Values | null | undefined,
): string {
  if (!tuningChoices || Object.keys(tuningChoices).length === 0) return baseHash;
  return fnv1a64Hex(canonicalJson(deepMerge(baseParams, tuningChoices)));
}

// --- stored choices ------------------------------------------------------------------------------

/** A stored option blob (JSON object) read back; anything unusable is `{}`. */
export function parseOptionValues(json: string | null | undefined): Values {
  if (!json) return {};
  try {
    const v: unknown = JSON.parse(json);
    return isObject(v) ? v : {};
  } catch {
    return {};
  }
}

/**
 * What changed between two option value objects, for an audit row: the keys,
 * with the values only for choices, numbers and switches (free text such as a
 * tag can carry anything, so it is recorded as changed without its value).
 */
export function optionChanges(
  fields: readonly OptionField[],
  before: Values,
  after: Values,
): Array<{ key: string; from?: unknown; to?: unknown }> {
  const keys = [...new Set([...setKeys(before, fields), ...setKeys(after, fields)])].sort();
  const out: Array<{ key: string; from?: unknown; to?: unknown }> = [];
  for (const key of keys) {
    const a = getPath(before, key);
    const b = getPath(after, key);
    if (canonicalJson(a ?? null) === canonicalJson(b ?? null)) continue;
    const type = fields.find((f) => f.key === key)?.type;
    const plain = type === 'select' || type === 'number' || type === 'boolean';
    out.push(plain ? { key, from: a ?? null, to: b ?? null } : { key });
  }
  return out;
}

/** Key-order-insensitive equality of two option value objects. */
export function sameValues(a: Values | null | undefined, b: Values | null | undefined): boolean {
  return canonicalJson(a ?? {}) === canonicalJson(b ?? {});
}

/** Split a pick's choices into its tuning and certificate parts. */
export function splitChoices(
  fields: readonly OptionField[],
  choices: Values,
): { tuning: Values; certificate: Values } {
  const cert = fields.filter((f) => f.kind === 'certificate').map((f) => f.key);
  const tune = fields.filter((f) => f.kind !== 'certificate').map((f) => f.key);
  return { tuning: pickKeys(choices, tune), certificate: pickKeys(choices, cert) };
}
