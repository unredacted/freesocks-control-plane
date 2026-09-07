/**
 * Edge templates: operator-editable provisioning parameters per provider,
 * validated by the adapter's zod `templateSchema`, with a small placeholder
 * language for string fields: {{name}} {{originAddress}} {{originPort}} {{edgePort}}.
 * Rendering is a deep walk over strings only; numbers/booleans pass through.
 */
import type { EdgeSpec } from './types';

export const TEMPLATE_PLACEHOLDERS = ['name', 'originAddress', 'originPort', 'edgePort'] as const;

export function renderTemplateValue<T>(value: T, spec: EdgeSpec): T {
  const listener = spec.listeners[0];
  const vars: Record<string, string> = {
    name: spec.name,
    originAddress: listener?.members[0]?.address ?? '',
    originPort: String(listener?.members[0]?.port ?? ''),
    edgePort: String(listener?.edgePort ?? ''),
  };
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') {
      return v.replace(/\{\{\s*([a-zA-Z]+)\s*\}\}/g, (m, key: string) =>
        key in vars ? vars[key] : m,
      );
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x)]),
      );
    }
    return v;
  };
  return walk(value) as T;
}

/** Stable JSON (sorted keys) for hashing template params. */
export function canonicalJson(value: unknown): string {
  const norm = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(norm);
    if (v && typeof v === 'object') {
      return Object.fromEntries(
        Object.keys(v as Record<string, unknown>)
          .sort()
          .map((k) => [k, norm((v as Record<string, unknown>)[k])]),
      );
    }
    return v;
  };
  return JSON.stringify(norm(value));
}

/** Parse + validate stored params with the adapter schema; throws the zod error. */
export function parseTemplateParams<T>(schema: { parse: (v: unknown) => T }, raw: string): T {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    json = {};
  }
  return schema.parse(json);
}
