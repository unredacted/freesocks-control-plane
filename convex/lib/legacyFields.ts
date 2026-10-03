/**
 * Refusing request fields the admin API no longer speaks (pure; unit-tested).
 *
 * Request bodies are parsed with the shared zod write schemas, and a zod object
 * STRIPS keys it does not know before any refinement runs. So a body that still
 * sends a renamed field (`inboundUuid` where the contract says `transportUuid`)
 * would have that field vanish silently: a mixed old+new body would pass, and a
 * legacy-only one would fail later with a misleading "missing field". The check
 * therefore runs on the RAW JSON, before zod, and names the field it refuses.
 *
 * A spec lists the obsolete names at one level and, per key, the spec of a
 * nested object or of every element of a nested array.
 */
export interface LegacySpec {
  keys?: readonly string[];
  nested?: Readonly<Record<string, LegacySpec>>;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);

/** The path of the first obsolete field present in `raw` (e.g. `ops[1].inboundTag`), or null. */
export function findLegacyField(raw: unknown, spec: LegacySpec, at = ''): string | null {
  if (!isObj(raw)) return null;
  for (const k of spec.keys ?? []) {
    if (Object.prototype.hasOwnProperty.call(raw, k)) return at ? `${at}.${k}` : k;
  }
  for (const [k, inner] of Object.entries(spec.nested ?? {})) {
    const v = raw[k];
    const path = at ? `${at}.${k}` : k;
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) {
        const hit = findLegacyField(v[i], inner, `${path}[${i}]`);
        if (hit) return hit;
      }
    } else {
      const hit = findLegacyField(v, inner, path);
      if (hit) return hit;
    }
  }
  return null;
}

/** The obsolete names of each admin write body (the 2026-09-20 vocabulary rename). */
export const LEGACY = {
  addressCreate: { keys: ['inboundUuid'] },
  addressPatch: { keys: ['inboundUuid'] },
  modeGroup: { keys: ['inboundUuids'] },
  profilePreview: { nested: { ops: { keys: ['inboundTag'] } } },
  profileApply: { keys: ['inboundUuids'], nested: { ops: { keys: ['inboundTag'] } } },
  directConfirm: { nested: { binding: { keys: ['inboundUuid'] } } },
  sniBind: { keys: ['inboundTag'] },
} as const satisfies Record<string, LegacySpec>;
