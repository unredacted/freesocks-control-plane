/**
 * Guards the "one source of truth" invariant for backend-type ids: every
 * derived union — the Convex validator, the schema's config-variant set, the
 * zod enum — must track BACKEND_IDS exactly, so adding a backend id fails
 * loudly everywhere a hand-written variant is still missing.
 */
import { describe, expect, test } from 'vitest';
import { BACKEND_IDS, backendIdValidator, isBackendId } from './backendIds';
import { BackendId as BackendIdZod } from '../../src/shared/contracts/backends';
import schema from '../schema';

// Convex validators expose their structure (VUnion.members, VObject.fields,
// VLiteral.value) — internal-ish, but the cheapest exhaustiveness probe there is.
interface VLiteralLike {
  value: string;
}
interface VUnionLike {
  members: unknown[];
}
interface VObjectLike {
  fields: Record<string, unknown>;
}

describe('backend-id derivations track BACKEND_IDS', () => {
  test('backendIdValidator members ≡ BACKEND_IDS', () => {
    const members = (backendIdValidator as unknown as VUnionLike).members.map(
      (m) => (m as VLiteralLike).value,
    );
    expect(members.sort()).toEqual([...BACKEND_IDS].sort());
  });

  test('schema backendServerConfig variant types ≡ BACKEND_IDS', () => {
    const table = schema.tables.backendServers as unknown as {
      validator: VObjectLike;
    };
    const config = table.validator.fields.config as VUnionLike;
    const types = config.members.map(
      (m) => ((m as VObjectLike).fields.type as unknown as VLiteralLike).value,
    );
    expect(types.sort()).toEqual([...BACKEND_IDS].sort());
  });

  test('zod BackendId enum options ≡ BACKEND_IDS', () => {
    expect([...BackendIdZod.options].sort()).toEqual([...BACKEND_IDS].sort());
  });

  test('isBackendId accepts every id and rejects the rest', () => {
    for (const id of BACKEND_IDS) expect(isBackendId(id)).toBe(true);
    for (const bad of ['wireguard', '', 'REMNAWAVE', null, undefined, 42]) {
      expect(isBackendId(bad)).toBe(false);
    }
  });
});
