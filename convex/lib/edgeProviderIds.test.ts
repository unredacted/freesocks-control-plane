/**
 * Guards the one-source-of-truth invariant for relay-provider ids: the Convex
 * validator, the schema's credential/settings variant sets, and the zod enum
 * must all track EDGE_PROVIDER_IDS exactly.
 */
import { describe, expect, test } from 'vitest';
import { EDGE_PROVIDER_IDS, isRelayProviderId, edgeProviderIdValidator } from './edgeProviderIds';
import { EdgeProviderId as RelayProviderIdZod } from '../../src/shared/contracts/relays';
import schema from '../schema';

interface VLiteralLike {
  value: string;
}
interface VUnionLike {
  members: unknown[];
}
interface VObjectLike {
  fields: Record<string, unknown>;
}

const variantTypes = (u: VUnionLike): string[] =>
  u.members.map((m) => ((m as VObjectLike).fields.type as unknown as VLiteralLike).value).sort();

describe('relay-provider-id derivations track EDGE_PROVIDER_IDS', () => {
  test('edgeProviderIdValidator members ≡ EDGE_PROVIDER_IDS', () => {
    const members = (edgeProviderIdValidator as unknown as VUnionLike).members.map(
      (m) => (m as VLiteralLike).value,
    );
    expect(members.sort()).toEqual([...EDGE_PROVIDER_IDS].sort());
  });

  test('schema edgeProviderAccounts credentials + settings variants ≡ EDGE_PROVIDER_IDS', () => {
    const table = schema.tables.edgeProviderAccounts as unknown as { validator: VObjectLike };
    expect(variantTypes(table.validator.fields.credentials as VUnionLike)).toEqual(
      [...EDGE_PROVIDER_IDS].sort(),
    );
    expect(variantTypes(table.validator.fields.settings as VUnionLike)).toEqual(
      [...EDGE_PROVIDER_IDS].sort(),
    );
  });

  test('zod EdgeProviderId enum options ≡ EDGE_PROVIDER_IDS', () => {
    expect([...RelayProviderIdZod.options].sort()).toEqual([...EDGE_PROVIDER_IDS].sort());
  });

  test('isRelayProviderId accepts every id and rejects the rest', () => {
    for (const id of EDGE_PROVIDER_IDS) expect(isRelayProviderId(id)).toBe(true);
    for (const bad of ['aws', '', 'GCORE', null, undefined, 42]) {
      expect(isRelayProviderId(bad)).toBe(false);
    }
  });
});
