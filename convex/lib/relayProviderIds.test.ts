/**
 * Guards the one-source-of-truth invariant for relay-provider ids: the Convex
 * validator, the schema's credential/settings variant sets, and the zod enum
 * must all track RELAY_PROVIDER_IDS exactly.
 */
import { describe, expect, test } from 'vitest';
import {
  RELAY_PROVIDER_IDS,
  isRelayProviderId,
  relayProviderIdValidator,
} from './relayProviderIds';
import { RelayProviderId as RelayProviderIdZod } from '../../src/shared/contracts/relays';
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

describe('relay-provider-id derivations track RELAY_PROVIDER_IDS', () => {
  test('relayProviderIdValidator members ≡ RELAY_PROVIDER_IDS', () => {
    const members = (relayProviderIdValidator as unknown as VUnionLike).members.map(
      (m) => (m as VLiteralLike).value,
    );
    expect(members.sort()).toEqual([...RELAY_PROVIDER_IDS].sort());
  });

  test('schema relayProviderAccounts credentials + settings variants ≡ RELAY_PROVIDER_IDS', () => {
    const table = schema.tables.relayProviderAccounts as unknown as { validator: VObjectLike };
    expect(variantTypes(table.validator.fields.credentials as VUnionLike)).toEqual(
      [...RELAY_PROVIDER_IDS].sort(),
    );
    expect(variantTypes(table.validator.fields.settings as VUnionLike)).toEqual(
      [...RELAY_PROVIDER_IDS].sort(),
    );
  });

  test('zod RelayProviderId enum options ≡ RELAY_PROVIDER_IDS', () => {
    expect([...RelayProviderIdZod.options].sort()).toEqual([...RELAY_PROVIDER_IDS].sort());
  });

  test('isRelayProviderId accepts every id and rejects the rest', () => {
    for (const id of RELAY_PROVIDER_IDS) expect(isRelayProviderId(id)).toBe(true);
    for (const bad of ['aws', '', 'GCORE', null, undefined, 42]) {
      expect(isRelayProviderId(bad)).toBe(false);
    }
  });
});
