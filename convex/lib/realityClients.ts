/**
 * Convex-side derivation of the REALITY client verdict
 * (src/shared/contracts/realityClients.ts): the one validator every stored or
 * passed verdict uses, so a new cause or family updates them all at once.
 */
import { v } from 'convex/values';
import {
  REALITY_CLIENT_FAMILIES,
  REALITY_REFUSAL_CAUSES,
} from '../../src/shared/contracts/realityClients';

const nullableString = v.union(v.string(), v.null());

export const realityClientRefusalFields = {
  cause: v.union(...REALITY_REFUSAL_CAUSES.map((c) => v.literal(c))),
  refuses: v.array(v.union(...REALITY_CLIENT_FAMILIES.map((f) => v.literal(f)))),
  xrayVersion: nullableString,
  minClientVer: nullableString,
  maxClientVer: nullableString,
};
export const realityClientRefusalV = v.object(realityClientRefusalFields);
