/**
 * Convex validators for the client check's stored verdict (`edges.clientCheck`),
 * derived from the shared code tuples so the schema, the mutations and the
 * admin contract name the same codes.
 */
import { v } from 'convex/values';
import {
  CLIENT_CHECK_ENGINES,
  CLIENT_CHECK_SESSION_CODES,
  CLIENT_CHECK_VERDICTS,
} from '../../../../src/shared/contracts/edgeCodes';

const lit = <T extends string>(xs: readonly T[]) => v.union(...xs.map((x) => v.literal(x)));

export const clientCheckEngineV = lit(CLIENT_CHECK_ENGINES);
export const clientCheckSessionCodeV = lit(CLIENT_CHECK_SESSION_CODES);
export const clientCheckVerdictV = lit(CLIENT_CHECK_VERDICTS);

export const clientCheckEngineVerdictV = v.object({
  engine: clientCheckEngineV,
  code: clientCheckSessionCodeV,
  engineVersion: v.union(v.string(), v.null()),
  egress: v.union(v.literal('matched'), v.literal('mismatch'), v.null()),
  excused: v.boolean(),
});

/**
 * The latest verdict a real engine reached through an address. Codes, versions
 * and the configuration it was taken against; never an address or an egress IP.
 */
export const edgeClientCheckV = v.object({
  at: v.number(),
  verdict: clientCheckVerdictV,
  ok: v.boolean(),
  engines: v.array(clientCheckEngineVerdictV),
  /** A control address was checked too (the verdict is relative to it). */
  control: v.boolean(),
  /** Who asked: an operator, or FCP's own work (a rotation). */
  by: v.union(v.literal('admin'), v.literal('system')),
  listenerRevision: v.number(),
  configHash: v.string(),
});

/**
 * What FCP's own test of a send's name found on one node
 * (`sniAcceptanceReceipts.check`, sniAutoConfirm.ts): the verdict, or the code
 * saying why none was reached or why the receipt was voided. Codes and engine
 * versions only.
 */
export const sniAutoTestCheckV = v.object({
  at: v.number(),
  verdict: v.union(clientCheckVerdictV, v.null()),
  code: v.union(v.string(), v.null()),
  engines: v.array(
    v.object({
      engine: clientCheckEngineV,
      code: clientCheckSessionCodeV,
      engineVersion: v.union(v.string(), v.null()),
    }),
  ),
  /** The same address with the name members get now was checked too. */
  control: v.boolean(),
});
