/**
 * Centralized parsing for the `subscriptions.subscription_mirrors` JSON
 * column. Six callers across `routes/api/*` and `services/*` previously did
 * `JSON.parse(sub.subscriptionMirrors) as <ad-hoc shape>` with no try/catch
 * and no schema validation. A single malformed row (admin SQL fix gone
 * wrong, mid-migration drift, storage corruption) would crash every read
 * path that touched the affected user — `/account`, `/subscription`,
 * regenerate, and the grace-period sweep cron mid-iteration.
 *
 * This helper:
 *   1. Returns `[]` on `null`/empty input (a row that's never had mirrors).
 *   2. Catches JSON parse errors, logs a structured warning, returns `[]`.
 *   3. Validates against a Zod schema that mirrors the on-disk shape
 *      written by `subscription-delivery.ts`. Unknown extra fields are
 *      stripped, missing required fields fail the parse → `[]`.
 *   4. NEVER throws. Callers can rely on the return being a usable array.
 *
 * The `objectPath` field is optional — storage-delete paths need it; SPA
 * read paths only consume `provider` + `publicUrl`. Future writes (H4
 * partial-mirror status) can extend the schema with optional fields and
 * existing readers won't break.
 */
import { z } from 'zod';
import type { Logger } from './logger';

const MirrorEntry = z.object({
  provider: z.string(),
  publicUrl: z.string().url(),
  objectPath: z.string().optional(),
  /**
   * Per-mirror upload outcome. Optional for backwards compatibility with
   * rows written before the H4 fix. When absent, treat as `'ok'`. See
   * `services/subscription-delivery.ts` for the producer.
   */
  status: z.enum(['ok', 'failed']).optional(),
});
export type Mirror = z.infer<typeof MirrorEntry>;

const MirrorList = z.array(MirrorEntry);

export function parseMirrors(
  raw: string | null | undefined,
  logger: Logger,
  ctx?: { subscriptionId?: number; userId?: number },
): Mirror[] {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    logger.warn('subscription_mirrors_parse_failed', {
      error: String(err),
      ...ctx,
    });
    return [];
  }
  const result = MirrorList.safeParse(parsed);
  if (!result.success) {
    logger.warn('subscription_mirrors_schema_invalid', {
      issues: result.error.issues.map((i) => ({ path: i.path, code: i.code })),
      ...ctx,
    });
    return [];
  }
  return result.data;
}
