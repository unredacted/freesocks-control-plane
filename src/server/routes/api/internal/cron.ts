/**
 * `/api/internal/cron/*` — HTTP entrypoint to the cron task dispatcher.
 *
 * Why this exists: not every deploy target has native scheduled triggers.
 *
 *   - **Cloudflare Workers** has `wrangler triggers`, and the worker entry's
 *     `scheduled` handler runs them automatically. This endpoint is still
 *     useful for ad-hoc manual triggers.
 *   - **Self-host** uses `node-cron` from the entry point. Same as above —
 *     useful as a manual lever.
 *   - **Fastly Compute** has no scheduled triggers at all. This endpoint is
 *     the only way to run cron tasks; pair it with any HTTP-capable
 *     scheduler (GitHub Actions, cron-job.org, a separate Cloudflare Worker,
 *     a systemd timer on a VPS, etc.).
 *
 * Auth: a single shared secret in the `Authorization: Bearer <secret>`
 * header, configured via `CRON_TRIGGER_SECRET`. We deliberately do NOT use
 * the admin session or API-token systems here — those are designed for
 * human/programmatic actors with named identities; cron triggers are
 * impersonal and the secret is rotated by the operator on the same cadence
 * as other infra secrets. If `CRON_TRIGGER_SECRET` is unset, every request
 * is rejected (failed-closed, so an operator who forgets to set the secret
 * doesn't accidentally expose the endpoint).
 *
 * The bearer comparison is constant-time to avoid timing-channel exposure.
 */
import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import { z, ApiErrorResponse } from '../../../openapi/registry';
import type { AppEnv } from '../../../env';
import { runCronTask, type CronTask } from '../../../jobs/dispatcher';

const CRON_TASKS: readonly CronTask[] = [
  'grace-sweep',
  'cleanup-expired-free',
  'propagate-tier-changes',
  'outline-healthcheck',
] as const;

const router = new OpenAPIHono<AppEnv>();

const runTaskRoute = createRoute({
  method: 'post',
  path: '/run-task',
  tags: ['Internal'],
  summary: 'Run a single cron task synchronously',
  description:
    'Authenticated with a shared bearer secret (`CRON_TRIGGER_SECRET`). Intended for ' +
    'external schedulers on platforms without native cron (e.g. Fastly Compute). ' +
    'Returns 200 when the task finishes, or surfaces the task failure as a 500.',
  // Excluded from the published OpenAPI spec: this is an internal,
  // shared-secret endpoint, not part of the public API surface. (`hide`
  // keeps it out of /api/openapi.json while preserving runtime validation.)
  hide: true,
  request: {
    query: z.object({
      task: z.enum(CRON_TASKS as readonly [CronTask, ...CronTask[]]),
    }),
  },
  responses: {
    200: {
      description: 'Task completed',
      content: {
        'application/json': {
          schema: z.object({ ok: z.literal(true), task: z.string(), durationMs: z.number() }),
        },
      },
    },
    401: {
      description: 'Unauthorized — missing or wrong bearer',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
    400: {
      description: 'Bad request — unknown task',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
    500: {
      description: 'Task failed',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(runTaskRoute, async (c) => {
  const platform = c.var.platform;
  const expected = platform.config.CRON_TRIGGER_SECRET;
  if (!expected) {
    // Endpoint disabled. Same response shape as a bad secret so operators
    // get a uniform signal rather than two different paths an attacker can
    // distinguish between.
    return c.json(
      { error: { code: 'auth.disabled', message: 'Cron trigger endpoint is not configured' } },
      401,
    );
  }
  const header = c.req.header('authorization') ?? '';
  const presented = header.toLowerCase().startsWith('bearer ') ? header.slice(7) : '';
  if (!presented || !constantTimeEquals(presented, expected)) {
    return c.json({ error: { code: 'auth.invalid', message: 'Invalid cron trigger bearer' } }, 401);
  }
  const { task } = c.req.valid('query');
  const start = Date.now();
  try {
    await runCronTask(task as CronTask, platform);
    return c.json({ ok: true as const, task, durationMs: Date.now() - start }, 200);
  } catch (err) {
    platform.logger.error('cron_trigger_failed', { task, error: String(err) });
    return c.json(
      {
        error: {
          code: 'cron.failed',
          message: err instanceof Error ? err.message : String(err),
        },
      },
      500,
    );
  }
});

/**
 * Length-checked constant-time string comparison. Skips constant-time when
 * lengths differ — leaking the length of `expected` is not useful to an
 * attacker (it's just the configured secret's length, which an operator can
 * choose), and short-circuiting avoids any timing oddity from comparing
 * mismatched-length strings.
 */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export default router;
