/**
 * Analytics relay (self-hosted Umami) — the Convex half. The config read is
 * shared by the public `POST /api/v1/telemetry` relay route and the admin
 * `GET /api/v1/admin/analytics`; the outbound send lives in `lib/umami.ts`.
 *
 * internalQuery per the raw-channel invariant (CLAUDE.md): publicConfig.get is
 * the ONLY public function — `umamiUrl`/`websiteId` here are server-side-only
 * values that must never be readable over the deploy port.
 */
import { internalQuery } from './_generated/server';
import { resolveAnalyticsConfig } from './lib/analyticsConfig';

export const getConfig = internalQuery({
  args: {},
  handler: (ctx) => resolveAnalyticsConfig(ctx.db),
});
