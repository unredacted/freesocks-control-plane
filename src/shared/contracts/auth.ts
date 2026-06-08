import { z } from 'zod';
import { TierSlug } from './common';

export const AuthMeResponse = z.object({
  authenticated: z.boolean(),
  member: z
    .object({
      tier: z.object({ slug: TierSlug, name: z.string() }),
    })
    .optional(),
});
export type AuthMeResponse = z.infer<typeof AuthMeResponse>;

export const LoginRedirectQuery = z.object({
  returnTo: z.string().optional(),
});
export type LoginRedirectQuery = z.infer<typeof LoginRedirectQuery>;

export const AdminAuthStatus = z.object({
  hasAdmins: z.boolean(),
  bootstrapAvailable: z.boolean(),
  /**
   * Whether the caller currently has a valid admin cookie session. Used by
   * AdminEntry to skip the login form and redirect to the admin app when an
   * already-signed-in admin lands on `/admin` directly.
   */
  signedIn: z.boolean(),
});
export type AdminAuthStatus = z.infer<typeof AdminAuthStatus>;

export const PublicConfig = z.object({
  membersJoinUrl: z.string().url().optional(),
  membersAccountUrl: z.string().url().optional(),
  freeTierTurnstileSiteKey: z.string(),
  environment: z.enum(['production', 'development', 'test']),
  /**
   * Public-safe tier limits so the marketing/comparison UI renders the actual
   * enforced numbers (straight from the DB) instead of hardcoded copies that
   * silently drift from the seed. Active tiers only, ordered by `priority`
   * ascending (free → patron), deduped by slug. Deliberately excludes every
   * sensitive field — no backend/squad identifiers.
   */
  tiers: z.array(
    z.object({
      // Free-form: admins may define custom tier slugs (the admin contract
      // allows any string), so this must not be the narrower TierSlug enum —
      // an out-of-enum slug must never 500 this public endpoint.
      slug: z.string(),
      name: z.string(),
      monthlyTrafficGb: z.number().int(), // 0 = unlimited
      deviceLimit: z.number().int(),
    }),
  ),
  /**
   * Public subset of AppSettings the SPA needs to render the backend chooser
   * on `/get-key` and pick the right labels everywhere else. This is the only
   * way anonymous users learn about the backend toggle state — the full
   * `/api/v1/admin/settings` endpoint is admin-only.
   *
   * `userChoiceEnabled` gates whether the chooser is rendered at all; when
   * false, the server picks `defaultBackend` and the SPA shouldn't tease the
   * user with an option they can't use.
   */
  backends: z.object({
    remnawaveEnabled: z.boolean(),
    outlineEnabled: z.boolean(),
    defaultBackend: z.enum(['remnawave', 'outline']),
    userChoiceEnabled: z.boolean(),
    labels: z.object({
      remnawave: z.string(),
      outline: z.string(),
    }),
  }),
});
export type PublicConfig = z.infer<typeof PublicConfig>;
