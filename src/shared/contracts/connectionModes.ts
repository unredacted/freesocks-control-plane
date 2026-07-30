import { z } from 'zod';
import { BackendId } from './backends';

/**
 * The single home of every connection-mode wire shape (DB-driven catalog):
 * the public projections publicConfig ships, the member's resolved current
 * mode on the account view, the switch-mode response, and the admin CMS
 * read/write shapes. Everything downstream imports these named symbols — no
 * inline hand-copies (the old inline shapes drifted into three duplicates).
 */

export const DeliveryStyle = z.enum(['url', 'rawConfig']);
export type DeliveryStyle = z.infer<typeof DeliveryStyle>;

/** PUBLIC family projection (publicConfig.connectionModeFamilies). Only
 *  enabled families with ≥1 visible child ship. `label`/`description`/
 *  `audience` are null unless admin-set (null → the SPA's translated copy for
 *  built-in ids); `iconId` is an OPEN string resolved by the client icon
 *  registry (unknown → fallback icon). */
export const PublicConnectionModeFamily = z.object({
  id: z.string(),
  label: z.string().nullable(),
  description: z.string().nullable().optional().default(null),
  audience: z.string().nullable().optional().default(null),
  iconId: z.string().nullable().optional().default(null),
});
export type PublicConnectionModeFamily = z.infer<typeof PublicConnectionModeFamily>;

/** PUBLIC leaf projection (publicConfig.connectionModes). Admin-disabled modes
 *  are omitted entirely; a member sitting on one is served their own mode via
 *  the account view's `currentMode` instead. `availableBackends` = the backend
 *  types the mode is actually selectable on (enabled AND applicable AND bound
 *  where the backend has a placement concept) — the client joins it against
 *  the member's backend; `available` is the any-backend convenience bool kept
 *  for deploy skew. */
export const PublicConnectionMode = z.object({
  id: z.string(),
  family: z.string().optional(),
  deliveryStyle: DeliveryStyle,
  label: z.string().nullable(),
  description: z.string().nullable().optional().default(null),
  isDefault: z.boolean(),
  isFamilyDefault: z.boolean().optional().default(false),
  availableBackends: z.array(z.string()).optional().default([]),
  available: z.boolean(),
});
export type PublicConnectionMode = z.infer<typeof PublicConnectionMode>;

/** The member's CURRENT mode, fully resolved on the account view — present
 *  even when the mode is admin-disabled or gone from the catalog, so the SPA
 *  renders the right delivery UI (deliveryStyle) and a proper label instead of
 *  a raw slug. `available` is judged against the member's own backend. */
export const MemberCurrentMode = z.object({
  id: z.string(),
  deliveryStyle: DeliveryStyle,
  label: z.string().nullable(),
  description: z.string().nullable().optional().default(null),
  family: z.object({ id: z.string(), label: z.string().nullable() }).nullable(),
  available: z.boolean(),
});
export type MemberCurrentMode = z.infer<typeof MemberCurrentMode>;

/** Response of POST /api/v1/account/switch-mode (replaces the inline zod that
 *  lived in ConnectionModeSwitcher). */
export const SwitchModeResponse = z.object({
  subscriptionUrl: z.string(),
  shortUuid: z.string(),
  mode: z.object({ id: z.string(), label: z.string().nullable() }),
  oldSubscriptionDeletedAt: z.string().nullable(),
});
export type SwitchModeResponse = z.infer<typeof SwitchModeResponse>;

// --- admin CMS shapes ---------------------------------------------------------

/** Per-(mode, backend) placement summary — sizes only, the config contents
 *  (squad UUIDs) are write-only and never round-trip. */
export const ModePlacementSummary = z.object({
  backendId: z.string(),
  bound: z.boolean(),
  boundCount: z.number().int().nonnegative(),
});
export type ModePlacementSummary = z.infer<typeof ModePlacementSummary>;

export const AdminConnectionModeFamily = z.object({
  id: z.string(),
  label: z.string().nullable(),
  description: z.string().nullable(),
  audience: z.string().nullable().optional().default(null),
  iconId: z.string().nullable().optional().default(null),
  enabled: z.boolean(),
  order: z.number().int().optional().default(0),
  /** Seeded slug the SPA has compiled i18n for (a null label is fine); an
   *  admin-created family must always carry a label. */
  builtIn: z.boolean().optional().default(false),
});
export type AdminConnectionModeFamily = z.infer<typeof AdminConnectionModeFamily>;

export const AdminConnectionMode = z.object({
  id: z.string(),
  family: z.string().nullable(),
  label: z.string().nullable(),
  description: z.string().nullable(),
  deliveryStyle: DeliveryStyle,
  isDefault: z.boolean(),
  isFamilyDefault: z.boolean(),
  isCensorshipRecommended: z.boolean().optional().default(false),
  enabled: z.boolean(),
  /** The row's own toggle (enabled = ownEnabled AND the family's). */
  ownEnabled: z.boolean().optional().default(true),
  /** The mode's family row is missing (fail-safe disabled) — surfaced so the
   *  operator can re-parent or recreate the family. */
  orphaned: z.boolean().optional().default(false),
  /** Backend APPLICABILITY (admin intent). */
  backends: z.array(z.string()).optional().default([]),
  /** Per-backend selectability (enabled AND applicable AND bound). */
  availableBackends: z.array(z.string()).optional().default([]),
  order: z.number().int().optional().default(0),
  builtIn: z.boolean().optional().default(false),
  placements: z.array(ModePlacementSummary).optional().default([]),
  /** Legacy any-backend bound flag (older servers). */
  bound: z.boolean().optional().default(false),
});
export type AdminConnectionMode = z.infer<typeof AdminConnectionMode>;

/** GET /api/v1/admin/connection-modes: the full catalog incl. DISABLED entries
 *  (the operator must see and re-enable what they switched off) — but, like
 *  every mode surface, never a placement config. */
export const AdminConnectionModesResponse = z.object({
  families: z.array(AdminConnectionModeFamily),
  modes: z.array(AdminConnectionMode),
});
export type AdminConnectionModesResponse = z.infer<typeof AdminConnectionModesResponse>;

/** The mode slug: the immutable wire id (users.connectionModeId, censorship
 *  matrix cells, audit payloads). Rename = create + migrate + delete. */
export const ModeSlug = z
  .string()
  .min(1)
  .max(32)
  .regex(/^[a-z0-9][a-z0-9-]*$/, 'lowercase letters, digits, and hyphens only');

/** Write shapes for the admin editors. `label` is REQUIRED on create — an
 *  admin-created id has no compiled i18n, and raw slugs must never render. */
export const FamilyUpsert = z.object({
  label: z.string().min(1).max(64).nullable().optional(),
  description: z.string().max(500).nullable().optional(),
  audience: z.string().max(80).nullable().optional(),
  iconId: z.string().max(40).nullable().optional(),
  enabled: z.boolean().optional(),
  order: z.number().int().optional(),
});
export type FamilyUpsert = z.infer<typeof FamilyUpsert>;

export const FamilyCreate = FamilyUpsert.extend({
  slug: ModeSlug,
  label: z.string().min(1).max(64),
});
export type FamilyCreate = z.infer<typeof FamilyCreate>;

export const ModeUpsert = z.object({
  family: z.string().optional(),
  label: z.string().min(1).max(64).nullable().optional(),
  description: z.string().max(500).nullable().optional(),
  deliveryStyle: DeliveryStyle.optional(),
  enabled: z.boolean().optional(),
  isFamilyDefault: z.boolean().optional(),
  isCensorshipRecommended: z.boolean().optional(),
  backends: z.array(BackendId).min(1).optional(),
  order: z.number().int().optional(),
  /** Point the global default at this mode (refused while it is disabled). */
  makeDefault: z.boolean().optional(),
});
export type ModeUpsert = z.infer<typeof ModeUpsert>;

export const ModeCreate = ModeUpsert.extend({
  slug: ModeSlug,
  label: z.string().min(1).max(64),
  family: z.string().min(1),
  deliveryStyle: DeliveryStyle,
  backends: z.array(BackendId).min(1),
});
export type ModeCreate = z.infer<typeof ModeCreate>;
