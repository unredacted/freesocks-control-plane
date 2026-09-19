/**
 * Wire contracts for server-name families (`/api/v1/admin/edges/sni/*`): curated
 * pools of names one target site really serves, rolled out to REALITY inbounds
 * and handed to members only after a node proves it accepts them (docs/edges.md).
 */
import { z } from 'zod';

export const SniConfig = z.object({
  enabled: z.boolean(),
  qualifyPerTick: z.number(),
  requalifyHours: z.number(),
  suspendAfterFails: z.number(),
  curatedCountries: z.array(z.string()),
});
export type SniConfig = z.infer<typeof SniConfig>;
export const SniConfigView = z.object({ config: SniConfig });

export const SniFamilySummary = z.object({
  id: z.string(),
  slug: z.string(),
  label: z.string(),
  target: z.object({ kind: z.string(), address: z.string(), port: z.number() }).passthrough(),
  enabled: z.boolean(),
  requireH2: z.boolean(),
  bindings: z.number(),
  counts: z.object({
    total: z.number(),
    ready: z.number(),
    waiting: z.number(),
    failing: z.number(),
    suspended: z.number(),
    retired: z.number(),
    burned: z.number(),
  }),
});
export type SniFamilySummary = z.infer<typeof SniFamilySummary>;
export const SniFamilyList = z.object({ families: z.array(SniFamilySummary) });

export const SniNameRow = z.object({
  name: z.string(),
  seq: z.number(),
  status: z.enum(['active', 'suspended', 'retired', 'burned']),
  qualification: z.enum(['pending', 'ok', 'failed']),
  code: z.string().nullable(),
  tlsVersion: z.string().nullable(),
  alpn: z.string().nullable(),
  checkedAt: z.string().nullable(),
  blockedIn: z.array(z.string()),
  provenIn: z.array(z.string()),
});
export type SniNameRow = z.infer<typeof SniNameRow>;

export const SniBinding = z.object({
  id: z.string(),
  backendSlug: z.string(),
  profileUuid: z.string(),
  inboundTag: z.string(),
  generation: z.number(),
  panelConfirmedGeneration: z.number(),
  rolloutId: z.string().nullable(),
});
export type SniBinding = z.infer<typeof SniBinding>;

export const SniFamilyDetail = z.object({
  family: SniFamilySummary,
  curatedCountries: z.array(z.string()),
  names: z.array(SniNameRow),
  bindings: z.array(SniBinding),
});
export type SniFamilyDetail = z.infer<typeof SniFamilyDetail>;

export const SniImportResult = z.object({
  added: z.number(),
  lines: z.array(
    z.object({
      input: z.string(),
      name: z.string().nullable(),
      verdict: z.enum(['added', 'invalid', 'duplicate', 'burned', 'in_other_family']),
    }),
  ),
});
export type SniImportResult = z.infer<typeof SniImportResult>;

/** What the next rollout of a binding would write. Names only. */
export const SniRolloutPlan = z
  .object({
    inboundTag: z.string(),
    generation: z.number(),
    names: z.array(z.string()),
    added: z.array(z.string()),
    removed: z.array(z.string()),
    witness: z.string().nullable(),
    overflow: z.number(),
    changed: z.boolean(),
  })
  .passthrough();
export type SniRolloutPlan = z.infer<typeof SniRolloutPlan>;

export const SniRolloutStarted = z.object({
  rolloutId: z.string().nullable(),
  phase: z.string(),
  added: z.number(),
  removed: z.number(),
});

export const SniRolloutStatus = z.object({
  id: z.string(),
  generation: z.number(),
  phase: z.enum(['writing', 'panel_confirmed', 'failed', 'superseded']),
  errorCode: z.string().nullable(),
  added: z.number(),
  removed: z.number(),
  hasWitness: z.boolean(),
  nodes: z.array(
    z.object({
      relaySlug: z.string(),
      listenerKey: z.string(),
      edges: z.array(z.object({ id: z.string(), name: z.string(), status: z.string() })),
      proven: z.number(),
      pending: z.number(),
      generationProven: z.boolean(),
    }),
  ),
});
export type SniRolloutStatus = z.infer<typeof SniRolloutStatus>;

export const SniTestLink = z.object({
  receiptId: z.string(),
  link: z.string(),
  sni: z.string(),
  isWitness: z.boolean(),
});
export type SniTestLink = z.infer<typeof SniTestLink>;

export const SniReceiptConfirmed = z.object({
  ok: z.literal(true),
  activated: z.number(),
  witness: z.boolean(),
});
