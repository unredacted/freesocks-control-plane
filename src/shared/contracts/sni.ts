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
  reportWindowDays: z.number(),
  /** Read only: the censored-country list (Settings, Censored countries). */
  curatedCountries: z.array(z.string()),
});
export type SniConfig = z.infer<typeof SniConfig>;

/** Checks of names from inside opted-in countries (`edge.sni.vantage.*`; docs/edges.md). */
export const SniVantageConfig = z.object({
  enabled: z.boolean(),
  /** Read only: the listed countries with "Check names from inside" on. */
  countries: z.array(z.string()),
  sources: z.object({ globalping: z.boolean(), ripeatlas: z.boolean() }),
  intervalHours: z.number(),
  hourlyBudget: z.number(),
  perCountryLimit: z.number(),
  batchNames: z.number(),
  windowDays: z.number(),
  minVantages: z.number(),
  minNetworks: z.number(),
  autoApply: z.boolean(),
});
export type SniVantageConfig = z.infer<typeof SniVantageConfig>;

export const SniConfigView = z.object({
  config: SniConfig,
  vantage: SniVantageConfig,
  /** Which sources can run now (RIPE Atlas needs its key). */
  vantageSources: z.object({ globalping: z.boolean(), ripeatlas: z.boolean() }),
});
export type SniConfigView = z.infer<typeof SniConfigView>;

/** `PATCH …/sni/config`: any subset, the vantage block nested. */
/** The countries are not patched here: they come from the censored-country list. */
export type SniConfigPatch = Partial<Omit<SniConfig, 'curatedCountries'>> & {
  vantage?: Partial<Omit<SniVantageConfig, 'sources' | 'countries'>> & {
    sources?: Partial<SniVantageConfig['sources']>;
  };
};

/** Why the checks suggest nothing (lib/edges/sni/vantage.ts `SuggestReason`). */
export const SNI_VANTAGE_REASONS = [
  'no_data',
  'not_enough_vantages',
  'not_enough_networks',
  'not_paired',
  'needs_repeat',
  'no_control',
  'mixed',
  'reports_disagree',
] as const;

/** What the checks from one country say about one name, judged now. */
export const SniVantageRow = z.object({
  country: z.string(),
  latest: z.enum(['ok', 'failing', 'mixed', 'none']),
  suggestion: z.enum(['proven', 'blocked']).nullable(),
  reason: z.enum(SNI_VANTAGE_REASONS).nullable(),
  /** Against the mark standing today: an operator's mark is never replaced. */
  decision: z.enum(['suggest', 'agrees', 'conflict', 'none']),
  okVantages: z.number(),
  okNetworks: z.number(),
  failVantages: z.number(),
  failNetworks: z.number(),
  pathFailures: z.number(),
  reportsAgree: z.boolean(),
  lastAt: z.string().nullable(),
  lastOkAt: z.string().nullable(),
  lastRequestedAt: z.string().nullable(),
});
export type SniVantageRow = z.infer<typeof SniVantageRow>;

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
  /** Curated countries where member reports single this name out. A hint, never a verdict. */
  suspectIn: z.array(z.string()),
  /** Countries whose mark was written by the checks themselves (`autoApply`), not an operator. */
  probeMarkedIn: z.array(z.string()),
  /** What the checks from inside each country say. */
  vantage: z.array(SniVantageRow),
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

/** `POST …/families/{slug}/bind`: bind a family to one REALITY transport of a backend. */
export const SniBindRequest = z.object({ backendSlug: z.string(), transportTag: z.string() });
export type SniBindRequest = z.infer<typeof SniBindRequest>;

export const SniFamilyDetail = z.object({
  family: SniFamilySummary,
  curatedCountries: z.array(z.string()),
  vantage: z.object({
    enabled: z.boolean(),
    /** Opted-in AND curated: the only countries checks run from. */
    countries: z.array(z.string()),
    autoApply: z.boolean(),
    sources: z.array(z.enum(['globalping', 'ripeatlas'])),
  }),
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

/** `POST …/families/{slug}/vantage {snis, country}`: check these names from there now. */
export const SniVantageRequested = z.object({
  batches: z.number(),
  measurements: z.number(),
  skipped: z.number(),
});
export type SniVantageRequested = z.infer<typeof SniVantageRequested>;

/** `POST …/families/{slug}/vantage/apply {snis, country}`: record the current suggestions. */
export const SniVantageApplied = z.object({
  proven: z.number(),
  blocked: z.number(),
  skipped: z.number(),
});
export type SniVantageApplied = z.infer<typeof SniVantageApplied>;
