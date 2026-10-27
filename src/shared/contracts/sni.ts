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
  /** Real-host controls: each name also checked against its real site from the same vantages. */
  realHost: z.boolean().default(false),
});
export type SniVantageConfig = z.infer<typeof SniVantageConfig>;

/** Finding names (`edge.sni.hunt.*`; docs/edges.md "Finding names"). */
export const SniHuntConfig = z.object({
  enabled: z.boolean(),
  depth: z.number(),
  wwwDepth: z.number(),
  lookupsPerSecond: z.number(),
  sweepEveryDays: z.number(),
  checksPerTick: z.number(),
  recheckHours: z.number(),
  shortlist: z.number(),
  ctRequestsPerHour: z.number(),
  ctPagesPerDomain: z.number(),
  timingPerHour: z.number(),
});
export type SniHuntConfig = z.infer<typeof SniHuntConfig>;

export const SniConfigView = z.object({
  config: SniConfig,
  vantage: SniVantageConfig,
  hunt: SniHuntConfig.optional(),
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
  hunt?: Partial<SniHuntConfig>;
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
  /** The network the target and every name live on (docs/edges.md "Networks"); null = anywhere. */
  network: z
    .object({ slug: z.string(), label: z.string(), ranges: z.number() })
    .nullable()
    .default(null),
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

/** Where a name stands on its way to members (`convex/lib/edges/sni/delivery.ts`). */
export const SNI_DELIVERY = [
  'in_use',
  'waiting_test',
  'to_send',
  'idle',
  'checking',
  'failing',
  'off',
] as const;
export const SniNameDelivery = z.object({
  state: z.enum(SNI_DELIVERY),
  /** On how many nodes members are handed it. */
  inUseOn: z.number(),
  /** How many protected nodes its transports have. */
  nodes: z.number(),
});
export type SniNameDelivery = z.infer<typeof SniNameDelivery>;

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
  /** Where it stands on its way to members, across the family's transports. */
  delivery: SniNameDelivery.default({ state: 'idle', inUseOn: 0, nodes: 0 }),
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
export const SniBindRequest = z.object({
  backendSlug: z.string(),
  transportTag: z.string(),
  /** The exact transport (a tag is unique per profile only). */
  transportUuid: z.string().optional(),
  /**
   * Take the names the transport lists now into the family: a transport whose
   * names were set by hand (a node FCP does not manage, an adopted node).
   */
  takeNames: z.boolean().optional(),
});
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
  /** Found names it may add (usable, `usableCandidate`): the overview's number. */
  suggestions: z.number().default(0),
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

/** `POST families/{slug}/bind`: the binding, and with `takeNames` what became of each name. */
export const SniBindResult = z.object({ id: z.string(), imported: SniImportResult.optional() });
export type SniBindResult = z.infer<typeof SniBindResult>;

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

/**
 * `GET /api/v1/admin/edges/networks` (docs/edges.md "Networks"): one or more
 * ASNs and the ranges they announce, plus ranges entered by hand. Counts only:
 * the ranges themselves never leave the server.
 */
export const EdgeNetworkView = z.object({
  id: z.string(),
  slug: z.string(),
  label: z.string(),
  asns: z.array(z.number()),
  manualPrefixes: z.array(z.string()),
  ranges: z.object({ v4: z.number(), v6: z.number() }),
  truncated: z.boolean(),
  refreshedAt: z.string().nullable(),
  /** The last refresh's failure (a short code); the stored ranges stay. */
  refreshError: z.string().nullable(),
  /** Finding names on it, and where its nodes are (a place name, never an address). */
  hunt: z
    .object({
      enabled: z.boolean(),
      place: z.object({ country: z.string(), city: z.string().optional() }).nullable(),
    })
    .optional(),
  families: z.array(z.object({ slug: z.string(), label: z.string() })),
  locations: z.array(
    z.object({
      id: z.string(),
      label: z.string(),
      provider: z.string(),
      /** Set by an operator, or learned from its addresses. */
      source: z.enum(['operator', 'address']),
    }),
  ),
});
export type EdgeNetworkView = z.infer<typeof EdgeNetworkView>;
export const EdgeNetworkList = z.object({ networks: z.array(EdgeNetworkView) });
export type EdgeNetworkList = z.infer<typeof EdgeNetworkList>;

/** `POST networks` / `PATCH networks/{slug}`. */
export const EdgeNetworkWrite = z.object({
  slug: z.string().optional(),
  label: z.string().optional(),
  asns: z.array(z.union([z.number(), z.string()])).optional(),
  manualPrefixes: z.array(z.string()).optional(),
});
export type EdgeNetworkWrite = z.infer<typeof EdgeNetworkWrite>;

/** `POST networks/{slug}/refresh`. */
export const EdgeNetworkRefreshed = z.object({ refreshed: z.number(), failed: z.number() });

// --- finding names (docs/edges.md "Finding names") --------------------------------------------------

export const HuntPlace = z.object({ country: z.string(), city: z.string().optional() });
export type HuntPlace = z.infer<typeof HuntPlace>;

export const HUNT_SOURCES = ['cert', 'seed', 'pasted', 'toplist', 'ct'] as const;
export const HUNT_STATES = ['new', 'added', 'ignored', 'gone', 'failing'] as const;

/**
 * Usable: a found name still to decide (not ignored, added, gone or failing)
 * whose last check gave qualification's pass. The ONE definition every count,
 * filter and list of found names uses, on the server and on the page.
 */
export function usableCandidate(c: {
  state: string;
  check?: { code: string | null } | null;
}): boolean {
  return c.state === 'new' && !!c.check && c.check.code === null;
}

/** A scope's counts: how many it holds, and how many are usable (`usableCandidate`). */
export const HuntCounts = z.object({ total: z.number(), ready: z.number() });

/** `GET sni/hunt`. */
export const SniHuntOverview = z.object({
  config: SniHuntConfig,
  sweep: z
    .object({
      state: z.enum(['downloading', 'running', 'done', 'failed', 'cancelled']),
      listDate: z.string().nullable(),
      depth: z.number(),
      wwwDepth: z.number(),
      total: z.number(),
      cursor: z.number(),
      hits: z.number(),
      lookups: z.number(),
      error: z.string().nullable(),
      startedAt: z.string(),
      finishedAt: z.string().nullable(),
    })
    .nullable(),
  networks: z.array(
    z.object({
      slug: z.string(),
      label: z.string(),
      hunt: z.object({
        enabled: z.boolean(),
        place: HuntPlace.nullable(),
        /** `node`: taken from a node's location when one of its transports was managed. */
        placeFrom: z.literal('node').nullable().default(null),
      }),
      ranges: z.object({ v4: z.number(), v6: z.number() }),
      candidates: HuntCounts,
    }),
  ),
  families: z.array(z.object({ slug: z.string(), label: z.string(), candidates: HuntCounts })),
});
export type SniHuntOverview = z.infer<typeof SniHuntOverview>;

export const HuntTiming = z.object({
  at: z.string(),
  place: z.string(),
  endpoint: z.string(),
  port: z.number(),
  connectMs: z.number(),
  tlsMs: z.number().nullable(),
  probes: z.number(),
});
export const HuntOoni = z.object({
  cc: z.string(),
  status: z.enum(['ok', 'mixed', 'likely_blocked', 'blocked', 'thin', 'no_data']),
  measurements: z.number(),
});

export const SniCandidateRow = z.object({
  id: z.string(),
  name: z.string(),
  site: z.string(),
  sources: z.array(z.enum(HUNT_SOURCES)),
  rank: z.number().nullable(),
  state: z.enum(HUNT_STATES),
  /** The family that holds it now (an added candidate). */
  inFamily: z.object({ slug: z.string(), label: z.string() }).nullable(),
  /** Qualification's verdict (`code` null = it would qualify) and its answers. */
  check: z
    .object({
      at: z.string(),
      code: z.string().nullable(),
      tlsVersion: z.string().nullable(),
      alpn: z.string().nullable(),
      answers: z.object({
        v4: z.number(),
        v6: z.number(),
        onNetwork: z.enum(['all', 'some', 'none', 'unknown']),
      }),
      shown: z.array(z.string()),
      dialled: z.string().nullable().default(null),
      port: z.number().nullable().default(null),
    })
    .nullable(),
  extra: z
    .object({
      x25519: z.boolean().nullable(),
      mlkem: z.boolean().nullable(),
      error: z.string().nullable(),
    })
    .nullable(),
  passes: z.number(),
  baseScore: z.number(),
  score: z.number(),
  parts: z
    .object({
      popularity: z.number(),
      cluster: z.number(),
      tls: z.number(),
      stability: z.number(),
      near: z.number().nullable(),
      country: z.number().nullable(),
      penalty: z.number(),
    })
    .nullable(),
  /** On the shortlist that gets evidence. */
  listed: z.boolean().default(false),
  /** From probes at the network's place to the address REALITY would relay to (scored). */
  timing: HuntTiming.nullable().default(null),
  /** A family candidate's own site, from the same place (shown only). */
  own: HuntTiming.nullable().default(null),
  ooni: z
    .object({ at: z.string(), exact: z.array(HuntOoni), site: z.array(HuntOoni) })
    .nullable()
    .default(null),
  countries: z
    .array(
      z.object({
        cc: z.string(),
        at: z.string(),
        reading: z.enum(['ok', 'interference', 'inconclusive', 'path']),
        vantages: z.number(),
        networks: z.number(),
        singled: z.number(),
      }),
    )
    .default([]),
  firstSeenAt: z.string(),
});
export type SniCandidateRow = z.infer<typeof SniCandidateRow>;

export const SniHuntCtRow = z.object({
  domain: z.string(),
  state: z.enum(['partial', 'complete', 'truncated', 'rate_limited', 'error']),
  pages: z.number(),
  names: z.number(),
  error: z.string().nullable(),
  backoffUntil: z.string().nullable(),
  completedAt: z.string().nullable(),
});
export type SniHuntCtRow = z.infer<typeof SniHuntCtRow>;

/** `GET sni/hunt/networks/{slug}` and `GET sni/hunt/families/{slug}`. */
export const SniHuntScopeView = z.object({
  scope: z.object({
    kind: z.enum(['network', 'family']),
    slug: z.string(),
    label: z.string(),
    network: z.object({ slug: z.string(), label: z.string() }).nullable(),
    target: z.object({ address: z.string(), port: z.number() }).nullable(),
    hunt: z.object({ enabled: z.boolean(), place: HuntPlace.nullable() }).nullable(),
  }),
  /** One page of one state's candidates, best first (`?state=`, `?cursor=`). */
  candidates: z.array(SniCandidateRow),
  page: z
    .object({ cursor: z.string().nullable(), done: z.boolean() })
    .default({ cursor: null, done: true }),
  /** Candidates by the first address they live on: a possible target and its names. */
  groups: z.array(
    z.object({ address: z.string(), names: z.number(), passing: z.number(), best: z.string() }),
  ),
  counts: z.object({
    new: z.number(),
    failing: z.number(),
    gone: z.number(),
    ignored: z.number(),
    added: z.number(),
    unchecked: z.number(),
    /** `usableCandidate`: the same number the overview shows for this scope. */
    usable: z.number().default(0),
  }),
  /**
   * A network's page: what was found for the families on it (each checked
   * against its family's target, so never mixed into this network's own sites).
   */
  families: z
    .array(z.object({ slug: z.string(), label: z.string(), candidates: HuntCounts }))
    .default([]),
  ct: z.array(SniHuntCtRow),
});
export type SniHuntScopeView = z.infer<typeof SniHuntScopeView>;

const Tally = {
  added: z.number(),
  known: z.number(),
  ignored: z.number(),
  inFamily: z.number(),
  invalid: z.number(),
  capped: z.number(),
};

/** `POST sni/hunt/import`: what happened to the lines, and what a seed describes that FCP lacks. */
export const SniHuntImported = z.object({
  ...Tally,
  proposals: z.object({
    networks: z.array(z.object({ slug: z.string(), label: z.string(), asns: z.array(z.number()) })),
    families: z.array(
      z.object({
        slug: z.string(),
        label: z.string(),
        targetAddress: z.string(),
        targetPort: z.number(),
        requireH2: z.boolean(),
        network: z.string(),
        names: z.array(z.string()),
      }),
    ),
  }),
});
export type SniHuntImported = z.infer<typeof SniHuntImported>;

/** `POST sni/hunt/families/{slug}/cert`. */
export const SniHuntCertRead = z.union([
  z.object({ ok: z.literal(true), listed: z.number(), ...Tally }),
  z.object({ ok: z.literal(false), code: z.string().nullable().optional() }),
]);
export type SniHuntCertRead = z.infer<typeof SniHuntCertRead>;

export const SniHuntCtQueued = z.object({ queued: z.number(), cached: z.number() });
export const SniHuntChanged = z.object({ changed: z.number() });

// --- a transport's names (docs/edges.md "A transport's names") ---------------------------------------

export const SniDeliveryCounts = z.object({
  inUse: z.number(),
  waitingTest: z.number(),
  toSend: z.number(),
  idle: z.number(),
  checking: z.number(),
  failing: z.number(),
  off: z.number(),
});
export type SniDeliveryCounts = z.infer<typeof SniDeliveryCounts>;

export const SniTransportNode = z.object({
  relaySlug: z.string(),
  nodeUuid: z.string().nullable(),
  nodeName: z.string(),
  /** Usable names its members are handed. */
  inUse: z.number(),
  /** Usable names on the backend in the newest confirmed rollout, not handed out here yet. */
  waitingTest: z.number(),
  /** Addresses a test link can go through (a current endpoint confirmation). */
  testable: z.array(z.object({ edgeId: z.string(), name: z.string() })),
});
export type SniTransportNode = z.infer<typeof SniTransportNode>;

export const SniTransport = z.object({
  transportUuid: z.string(),
  tag: z.string(),
  profileUuid: z.string(),
  profileName: z.string(),
  port: z.number().nullable(),
  /** The transport's REALITY target, `host:port`, as Servers last read it. */
  coverSite: z.string().nullable(),
  /** How many names the transport lists on the backend. */
  listed: z.number(),
  /** The backend nodes running its profile (they share its names). */
  profileNodes: z.array(z.object({ nodeUuid: z.string(), name: z.string() })),
  /** The family FCP manages its names with; null: set by hand. */
  list: z
    .object({
      slug: z.string(),
      label: z.string(),
      enabled: z.boolean(),
      bindingId: z.string(),
      counts: SniDeliveryCounts,
      /** Found names it may add: checked against its target, not added or ignored. */
      suggestions: z.number(),
    })
    .nullable(),
  /** The newest rollout to the backend. */
  send: z
    .object({
      rolloutId: z.string(),
      generation: z.number(),
      phase: z.enum(['writing', 'panel_confirmed', 'failed', 'superseded']),
    })
    .nullable(),
  /** Each protected node behind it (one per listener). */
  nodes: z.array(SniTransportNode),
  /** Families with the same target that no transport uses (not managed only). */
  sameCoverSite: z.array(z.object({ slug: z.string(), label: z.string(), names: z.number() })),
});
export type SniTransport = z.infer<typeof SniTransport>;

/** `GET sni/transports?backend=<slug>`. */
export const SniTransportsView = z.object({
  switches: z.object({
    /** `edge.sni.enabled` */
    names: z.boolean(),
    /** `edge.sni.hunt.enabled` */
    findNames: z.boolean(),
    /** `servers.manage.enabled`: a rollout writes the backend through it. */
    backendChanges: z.boolean(),
    /** The backend is set up (or adopted): writes to it are accepted. */
    backendSetUp: z.boolean(),
  }),
  transports: z.array(SniTransport),
});
export type SniTransportsView = z.infer<typeof SniTransportsView>;

/** `POST sni/transports/manage`. */
export const SniManageRequest = z.object({
  backendSlug: z.string().min(1),
  transportUuid: z.string().min(1),
  /** Only work out the suggestions (the network); nothing is written. */
  dryRun: z.boolean().optional(),
  /** An existing family with the same target, instead of a new one. */
  family: z.string().min(1).optional(),
  network: z.string().min(1).nullable().optional(),
  label: z.string().max(80).optional(),
  requireH2: z.boolean().optional(),
});
export type SniManageRequest = z.infer<typeof SniManageRequest>;

export const SniManageDryRun = z.object({
  dryRun: z.literal(true),
  coverSite: z.string(),
  /** The target resolved to public addresses (a network can only be suggested then). */
  resolved: z.boolean(),
  /** The one network holding the target and every address in use on the transport. */
  network: z.object({ slug: z.string(), label: z.string() }).nullable(),
  label: z.string(),
});
export type SniManageDryRun = z.infer<typeof SniManageDryRun>;

export const SniManaged = z.object({
  dryRun: z.literal(false),
  family: z.string(),
  created: z.boolean(),
  bindingId: z.string(),
  imported: SniImportResult,
  /** The network's place for timing checks was taken from the node. */
  placeSet: z.boolean(),
  /** With finding names on: the target's certificate was read for suggestions. */
  cert: SniHuntCertRead.nullable(),
});
export type SniManaged = z.infer<typeof SniManaged>;
