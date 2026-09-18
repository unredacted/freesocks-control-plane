/**
 * The settings page as data: which knob lives in which section, its label, unit
 * and one line of consequence. Every flat path of the `edge.*` namespace appears
 * in exactly ONE section (pinned by settings.test.ts) so a per-section save is
 * unambiguous. Bounds and defaults are NOT here: they come from the server
 * (`EdgeConfigView.bounds` / `.defaults`).
 */
export const SETTINGS_SECTIONS = [
  'basics',
  'rotation',
  'rendering',
  'detector',
  'probes',
  'l7',
  'maintenance',
] as const;
export type SettingsSection = (typeof SETTINGS_SECTIONS)[number];
export const parseSection = (raw: string | null | undefined): SettingsSection =>
  (SETTINGS_SECTIONS as readonly string[]).includes(raw ?? '')
    ? (raw as SettingsSection)
    : 'basics';

export type Field =
  | { kind: 'switch'; path: string; label: string; helper: string }
  | { kind: 'number'; path: string; label: string; helper: string; unit?: string; step?: number }
  | {
      kind: 'select';
      path: string;
      label: string;
      helper: string;
      options: ReadonlyArray<{ value: string; label: string }>;
    }
  | { kind: 'text'; path: string; label: string; helper: string; maxLength: number };

export const BASIC_SWITCHES: Field[] = [
  {
    kind: 'switch',
    path: 'enabled',
    label: 'Edge automation',
    helper:
      'On: the block detector runs and automatic actions are allowed. Off: nothing happens unless you start it by hand.',
  },
  {
    kind: 'switch',
    path: 'autoRotate',
    label: 'Automatic rotation',
    helper:
      'On: a relay that also opted in gets its suspected edge replaced without asking. Off: suspicions only show up as attention items.',
  },
  {
    kind: 'switch',
    path: 'render.enabled',
    label: 'Render edge addresses into subscriptions',
    helper:
      'On: members of an edge-required relay receive edge addresses. Off: those members get no subscription at all, because the origin is never handed out.',
  },
  {
    kind: 'switch',
    path: 'probe.enabled',
    label: 'Reachability probes',
    helper:
      'On: published addresses are checked from the watched countries on a schedule. Off: the detector only has member reports to go on.',
  },
  {
    kind: 'switch',
    path: 'l7.autoSelect',
    label: 'Let automation pick CDN fronts',
    helper:
      'On: automatic replacements and auto-provisioning may choose an L7 account. Off: L7 edges are only created when you ask for one.',
  },
];

export const BASIC_NUMBERS: Field[] = [
  {
    kind: 'number',
    path: 'desiredPublishedDefault',
    label: 'Published edges per relay',
    unit: 'edges',
    helper: 'The pool size a new relay starts with. Each relay can override it.',
  },
  {
    kind: 'number',
    path: 'standbyPerRelay',
    label: 'Standbys per relay',
    unit: 'edges',
    helper: 'Ready edges kept in reserve so a replacement is instant. Each one is billed.',
  },
  {
    kind: 'number',
    path: 'cooldownMinutes',
    label: 'Cooldown between rotations',
    unit: 'min',
    helper: 'How long a relay rests after a rotation before automation may rotate it again.',
  },
  {
    kind: 'number',
    path: 'maxRotationsPerRelayPerDay',
    label: 'Rotations per relay per day',
    unit: 'per day',
    helper: 'The daily cap on automatic rotations of one relay.',
  },
  {
    kind: 'number',
    path: 'drainMinutes',
    label: 'Drain time',
    unit: 'min',
    helper:
      'How long a replaced edge keeps serving connected members before it is destroyed. It is billed while it drains.',
  },
];

export const AUTO_PROVISION: Field = {
  kind: 'switch',
  path: 'autoProvisionToDesired',
  label: 'Provision up to the desired pool size automatically',
  helper:
    'On: the control plane creates edges on its own until every relay reaches its pool size. This spends provider budget without asking. Off: you provision each edge yourself.',
};

/**
 * Server config keys deliberately NOT offered: `providerAffinity` is sanitized and
 * stored but no selection path reads it (docs/edges.md), so a control for it
 * would be a switch that changes nothing.
 */
export const UNEXPOSED_PATHS: readonly string[] = ['providerAffinity'];

export const ROTATION_FIELDS: Field[] = [
  {
    kind: 'switch',
    path: 'autoPublishStandby',
    label: 'Publish a standby when a pool slot is empty',
    helper: 'On: a ready standby fills a missing slot on its own. Off: you publish it by hand.',
  },
  {
    kind: 'switch',
    path: 'requireProviderHealth',
    label: 'Wait for the provider health check',
    helper:
      'On: an edge is only verified once the provider reports its origin member healthy (where the provider can tell). Off: a successful connect is enough.',
  },
  {
    kind: 'switch',
    path: 'refreshMirrorsAfterFlip',
    label: 'Refresh stored mirrors after a publish',
    helper:
      'On: mirrored subscription copies are rebuilt right after the pool changes. Off: they catch up on the next scheduled refresh.',
  },
  {
    kind: 'number',
    path: 'burnedDrainMinutes',
    label: 'Drain time of a burned edge',
    unit: 'min',
    helper:
      'A burned edge is known to be blocked, so it is kept only this long. 0 destroys it at once.',
  },
  {
    kind: 'number',
    path: 'sniDrainMinutes',
    label: 'Drain time of a retired server name',
    unit: 'min',
    helper: 'How long a retired name stays valid on the origin for members who still hold it.',
  },
  {
    kind: 'number',
    path: 'maxConcurrentRotations',
    label: 'Rotations running at once',
    unit: 'runs',
    helper: 'Fleet-wide limit. Further rotations are refused until one finishes.',
  },
  {
    kind: 'number',
    path: 'maxReconcileStartsPerTick',
    label: 'Automatic starts per reconcile pass',
    unit: 'runs',
    helper: 'How many runs the reconcile job may start each pass. 0 stops it from starting any.',
  },
  {
    kind: 'number',
    path: 'provisionTimeoutMinutes',
    label: 'Provisioning timeout',
    unit: 'min',
    helper: 'How long to wait for the provider to build an edge before the run fails.',
  },
  {
    kind: 'number',
    path: 'discoveryTimeoutMinutes',
    label: 'Discovery timeout',
    unit: 'min',
    helper: 'How long to look for a resource whose create call was cut off before giving up on it.',
  },
  {
    kind: 'number',
    path: 'maxRotationMinutes',
    label: 'Longest rotation run',
    unit: 'min',
    helper: 'Past this a run rolls back, or quarantines the relay if it cannot.',
  },
  {
    kind: 'number',
    path: 'pollSeconds',
    label: 'Poll interval',
    unit: 's',
    helper: 'How often a running rotation checks the provider.',
  },
  {
    kind: 'number',
    path: 'settleGraceSeconds',
    label: 'Settle time',
    unit: 's',
    helper: 'Pause after the provider reports ready, before the first verification.',
  },
  {
    kind: 'number',
    path: 'opClaimSeconds',
    label: 'Operation claim',
    unit: 's',
    helper: 'How long one step holds its claim before another worker may retry it.',
  },
  {
    kind: 'number',
    path: 'verifyAttempts',
    label: 'Verification attempts',
    unit: 'tries',
    helper: 'Connect checks against a new edge before the run gives up on it.',
  },
  {
    kind: 'number',
    path: 'maxFlipAttempts',
    label: 'Publish attempts',
    unit: 'tries',
    helper: 'Tries to write the new address to the panel before rolling back.',
  },
  {
    kind: 'number',
    path: 'maxRollbackAttempts',
    label: 'Rollback attempts',
    unit: 'tries',
    helper: 'Tries to restore the previous state before the relay is quarantined.',
  },
  {
    kind: 'number',
    path: 'maxDestroyAttempts',
    label: 'Destroy attempts',
    unit: 'tries',
    helper: 'Tries to delete a provider resource before the edge is left for you to decide.',
  },
];

const IPV6_GLOBAL = [
  { value: 'both', label: 'IPv4 and IPv6 entries' },
  { value: 'auto-group-only', label: 'IPv6 only inside the automatic group' },
  { value: 'off', label: 'No IPv6 entries' },
] as const;

export const RENDER_GLOBAL_FIELDS: Field[] = [
  {
    kind: 'text',
    path: 'render.primaryLabel',
    label: 'Primary entry label',
    helper: 'What members see as the name of the first edge entry.',
    maxLength: 48,
  },
  {
    kind: 'text',
    path: 'render.backupLabel',
    label: 'Backup entry label',
    helper: 'The name of the second and later edge entries.',
    maxLength: 48,
  },
  {
    kind: 'text',
    path: 'render.autoGroupName',
    label: 'Automatic group name',
    helper: 'The group that picks the fastest entry, in clients that support one.',
    maxLength: 48,
  },
  {
    kind: 'text',
    path: 'render.ipv6Label',
    label: 'IPv6 suffix',
    helper: 'Added to the label of an IPv6 entry.',
    maxLength: 24,
  },
  {
    kind: 'select',
    path: 'render.ipv6Mode',
    label: 'IPv6 entries',
    helper: 'Whether members receive the IPv6 address of an edge next to the IPv4 one.',
    options: IPV6_GLOBAL,
  },
  {
    kind: 'switch',
    path: 'render.preferDistinctProviders',
    label: 'Spread a member across providers',
    helper:
      'On: the primary and backup entries of one member come from different providers when the pool allows. Off: assignment ignores the provider.',
  },
];

/** Per-family rule fields (keys of `ClientRenderRule`). */
export type RuleField =
  | { kind: 'switch'; key: string; label: string; helper: string }
  | { kind: 'number'; key: string; label: string; helper: string; unit?: string }
  | { kind: 'text'; key: string; label: string; helper: string; maxLength: number }
  | {
      kind: 'select';
      key: string;
      label: string;
      helper: string;
      options: ReadonlyArray<{ value: string; label: string }>;
    };

export const RULE_FIELDS: RuleField[] = [
  {
    kind: 'switch',
    key: 'enabled',
    label: 'Render for this client family',
    helper:
      'Off: this family is not rendered, so its members on an edge-required relay get no subscription.',
  },
  {
    kind: 'switch',
    key: 'includeBackup',
    label: 'Include backup entries',
    helper: 'Off: only the primary edge is handed out.',
  },
  {
    kind: 'switch',
    key: 'autoGroup',
    label: 'Add an automatic group',
    helper: 'Only has an effect in formats that have groups.',
  },
  {
    kind: 'switch',
    key: 'dropTemplateEntries',
    label: 'Drop the origin entries of the template',
    helper: 'On: the entry that points at the origin never reaches the member.',
  },
  {
    kind: 'number',
    key: 'maxEntries',
    label: 'Most entries',
    unit: 'entries',
    helper: '0 means no limit.',
  },
  {
    kind: 'select',
    key: 'order',
    label: 'Entry order',
    helper: 'Which entry a client lists first.',
    options: [
      { value: 'primary-first', label: 'Primary first' },
      { value: 'backup-first', label: 'Backup first' },
    ],
  },
  {
    kind: 'select',
    key: 'ipv6Mode',
    label: 'IPv6 entries',
    helper: 'Follow the fleet setting or override it for this family.',
    options: [{ value: 'inherit', label: 'Follow the fleet setting' }, ...IPV6_GLOBAL],
  },
  {
    kind: 'text',
    key: 'primaryLabel',
    label: 'Primary entry label',
    helper: 'Empty uses the fleet label.',
    maxLength: 48,
  },
  {
    kind: 'text',
    key: 'backupLabel',
    label: 'Backup entry label',
    helper: 'Empty uses the fleet label.',
    maxLength: 48,
  },
  {
    kind: 'text',
    key: 'autoGroupName',
    label: 'Automatic group name',
    helper: 'Empty uses the fleet name.',
    maxLength: 48,
  },
];

export const FAMILY_LABELS: Record<string, string> = {
  singbox: 'sing-box clients',
  mihomo: 'Mihomo and Clash clients',
  'xray-links': 'Xray link lists',
  happ: 'Happ',
  hiddify: 'Hiddify',
  streisand: 'Streisand',
  v2rayng: 'v2rayNG',
  other: 'Every other client',
};
export const familyLabel = (family: string): string => FAMILY_LABELS[family] ?? family;
export const rulePath = (family: string): string => `render.clients.${family}`;

export const DETECTOR_FIELDS: Field[] = [
  {
    kind: 'number',
    path: 'detect.windowMinutes',
    label: 'Evaluation window',
    unit: 'min',
    helper: 'Member reports newer than this count toward a suspicion.',
  },
  {
    kind: 'number',
    path: 'detect.minReporters',
    label: 'Reporters needed per relay',
    unit: 'members',
    helper: 'Distinct members that must report before reports can raise a suspicion.',
  },
  {
    kind: 'number',
    path: 'detect.minEdgeReporters',
    label: 'Reporters needed per edge',
    unit: 'members',
    helper: 'Distinct members on one edge before that edge is named as the blocked one.',
  },
  {
    kind: 'number',
    path: 'detect.spikeFactor',
    label: 'Report spike factor',
    unit: 'x',
    step: 0.5,
    helper: 'How many times the usual report rate counts as a spike.',
  },
  {
    kind: 'number',
    path: 'detect.loadDropPct',
    label: 'Load drop',
    unit: '%',
    helper: 'The fall in connected users, against the same time of day, that corroborates a block.',
  },
  {
    kind: 'number',
    path: 'detect.minLoadUsers',
    label: 'Users needed for a load signal',
    unit: 'users',
    helper: 'Below this baseline a load drop is noise and is ignored.',
  },
  {
    kind: 'switch',
    path: 'detect.requireLoadCorroboration',
    label: 'Reports need a load drop to act',
    helper:
      'On: member reports alone never rotate an edge. Off: a report spike is enough on its own.',
  },
  {
    kind: 'number',
    path: 'detect.staleWeight',
    label: 'Weight of a stale report',
    step: 0.05,
    helper: 'A report from a member whose subscription predates the current pool counts this much.',
  },
  {
    kind: 'number',
    path: 'detect.probeWeight',
    label: 'Weight of probe evidence',
    step: 0.05,
    helper: 'How much a reachable to unreachable change in a country adds to the score.',
  },
  {
    kind: 'switch',
    path: 'detect.allowProbeOnlyAutoRotate',
    label: 'Probes alone may rotate',
    helper:
      'On: agreeing probes can trigger an automatic rotation without any member report. Off: probes can only suspect.',
  },
  {
    kind: 'number',
    path: 'detect.suspectAt',
    label: 'Suspect at score',
    step: 0.05,
    helper: 'A relay becomes suspected at or above this score.',
  },
  {
    kind: 'number',
    path: 'detect.clearBelow',
    label: 'Clear below score',
    step: 0.05,
    helper:
      'A suspicion starts clearing under this score. The server keeps it at least 0.05 under the suspect score.',
  },
  {
    kind: 'number',
    path: 'detect.clearAfterEvals',
    label: 'Quiet evaluations to clear',
    unit: 'evaluations',
    helper: 'Consecutive low scores before a suspicion is dropped.',
  },
  {
    kind: 'number',
    path: 'detect.minBaselineSamples',
    label: 'Baseline samples',
    unit: 'samples',
    helper:
      'Load samples needed before the baseline is trusted. Until then load cannot corroborate.',
  },
  {
    kind: 'number',
    path: 'detect.maxReportRowsPerEval',
    label: 'Reports read per evaluation',
    unit: 'rows',
    helper: 'Past this the window is treated as incomplete and nothing is rotated.',
  },
];

export const PROBE_SOURCE_FIELDS: Field[] = [
  {
    kind: 'switch',
    path: 'probe.sources.globalping',
    label: 'Globalping',
    helper: 'Community vantage points. A token raises the free allowance.',
  },
  {
    kind: 'switch',
    path: 'probe.sources.checkhost',
    label: 'check-host',
    helper: 'A second public network of vantage points, no credential needed.',
  },
  {
    kind: 'switch',
    path: 'probe.sources.ripeatlas',
    label: 'RIPE Atlas',
    helper: 'Needs an API key with credits. Measurements are created private.',
  },
  {
    kind: 'switch',
    path: 'probe.sources.internal',
    label: 'Internal connect check',
    helper:
      'A connect from the control plane itself. Proves the edge is up, not that a country can reach it.',
  },
];

export const PROBE_FIELDS: Field[] = [
  {
    kind: 'number',
    path: 'probe.intervalMinutes',
    label: 'Probe interval',
    unit: 'min',
    helper: 'How often every published edge is probed.',
  },
  {
    kind: 'number',
    path: 'probe.suspectedIntervalMinutes',
    label: 'Interval while suspected',
    unit: 'min',
    helper: 'A suspected relay is probed this often instead.',
  },
  {
    kind: 'number',
    path: 'probe.perCountryLimit',
    label: 'Vantage points per country',
    unit: 'vantages',
    helper: 'How many vantage points one run asks for in each country.',
  },
  {
    kind: 'number',
    path: 'probe.agreementVantages',
    label: 'Vantages that must agree',
    unit: 'vantages',
    helper: 'Distinct networks that must fail before a country counts as unreachable.',
  },
  {
    kind: 'number',
    path: 'probe.hourlyBudget',
    label: 'Hourly budget',
    unit: 'runs per hour',
    helper: 'External probe runs allowed per hour. 0 stops external probing.',
  },
  {
    kind: 'number',
    path: 'probe.sourceSpacingMs',
    label: 'Spacing between runs on one source',
    unit: 'ms',
    helper: 'Keeps a batch from hitting the rate limit of a probe network.',
  },
  {
    kind: 'switch',
    path: 'probe.preferEyeball',
    label: 'Prefer residential networks',
    helper:
      'On: vantage points on consumer networks are asked for first, where the source can tell.',
  },
  {
    kind: 'switch',
    path: 'probe.ipv6',
    label: 'Probe IPv6 paths',
    helper: 'Applies to relay and custom targets. Edge targets follow the rendering IPv6 setting.',
  },
];
export const PROBE_COUNTRIES_PATH = 'probe.countries';

export const L7_FIELDS: Field[] = [
  {
    kind: 'number',
    path: 'l7.maxSameProviderReplacementsPerDay',
    label: 'Same-provider replacements per relay per day',
    unit: 'per day',
    helper:
      'A new hostname on the same CDN shares its addresses, so repeating it rarely helps. 0 forbids it.',
  },
  {
    kind: 'number',
    path: 'l7.qualifyTimeoutMinutes',
    label: 'Evidence wait for an automatic replacement',
    unit: 'min',
    helper: 'How long to wait for proof from the affected country before the run gives up.',
  },
  {
    kind: 'number',
    path: 'l7.qualifyStepTimeoutMs',
    label: 'Qualification step timeout',
    unit: 'ms',
    helper: 'Each step of the authenticated session through the front must finish within this.',
  },
  {
    kind: 'number',
    path: 'l7.qualificationTtlMinutes',
    label: 'Qualification lifetime',
    unit: 'min',
    helper:
      'A front is proven again before this runs out. An expired proof removes it from rendering.',
  },
  {
    kind: 'number',
    path: 'l7.maxRequalifyPerTick',
    label: 'Re-proofs per reconcile pass',
    unit: 'fronts',
    helper: 'Each proof is an outbound session, so the pass is capped.',
  },
];

const pathsOf = (fields: readonly Field[]): string[] => fields.map((f) => f.path);

/** Every flat path a section owns (the rendering section adds its family rules at runtime). */
export const SECTION_PATHS: Record<Exclude<SettingsSection, 'maintenance'>, string[]> = {
  basics: [...pathsOf(BASIC_SWITCHES), ...pathsOf(BASIC_NUMBERS), AUTO_PROVISION.path],
  rotation: pathsOf(ROTATION_FIELDS),
  rendering: pathsOf(RENDER_GLOBAL_FIELDS),
  detector: pathsOf(DETECTOR_FIELDS),
  probes: [...pathsOf(PROBE_SOURCE_FIELDS), ...pathsOf(PROBE_FIELDS), PROBE_COUNTRIES_PATH],
  l7: pathsOf(L7_FIELDS),
};
