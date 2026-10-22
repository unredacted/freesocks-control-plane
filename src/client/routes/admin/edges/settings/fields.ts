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
  'freedom',
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
      'On: an origin that also opted in gets its suspected edge replaced without asking. Off: suspicions only show up as attention items.',
  },
  {
    kind: 'switch',
    path: 'render.enabled',
    label: 'Render edge addresses into subscriptions',
    helper:
      'On: members of an edge-required origin receive edge addresses. Off: those members get no subscription at all, because the origin is never handed out.',
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
    label: 'Published edges per origin',
    unit: 'edges',
    helper: 'The pool size a new origin starts with. Each origin can override it.',
  },
  {
    kind: 'number',
    path: 'standbyPerRelay',
    label: 'Standbys per origin',
    unit: 'edges',
    helper: 'Ready edges kept in reserve so a replacement is instant. Each one is billed.',
  },
  {
    kind: 'number',
    path: 'standbyPerListener',
    label: 'Standbys per listener',
    unit: 'edges',
    helper:
      'Ready edges kept in reserve for each deployed listener, on top of the per-origin standbys. Automatic protection sets this to one. Each one is billed.',
  },
  {
    kind: 'number',
    path: 'cooldownMinutes',
    label: 'Cooldown between rotations',
    unit: 'min',
    helper: 'How long an origin rests after a rotation before automation may rotate it again.',
  },
  {
    kind: 'number',
    path: 'maxRotationsPerRelayPerDay',
    label: 'Rotations per origin per day',
    unit: 'per day',
    helper: 'The daily cap on automatic rotations of one origin.',
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
    'On: the control plane creates edges on its own until every origin reaches its pool size. This spends provider budget without asking. Off: you provision each edge yourself.',
};

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
      'A burned edge is known to be blocked, so it is kept only this long, for members outside the blocking country who have not refreshed yet. 0 destroys it at once.',
  },
  {
    kind: 'number',
    path: 'updateIntervalHours',
    label: 'How often apps check for a new address',
    unit: 'hours',
    helper:
      'Sent with the subscription of a protected node. Apps that honour it fetch their configuration this often, so a replaced address reaches them in time.',
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
    helper: 'What members see as the name of the first edge entry (blank: FreeSocks).',
    maxLength: 48,
  },
  {
    kind: 'text',
    path: 'render.backupLabel',
    label: 'Backup entry label',
    helper: 'The name of the second and later edge entries (blank: FreeSocks (backup)).',
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
    kind: 'number',
    path: 'render.namesPerEndpoint',
    label: 'Server names per member',
    unit: 'names',
    helper:
      'How many server names one member gets for their main address, so a blocked name does not cut them off. Only for listeners that use the growth-stable name selection.',
  },
  {
    kind: 'number',
    path: 'render.backupNames',
    label: 'Server names on the backup address',
    unit: 'names',
    helper: 'The same, for the backup address. They differ from the main ones where possible.',
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
      'Off: this family is not rendered, so its members on an edge-required origin get no subscription.',
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
    label: 'Reporters needed per origin',
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
    helper: 'An origin becomes suspected at or above this score.',
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
    path: 'detect.fleetBreakerPct',
    label: 'Fleet brake',
    unit: '%',
    helper:
      'When more than this share of the nodes looks blocked at once (and at least three do), every automatic replacement is held. 100 turns the brake off.',
  },
  {
    kind: 'number',
    path: 'detect.fleetRotationsPerDay',
    label: 'Automatic replacements per day, all nodes',
    unit: 'per day',
    helper: 'A cap across the whole fleet, on top of the cap per node. 0 = none at all.',
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
    helper: 'A suspected origin is probed this often instead.',
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
    helper: 'Applies to origin and custom targets. Edge targets follow the rendering IPv6 setting.',
  },
  {
    kind: 'number',
    path: 'probe.globalpingTestsPerHour',
    label: 'Globalping tests per hour',
    unit: 'tests per hour',
    helper:
      'Vantage points asked of Globalping per hour. A round that would pass it runs without Globalping.',
  },
];

/** Checks of every edge from each censored country (edgeCountry.ts). */
export const COUNTRY_FIELDS: Field[] = [
  {
    kind: 'switch',
    path: 'country.enabled',
    label: 'Check edges from each country',
    helper:
      'On: every round also asks a few uncensored control countries, spares are checked too, and each edge gets a result per country. Off: probes work as before.',
  },
  {
    kind: 'text',
    path: 'country.controlCountries',
    label: 'Control countries',
    maxLength: 20,
    helper:
      'Country codes, like DE US JP. One vantage each per run. They tell a blocked edge from a broken one.',
  },
  {
    kind: 'number',
    path: 'country.minProbes',
    label: 'Vantages needed',
    unit: 'vantages',
    helper: 'Fewer vantages with an answer from a country decide nothing there.',
  },
  {
    kind: 'number',
    path: 'country.minNetworks',
    label: 'Networks needed',
    unit: 'networks',
    helper: 'Those vantages must sit in at least this many networks.',
  },
  {
    kind: 'number',
    path: 'country.minControls',
    label: 'Controls that must work',
    unit: 'controls',
    helper:
      'Blocked needs this many controls to reach the edge in the same round (the control plane counts as one). Otherwise the edge is down, not blocked.',
  },
  {
    kind: 'number',
    path: 'country.blockedRounds',
    label: 'Blocked rounds before it counts',
    unit: 'rounds',
    helper: 'At least 30 minutes apart. Working again takes one round.',
  },
  {
    kind: 'number',
    path: 'country.windowDays',
    label: 'How long a result stands',
    unit: 'days',
    helper: 'Without a new decided round, a result lapses to not known after this.',
  },
  {
    kind: 'number',
    path: 'country.standbyRecheckHours',
    label: 'Spare check interval',
    unit: 'h',
    helper: 'Spares are checked from every country this often.',
  },
  {
    kind: 'number',
    path: 'country.preUseWaitMinutes',
    label: 'Wait for the first round',
    unit: 'min',
    helper:
      'A new address waits this long for its first check before a setup run or a replacement goes on. Not known never holds it.',
  },
  {
    kind: 'number',
    path: 'country.minProvenForExclusive',
    label: 'Working addresses before they are used alone',
    unit: 'addresses',
    helper:
      'When members are ordered by country: with fewer addresses known to work there, those and the not yet known ones are shared out together.',
  },
];

export const L7_FIELDS: Field[] = [
  {
    kind: 'number',
    path: 'l7.maxSameProviderReplacementsPerDay',
    label: 'Same-provider replacements per origin per day',
    unit: 'per day',
    helper:
      'A new hostname on the same CDN shares its addresses, so repeating it rarely helps. 0 forbids it.',
  },
];

const pathsOf = (fields: readonly Field[]): string[] => fields.map((f) => f.path);

/** Every flat path a section owns (the rendering section adds its family rules at runtime). */
export const SECTION_PATHS: Record<
  Exclude<SettingsSection, 'maintenance' | 'freedom'>,
  string[]
> = {
  basics: [...pathsOf(BASIC_SWITCHES), ...pathsOf(BASIC_NUMBERS), AUTO_PROVISION.path],
  rotation: pathsOf(ROTATION_FIELDS),
  rendering: pathsOf(RENDER_GLOBAL_FIELDS),
  detector: pathsOf(DETECTOR_FIELDS),
  probes: [...pathsOf(PROBE_SOURCE_FIELDS), ...pathsOf(PROBE_FIELDS), ...pathsOf(COUNTRY_FIELDS)],
  l7: pathsOf(L7_FIELDS),
};
