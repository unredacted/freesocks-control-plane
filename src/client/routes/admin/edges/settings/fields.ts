/**
 * The settings page as data: which knob lives in which group, its label, unit,
 * one line of consequence, and extra words a search should find it by. Every
 * flat path of the `edge.*` namespace appears in exactly ONE group (pinned by
 * settings.test.ts) so a per-group save is unambiguous. Bounds and defaults
 * are NOT here: they come from the server (`EdgeConfigView.bounds` /
 * `.defaults`). The groups themselves are in ./groups.ts; the search over this
 * catalog is ./search.ts.
 */
import type { SettingsGroupId } from './groups';

type FieldCopy = {
  path: string;
  label: string;
  helper: string;
  /** Other words for it (old names, what an operator might type). */
  keywords?: readonly string[];
};
type FieldShape =
  | { kind: 'switch' }
  | { kind: 'number'; unit?: string; step?: number }
  | { kind: 'select'; options: ReadonlyArray<{ value: string; label: string }> }
  | { kind: 'text'; maxLength: number };

/** A knob as written below, before its group is stamped on. */
export type FieldDef = FieldCopy & FieldShape;
export type Field = FieldDef & { group: SettingsGroupId };

const inGroup = (group: SettingsGroupId, defs: readonly FieldDef[]): Field[] =>
  defs.map((d) => ({ ...d, group }));

export const BASIC_SWITCHES: Field[] = inGroup('automatic', [
  {
    kind: 'switch',
    path: 'enabled',
    keywords: ['automation', 'master switch', 'detector'],
    label: 'Edge automation',
    helper:
      'On: the block detector runs and automatic actions may happen. Off: only what you start by hand.',
  },
  {
    kind: 'switch',
    path: 'autoRotate',
    keywords: ['automatic replacement', 'rotate', 'replace blocked addresses'],
    label: 'Automatic replacement',
    helper:
      'On: a suspected edge is replaced without asking, on origins that opted in. Off: suspicions only show as attention items.',
  },
  {
    kind: 'switch',
    path: 'clientCheck.enabled',
    keywords: ['spare', 'tested location'],
    label: "Replace without a spare using FCP's client check",
    helper:
      "On: with no tested spare, a blocked address is replaced in a location you tested before, and FCP's sing-box and Xray clients test the new one for you. Off: a replacement needs a tested spare, and the check is advice only.",
  },
  {
    kind: 'switch',
    path: 'render.enabled',
    keywords: ['subscription', 'edge-required'],
    label: 'Render edge addresses into subscriptions',
    helper:
      'On: members of an edge-required origin get edge addresses. Off: those members get no subscription.',
  },
  {
    kind: 'switch',
    path: 'probe.enabled',
    keywords: ['reachability', 'probes'],
    label: 'Reachability probes',
    helper:
      'On: published addresses are checked from the watched countries on a schedule. Off: the detector has only member reports.',
  },
  {
    kind: 'switch',
    path: 'l7.autoSelect',
    keywords: ['cdn', 'hostname front', 'l7'],
    label: 'Let automation pick CDN fronts',
    helper:
      'On: automatic replacements and auto-provisioning may choose an L7 account. Off: L7 edges are only created when you ask for one.',
  },
]);

export const BASIC_NUMBERS: Field[] = inGroup('automatic', [
  {
    kind: 'number',
    path: 'desiredPublishedDefault',
    keywords: ['pool size', 'addresses per node', 'in use'],
    label: 'Published edges per origin',
    unit: 'edges',
    helper: 'The pool size a new origin starts with. Each origin can override it.',
  },
  {
    kind: 'number',
    path: 'standbyPerRelay',
    keywords: ['spare', 'standby', 'reserve'],
    label: 'Standbys per origin',
    unit: 'edges',
    helper: 'Ready edges kept in reserve so a replacement is instant. Each one is billed.',
  },
  {
    kind: 'number',
    path: 'standbyPerListener',
    keywords: ['spare', 'standby', 'transport'],
    label: 'Standbys per listener',
    unit: 'edges',
    helper:
      'Ready edges per deployed listener, on top of the per-origin standbys. Automatic replacement sets this to 1. Each one is billed.',
  },
  {
    kind: 'number',
    path: 'cooldownMinutes',
    keywords: ['rest', 'replacement'],
    label: 'Cooldown between rotations',
    unit: 'min',
    helper: 'How long an origin rests after a rotation before automation may rotate it again.',
  },
  {
    kind: 'number',
    path: 'maxRotationsPerRelayPerDay',
    keywords: ['replacements per day', 'daily cap'],
    label: 'Rotations per origin per day',
    unit: 'per day',
    helper: 'The daily cap on automatic rotations of one origin.',
  },
  {
    kind: 'number',
    path: 'drainMinutes',
    keywords: ['retiring', 'destroy', 'replaced address'],
    label: 'Drain time',
    unit: 'min',
    helper:
      'How long a replaced edge keeps serving members before it is destroyed. Billed while it drains.',
  },
]);

export const AUTO_PROVISION: Field = inGroup('automatic', [
  {
    kind: 'switch',
    path: 'autoProvisionToDesired',
    keywords: ['buy', 'provision', 'pool size'],
    label: 'Provision up to the desired pool size automatically',
    helper:
      'On: edges are bought without asking until every origin reaches its pool size. Never while a spare waits for the slot, and never for an edge that could only be a spare. Off: you provision each edge yourself.',
  },
])[0]!;

export const REPLACEMENT_FIELDS: Field[] = inGroup('replacement', [
  {
    kind: 'switch',
    path: 'autoPublishStandby',
    keywords: ['spare', 'put in use'],
    label: 'Publish a standby when a pool slot is empty',
    helper:
      'On: a ready standby fills a missing slot on its own. Off: you publish it by hand, and no edge is bought for that slot meanwhile.',
  },
  {
    kind: 'switch',
    path: 'requireProviderHealth',
    keywords: ['health check', 'verify'],
    label: 'Wait for the provider health check',
    helper:
      'On: an edge is verified only once the provider reports its origin member healthy, where the provider can tell. Off: a successful connect is enough.',
  },
  {
    kind: 'switch',
    path: 'refreshMirrorsAfterFlip',
    keywords: ['storage mirrors', 's3'],
    label: 'Refresh stored mirrors after a publish',
    helper:
      'On: mirrored subscription copies are rebuilt right after the pool changes. Off: they catch up on the next scheduled refresh.',
  },
  {
    kind: 'number',
    path: 'burnedDrainMinutes',
    keywords: ['blocked', 'drain'],
    label: 'Drain time of a burned edge',
    unit: 'min',
    helper:
      'A burned edge is known to be blocked. It stays this long for members outside the blocking country who have not refreshed. 0 destroys it at once.',
  },
  {
    kind: 'number',
    path: 'updateIntervalHours',
    keywords: ['refresh interval', 'profile-update-interval', 'subscription'],
    label: 'How often apps check for a new address',
    unit: 'hours',
    helper:
      "Sent with a fronted node's subscription. Apps that honour it refetch this often and pick up a replaced address.",
  },
  {
    kind: 'switch',
    path: 'drainHold.enabled',
    keywords: ['drain hold', 'keep up', 'stale apps'],
    label: 'Keep replaced CDN fronts up for apps that have not refreshed',
    helper:
      'Most apps never refresh on their own. On: a replaced or blocked CDN front stays up after its drain until its apps refresh, or until the limit below. It costs next to nothing. Load balancer addresses are never kept.',
  },
  {
    kind: 'number',
    path: 'drainHold.maxDays',
    keywords: ['drain hold'],
    label: 'Keep a replaced CDN front up for at most',
    unit: 'days',
    helper:
      'Counted from when it was replaced. 0 never keeps one. An account at its edge limit lets its oldest kept front go first.',
  },
  {
    kind: 'number',
    path: 'drainHold.releaseAtKeys',
    keywords: ['drain hold', 'keys'],
    label: 'Let it go when this few apps may still use it',
    unit: 'apps',
    helper:
      'Counted hourly: keys that fetched while the front was in use and not since. Unused keys never refresh, so this is rarely 0.',
  },
  {
    kind: 'number',
    path: 'sniDrainMinutes',
    keywords: ['server name', 'reality', 'drain'],
    label: 'Drain time of a retired SNI',
    unit: 'min',
    helper: 'How long a retired SNI stays valid on the origin for members who still hold it.',
  },
  {
    kind: 'number',
    path: 'maxConcurrentRotations',
    keywords: ['replacements at once', 'concurrent'],
    label: 'Rotations running at once',
    unit: 'runs',
    helper: 'Fleet-wide limit. Further rotations are refused until one finishes.',
  },
  {
    kind: 'number',
    path: 'replacement.reblockHours',
    keywords: ['blocked again', 'hold', 'automatic replacement'],
    label: 'Hold when a replacement is blocked again within',
    unit: 'hours',
    helper:
      'If a replacement looks blocked this soon after going into use, automatic replacement of that transport on that node stops until you resume it. 0 never holds.',
  },
  {
    kind: 'number',
    path: 'replacement.freshBlockHours',
    keywords: ['fresh hostname', 'cdn blocked', 'pause'],
    label: 'Pause when a new hostname is blocked before use for',
    unit: 'hours',
    helper:
      'A new CDN hostname blocked in a country before anyone got it means the whole CDN is refused there. Automatic replacement for that country pauses this long and the address in use stays. Then one new hostname is tried. 0 never pauses.',
  },
]);

/** Trusted and open addresses, and suspicion (docs/edges.md "Address enumeration"). */
export const TRUST_FIELDS: Field[] = inGroup('trust', [
  {
    kind: 'number',
    path: 'trust.promoteAfterDays',
    keywords: ['trusted', 'free accounts', 'lanes'],
    label: 'Trusted addresses after',
    unit: 'days',
    helper:
      'On a node with trusted addresses, a free account this old is handed them; younger ones get the open addresses. Paid members get them at once.',
  },
  {
    kind: 'number',
    path: 'lanes.openReplacesPerDay',
    keywords: ['open lane', 'budget'],
    label: 'Open addresses replaced per node',
    unit: 'a day',
    helper:
      'Open addresses are expected to be blocked. They have their own budget, apart from the daily cap for trusted addresses.',
  },
  {
    kind: 'number',
    path: 'lanes.openReplacesPerFleetDay',
    keywords: ['open lane', 'budget', 'fleet'],
    label: 'Open addresses replaced in all',
    unit: 'a day',
    helper: 'The same budget across every node.',
  },
  {
    kind: 'number',
    path: 'trust.strikesToSuspect',
    keywords: ['suspicion', 'enumeration'],
    label: 'Suspect an account after',
    unit: 'strikes',
    helper:
      'A strike is a trusted address blocked soon after the account first got it, while few others had it. A suspected account gets open addresses only.',
  },
  {
    kind: 'number',
    path: 'trust.strikeDays',
    label: 'Strikes count for',
    unit: 'days',
    helper: 'Older strikes are deleted, so suspicion ends by itself.',
  },
  {
    kind: 'number',
    path: 'trust.strikeSpacingHours',
    label: 'At most one strike per account every',
    unit: 'hours',
    helper: 'One mass block never counts as several strikes.',
  },
  {
    kind: 'number',
    path: 'trust.windowDays',
    label: 'Handed out recently means within',
    unit: 'days',
    helper:
      'Only accounts that first got the address within this long before the block can get a strike. Records of who got which trusted address last as long as the address.',
  },
  {
    kind: 'number',
    path: 'trust.firstWaveHours',
    label: 'Not counted in an address\u2019s first',
    unit: 'hours',
    helper:
      'Accounts get a new address because it outranks theirs. A block in this window strikes none of them.',
  },
  {
    kind: 'number',
    path: 'trust.maxFreshHolders',
    label: 'No strike when more accounts got it recently than',
    unit: 'accounts',
    helper:
      'A brand-new address handed to many members at once tells nothing about any one of them.',
  },
]);

const IPV6_GLOBAL = [
  { value: 'both', label: 'IPv4 and IPv6 entries' },
  { value: 'auto-group-only', label: 'IPv6 only inside the automatic group' },
  { value: 'off', label: 'No IPv6 entries' },
] as const;

export const RENDER_GLOBAL_FIELDS: Field[] = inGroup('subscriptions', [
  {
    kind: 'number',
    path: 'render.namesPerEndpoint',
    keywords: ['sni', 'server names'],
    label: 'SNIs per member',
    unit: 'SNIs',
    helper:
      'SNIs one member gets for their main address. Apps with an Auto group get them all and skip a blocked one. Plain lists get the first only. Only for listeners with growth-stable SNI selection.',
  },
  {
    kind: 'number',
    path: 'render.backupNames',
    keywords: ['sni', 'backup'],
    label: 'SNIs on the backup address',
    unit: 'SNIs',
    helper:
      'The same for the backup address, also only in apps with an Auto group. They differ from the main SNIs where possible.',
  },
  {
    kind: 'select',
    path: 'render.ipv6Mode',
    keywords: ['ipv6', 'ipv4'],
    label: 'IPv6 entries',
    helper: 'Whether members receive the IPv6 address of an edge next to the IPv4 one.',
    options: IPV6_GLOBAL,
  },
  {
    kind: 'switch',
    path: 'render.preferDistinctProviders',
    keywords: ['providers', 'backup'],
    label: 'Spread a member across providers',
    helper:
      'On: the primary and backup entries of one member come from different providers when the pool allows. Off: assignment ignores the provider.',
  },
]);

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
    helper:
      'The "⚡ Auto (fastest)" group that picks the fastest entry, in formats that have groups.',
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

export const DETECTOR_FIELDS: Field[] = inGroup('detection', [
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
    helper: 'Distinct members on one edge before that edge counts as the blocked one.',
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
    keywords: ['circuit breaker', 'brake', 'mass block'],
    label: 'Fleet brake',
    unit: '%',
    helper:
      'When more than this share of nodes, and at least three, look blocked at once, every automatic replacement is held. 100 turns the brake off.',
  },
  {
    kind: 'number',
    path: 'detect.fleetRotationsPerDay',
    keywords: ['fleet cap', 'automatic replacement'],
    label: 'Automatic replacements per day, all nodes',
    unit: 'per day',
    helper: 'A cap across the whole fleet, on top of the cap per node. 0 = none at all.',
  },
  {
    kind: 'number',
    path: 'detect.sustainedChecks',
    keywords: ['never reached', 'blocked'],
    label: 'Failed checks for an address never reached',
    unit: 'checks',
    helper:
      'An address never reached from a listed country counts as blocked there after this many failed checks, if the node’s other addresses are reached from there.',
  },
  {
    kind: 'number',
    path: 'detect.sustainedNetworks',
    label: 'Networks among those checks',
    unit: 'networks',
    helper: 'The failed checks must come from at least this many networks.',
  },
  {
    kind: 'number',
    path: 'detect.sustainedMinutes',
    label: 'Over at least',
    unit: 'min',
    helper: 'Time between the first failed check and the newest.',
  },
]);

export const PROBE_SOURCE_FIELDS: Field[] = inGroup('probes', [
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
]);

export const PROBE_FIELDS: Field[] = inGroup('probes', [
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
    keywords: ['budget', 'runs'],
    label: 'Hourly budget',
    unit: 'runs per hour',
    helper: 'External probe runs allowed per hour. 0 stops external probing.',
  },
  {
    kind: 'switch',
    path: 'probe.preferEyeball',
    keywords: ['eyeball', 'residential', 'home networks'],
    label: 'Prefer residential networks',
    helper:
      'On: vantage points on consumer networks are asked for first, where the source can tell.',
  },
  {
    kind: 'switch',
    path: 'probe.ipv6',
    keywords: ['ipv6'],
    label: 'Probe IPv6 paths',
    helper: 'Applies to origin and custom targets. Edge targets follow the rendering IPv6 setting.',
  },
  {
    kind: 'number',
    path: 'probe.globalpingTestsPerHour',
    keywords: ['budget', 'credits', 'cost'],
    label: 'Globalping tests per hour',
    unit: 'tests per hour',
    helper:
      'All Globalping tests per hour, for probe rounds, in-country SNI checks and SNI timing. SNI checks keep their share. A probe round over the rest runs without Globalping. Past the free 500 an hour with a token, each test costs a credit.',
  },
]);

/** Checks of every edge from each censored country (edgeCountry.ts). */
export const COUNTRY_FIELDS: Field[] = inGroup('country-checks', [
  {
    kind: 'switch',
    path: 'country.enabled',
    keywords: ['per country', 'censored countries', 'controls'],
    label: 'Check edges from each country',
    helper:
      'On: each edge and spare gets a result per country, with a few uncensored control countries asked too. Off: probes work as before.',
  },
  {
    kind: 'text',
    path: 'country.controlCountries',
    keywords: ['controls', 'uncensored'],
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
      'Blocked needs this many controls to reach the edge in the same round. The control plane counts as one. Otherwise the edge is down, not blocked.',
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
      'With members ordered by country and fewer working addresses than this, working and not yet known addresses are shared out together.',
  },
]);

export const L7_FIELDS: Field[] = inGroup('cdn-fronts', [
  {
    kind: 'number',
    path: 'l7.maxSameProviderReplacementsPerDay',
    keywords: ['cdn', 'same provider'],
    label: 'Same-provider replacements per origin per day',
    unit: 'per day',
    helper:
      'A new hostname on the same CDN shares its addresses, so repeating it rarely helps. 0 forbids it.',
  },
]);

/** Names for load balancer addresses; the zones are a checklist of their own (`names.zones`). */
export const NAMES_FIELDS: Field[] = inGroup('address-hostnames', [
  {
    kind: 'switch',
    path: 'names.enabled',
    keywords: ['dns', 'hostname', 'load balancer', 'ip'],
    label: 'Give load balancer addresses a hostname',
    helper:
      'On: each new address gets a hostname in one of the zones below, and members dial it. Apps with an Auto group also get the IP as a fallback. Off: members get IPs again. Existing hostnames stay until their address goes.',
  },
  {
    kind: 'number',
    path: 'names.moveQuietDays',
    keywords: ['dns', 'hostname', 'move'],
    label: 'Move a hostname to its replacement at most every',
    unit: 'days',
    helper:
      'A replaced address passes its hostname to the new one, so members need no update. If the new address is blocked within this window, the next one gets a new hostname. 0 never moves one.',
  },
]);

/** Country lists (convex/countryLists.ts): community lists of what works, or is blocked, in a country. */
export const LIST_FIELDS: Field[] = inGroup('country-lists', [
  {
    kind: 'switch',
    path: 'lists.enabled',
    keywords: ['country lists', 'evidence', 'community'],
    label: 'Use country lists',
    helper:
      'On: lists are fetched on schedule and count as evidence. Off: nothing fetches or reads them. You can still add and read lists by hand.',
  },
  {
    kind: 'number',
    path: 'lists.jumpFactor',
    label: 'Hold a version that grew or shrank by more than',
    unit: 'times',
    helper: 'A list that changes this much is likely broken. It waits for you.',
  },
  {
    kind: 'number',
    path: 'lists.minOverlap',
    label: 'Hold a version sharing less than',
    unit: 'share (0 to 1)',
    step: 0.05,
    helper:
      'How much a new version must share with the one in use. Below this it waits for you, even at the same size.',
  },
  {
    kind: 'number',
    path: 'lists.heldDays',
    label: 'Throw away a waiting version after',
    unit: 'days',
    helper: 'A version nobody decided on goes after this long. The one in use stays.',
  },
  {
    kind: 'number',
    path: 'lists.staleDays',
    label: 'A list is stale after',
    unit: 'days',
    helper:
      'When its source has not confirmed it for this long, nothing reads it. A fetch with the same content confirms it again.',
  },
  {
    kind: 'number',
    path: 'lists.defaultFetchHours',
    label: 'A new list is fetched every',
    unit: 'hours',
    helper: 'Each list can change its own schedule.',
  },
]);

/** The zone checklist's own path (a list of zone ids). */
export const NAME_ZONES_PATH = 'names.zones';

/** The knobs of each group, in page order. */
export const GROUP_FIELDS: Record<SettingsGroupId, readonly Field[]> = {
  automatic: [...BASIC_SWITCHES, ...BASIC_NUMBERS, AUTO_PROVISION],
  replacement: REPLACEMENT_FIELDS,
  trust: TRUST_FIELDS,
  detection: DETECTOR_FIELDS,
  probes: [...PROBE_SOURCE_FIELDS, ...PROBE_FIELDS],
  'country-checks': COUNTRY_FIELDS,
  subscriptions: RENDER_GLOBAL_FIELDS,
  'cdn-fronts': L7_FIELDS,
  'address-hostnames': NAMES_FIELDS,
  'country-lists': LIST_FIELDS,
  delivery: [],
  'client-check': [],
  maintenance: [],
};

/** Every knob of the catalog. */
export const ALL_FIELDS: readonly Field[] = Object.values(GROUP_FIELDS).flat();

/**
 * Every flat config path a group saves with its one Save. Subscriptions also
 * owns each client family's rule (`families`, known only from the server view).
 */
export function groupPaths(group: SettingsGroupId, families: readonly string[] = []): string[] {
  const own = GROUP_FIELDS[group].map((f) => f.path);
  if (group === 'address-hostnames') return [...own, NAME_ZONES_PATH];
  if (group === 'subscriptions') return [...own, ...families.map(rulePath)];
  return own;
}

/**
 * One row of the page a search can find: a knob from above, or a control that
 * is not one knob (a write-only credential, a checklist, a card with its own
 * actions).
 */
export interface SettingEntry {
  /** The flat path of a knob, else a stable id of its own. */
  id: string;
  group: SettingsGroupId;
  label: string;
  helper: string;
  keywords?: readonly string[];
  /** The stored key, as the docs and the API spell it (`edge.drainMinutes`). */
  key?: string;
  /** The config paths it shows: it is changed when any of them is off its default. */
  paths: readonly string[];
}

const fieldEntry = (f: Field): SettingEntry => ({
  id: f.path,
  group: f.group,
  label: f.label,
  helper: f.helper,
  keywords: f.keywords,
  key: `edge.${f.path}`,
  paths: [f.path],
});

/** The rows that are not one knob, by id. */
export const ENTRY_IDS = {
  globalpingToken: 'secrets.globalpingToken',
  ripeAtlasKey: 'secrets.ripeAtlasKey',
  probeCountries: 'probe.countries',
  trustCounts: 'trust.counts',
  runCost: 'country.runCost',
  clientRules: 'render.clients',
  nameZones: NAME_ZONES_PATH,
  freedom: 'freedom.edgesOnly',
  deliveryPlaces: 'delivery.places',
  clientCheck: 'clientCheck.status',
  pause: 'maintenance.pause',
  panelRead: 'manage.observe',
  panelChanges: 'manage.enabled',
} as const;

/** Every row a search can find, in page order. `families` are the server view's client families. */
export function settingEntries(families: readonly string[] = []): SettingEntry[] {
  const fields = (group: SettingsGroupId) => GROUP_FIELDS[group].map(fieldEntry);
  const E = ENTRY_IDS;
  return [
    ...fields('automatic'),
    ...fields('replacement'),
    ...fields('trust'),
    {
      id: E.trustCounts,
      group: 'trust',
      label: 'Suspected accounts',
      helper: "How many accounts are suspected now, and today's strikes. Counts only.",
      keywords: ['strikes', 'suspicion'],
      paths: [],
    },
    ...fields('detection'),
    ...PROBE_SOURCE_FIELDS.map(fieldEntry),
    {
      id: E.globalpingToken,
      group: 'probes',
      label: 'Globalping token',
      helper: 'Write only. A token raises the free Globalping allowance.',
      keywords: ['credentials', 'api key', 'secret'],
      paths: [],
    },
    {
      id: E.ripeAtlasKey,
      group: 'probes',
      label: 'RIPE Atlas key',
      helper: 'Write only. RIPE Atlas needs an API key with credits.',
      keywords: ['credentials', 'api key', 'secret'],
      paths: [],
    },
    {
      id: E.probeCountries,
      group: 'probes',
      label: 'Countries to probe from',
      helper: 'The censored countries with "Check edges from here" on.',
      keywords: ['vantage', 'censored countries', 'coverage'],
      key: 'edge.probe.countries',
      paths: [],
    },
    ...PROBE_FIELDS.map(fieldEntry),
    {
      id: E.runCost,
      group: 'country-checks',
      label: 'Vantage points per Globalping run',
      helper: 'What one run of an IPv4 edge asks for, as typed.',
      keywords: ['globalping', 'cost', 'budget', 'credits', 'tests'],
      paths: [],
    },
    ...fields('country-checks'),
    ...fields('subscriptions'),
    {
      id: E.clientRules,
      group: 'subscriptions',
      label: 'Client families',
      helper:
        'Per client family: whether it is rendered, backup entries, the automatic group, the most entries, entry order and IPv6.',
      keywords: [
        ...Object.values(FAMILY_LABELS),
        ...RULE_FIELDS.map((f) => f.label),
        'rendering',
        'apps',
      ],
      key: 'edge.render.clients',
      paths: families.map(rulePath),
    },
    ...fields('cdn-fronts'),
    ...fields('address-hostnames'),
    {
      id: E.nameZones,
      group: 'address-hostnames',
      label: 'Zones for hostnames',
      helper: 'The DNS zones FCP writes address hostnames in.',
      keywords: ['dns', 'domain', 'records'],
      key: `edge.${NAME_ZONES_PATH}`,
      paths: [NAME_ZONES_PATH],
    },
    ...fields('country-lists'),
    {
      id: E.freedom,
      group: 'delivery',
      label: 'Freedom modes only through edges',
      helper: "Freedom members get edge addresses or nothing, never a node's own address.",
      keywords: ['direct', 'held back', 'withheld'],
      key: 'edge.freedom.edgesOnly',
      paths: [],
    },
    {
      id: E.deliveryPlaces,
      group: 'delivery',
      label: 'Edge-required places',
      helper:
        'Places whose members get edge addresses or nothing. Release one whose origin was deleted.',
      keywords: ['delivery bindings', 'keep dark', 'release', 'direct delivery', 'unavailable'],
      paths: [],
    },
    {
      id: E.clientCheck,
      group: 'client-check',
      label: "FCP's own client check",
      helper:
        'Whether the client-check service answers, and the clients it runs. Check now asks again.',
      keywords: ['sing-box', 'xray', 'mihomo', 'health', 'service', 'check now'],
      paths: [],
    },
    {
      id: E.pause,
      group: 'maintenance',
      label: 'Pause new edge work',
      helper: 'Running work finishes and nothing new starts, by hand or automatically.',
      keywords: ['freeze', 'resume', 'maintenance', 'upgrade', 'stop'],
      paths: [],
    },
    {
      id: E.panelRead,
      group: 'maintenance',
      label: 'Read panels every ten minutes',
      helper: 'FCP reads each backend panel with the health check, so node status stays current.',
      keywords: ['observe', 'backend', 'refresh', 'status'],
      key: 'servers.manage.observe',
      paths: [],
    },
    {
      id: E.panelChanges,
      group: 'maintenance',
      label: 'Changes from here',
      helper: 'FCP may change nodes, Hosts and mode groups on the backend panels.',
      keywords: ['manage', 'write', 'backend', 'panel'],
      key: 'servers.manage.enabled',
      paths: [],
    },
  ];
}
