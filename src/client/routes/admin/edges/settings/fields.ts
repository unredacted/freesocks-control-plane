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
  'names',
  'lists',
  'maintenance',
  'freedom',
  // The Edge-required places card (DeliveryBindingsCard, id settings-delivery).
  'delivery',
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
      'On: the block detector runs and automatic actions may happen. Off: only what you start by hand.',
  },
  {
    kind: 'switch',
    path: 'autoRotate',
    label: 'Automatic rotation',
    helper:
      'On: a suspected edge is replaced without asking, on origins that opted in. Off: suspicions only show as attention items.',
  },
  {
    kind: 'switch',
    path: 'clientCheck.enabled',
    label: "Replace without a spare using FCP's client check",
    helper:
      "On: nobody has to test an address by hand. A new address in a node's locations is checked with FCP's sing-box and Xray clients, and a pass counts as the test. Off: an address needs a person's test before it goes live, and the check is advice only.",
  },
  {
    kind: 'switch',
    path: 'render.enabled',
    label: 'Render edge addresses into subscriptions',
    helper:
      'On: members of an edge-required origin get edge addresses. Off: those members get no subscription.',
  },
  {
    kind: 'switch',
    path: 'probe.enabled',
    label: 'Reachability probes',
    helper:
      'On: published addresses are checked from the watched countries on a schedule. Off: the detector has only member reports.',
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
      'Ready edges per deployed listener, on top of the per-origin standbys. Automatic replacement sets this to 1. Each one is billed.',
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
      'How long a replaced edge keeps serving members before it is destroyed. Billed while it drains.',
  },
];

export const AUTO_PROVISION: Field = {
  kind: 'switch',
  path: 'autoProvisionToDesired',
  label: 'Provision up to the desired pool size automatically',
  helper:
    'On: edges are bought without asking until every origin reaches its pool size. Never while a spare waits for the slot, and never for an edge that could only be a spare. Off: you provision each edge yourself.',
};

export const ROTATION_FIELDS: Field[] = [
  {
    kind: 'switch',
    path: 'autoPublishStandby',
    label: 'Publish a standby when a pool slot is empty',
    helper:
      'On: a ready standby fills a missing slot on its own. Off: you publish it by hand, and no edge is bought for that slot meanwhile.',
  },
  {
    kind: 'switch',
    path: 'requireProviderHealth',
    label: 'Wait for the provider health check',
    helper:
      'On: an edge is verified only once the provider reports its origin member healthy, where the provider can tell. Off: a successful connect is enough.',
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
      'A burned edge is known to be blocked. It stays this long for members outside the blocking country who have not refreshed. 0 destroys it at once.',
  },
  {
    kind: 'number',
    path: 'updateIntervalHours',
    label: 'How often apps check for a new address',
    unit: 'hours',
    helper:
      "Sent with a fronted node's subscription. Apps that honour it refetch this often and pick up a replaced address.",
  },
  {
    kind: 'switch',
    path: 'drainHold.enabled',
    label: 'Keep replaced CDN fronts up for apps that have not refreshed',
    helper:
      'Most apps never refresh on their own. On: a replaced or blocked CDN front stays up after its drain until its apps refresh, or until the limit below. It costs next to nothing. Load balancer addresses are never kept.',
  },
  {
    kind: 'number',
    path: 'drainHold.maxDays',
    label: 'Keep a replaced CDN front up for at most',
    unit: 'days',
    helper:
      'Counted from when it was replaced. 0 never keeps one. An account at its edge limit lets its oldest kept front go first.',
  },
  {
    kind: 'number',
    path: 'drainHold.releaseAtKeys',
    label: 'Let it go when this few apps may still use it',
    unit: 'apps',
    helper:
      'Counted hourly: keys that fetched while the front was in use and not since. Unused keys never refresh, so this is rarely 0.',
  },
  {
    kind: 'number',
    path: 'sniDrainMinutes',
    label: 'Drain time of a retired server name',
    unit: 'min',
    helper: 'How long a retired SNI stays valid on the origin for members who still hold it.',
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
    path: 'replacement.reblockHours',
    label: 'Hold when a replacement is blocked again within',
    unit: 'hours',
    helper:
      'If a replacement looks blocked this soon after going into use, automatic replacement of that transport on that node stops until you resume it. 0 never holds.',
  },
  {
    kind: 'number',
    path: 'replacement.freshBlockHours',
    label: 'Pause when a new hostname is blocked before use for',
    unit: 'hours',
    helper:
      'A new CDN hostname blocked in a country before anyone got it means the whole CDN is refused there. Automatic replacement for that country pauses this long and the address in use stays. Then one new hostname is tried. 0 never pauses.',
  },
  {
    kind: 'number',
    path: 'trust.promoteAfterDays',
    label: 'Trusted addresses after',
    unit: 'days',
    helper:
      'On a node with trusted addresses, a free account this old is handed them; younger ones get the open addresses. Paid members get them at once.',
  },
  {
    kind: 'number',
    path: 'lanes.openReplacesPerDay',
    label: 'Open addresses replaced per node',
    unit: 'a day',
    helper:
      'Open addresses are expected to be blocked. They have their own budget, apart from the daily cap for trusted addresses.',
  },
  {
    kind: 'number',
    path: 'lanes.openReplacesPerFleetDay',
    label: 'Open addresses replaced in all',
    unit: 'a day',
    helper: 'The same budget across every node.',
  },
  {
    kind: 'number',
    path: 'audience.replacesPerDay',
    label: "A country's own addresses replaced per node",
    unit: 'a day',
    helper:
      "Replacements per day for a country on its own addresses on a node, per transport. Separate from the node's daily cap. 0 means by hand only.",
  },
  {
    kind: 'number',
    path: 'trust.strikesToSuspect',
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
];

const IPV6_GLOBAL = [
  { value: 'both', label: 'IPv4 and IPv6 entries' },
  { value: 'auto-group-only', label: 'IPv6 only inside the automatic group' },
  { value: 'off', label: 'No IPv6 entries' },
] as const;

const PROBE_NETWORK_OPTIONS = [
  { value: 'home', label: 'Home networks only' },
  { value: 'home_first', label: 'Home networks first, topped up with data centres' },
  { value: 'any', label: 'Any network' },
] as const;

export const RENDER_GLOBAL_FIELDS: Field[] = [
  {
    kind: 'number',
    path: 'render.namesPerEndpoint',
    label: 'SNIs per member',
    unit: 'SNIs',
    helper:
      'SNIs one member gets for their main address. Apps with an Auto group get them all and skip a blocked one. Plain lists get the first only. Only for listeners with growth-stable SNI selection.',
  },
  {
    kind: 'number',
    path: 'render.backupNames',
    label: 'SNIs on the backup address',
    unit: 'SNIs',
    helper:
      'The same for the backup address, also only in apps with an Auto group. They differ from the main SNIs where possible.',
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
    label: 'Fleet brake',
    unit: '%',
    helper:
      'When more than this share of nodes, and at least three, look blocked at once, every automatic replacement is held. 100 turns the brake off.',
  },
  {
    kind: 'number',
    path: 'detect.fleetRotationsPerDay',
    label: 'Automatic replacements per day, all nodes',
    unit: 'per day',
    helper: 'A cap across the whole fleet, on top of the cap per node. 0 = none at all.',
  },
  {
    kind: 'number',
    path: 'detect.sustainedChecks',
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
    kind: 'select',
    path: 'probe.networks',
    label: 'Globalping probe networks',
    helper:
      'Which networks Globalping checks come from. Home networks see what members see, but a country with few of them gets fewer results. Control countries use any probe.',
    options: PROBE_NETWORK_OPTIONS,
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
      'All Globalping tests per hour, for probe rounds, in-country SNI checks and SNI timing. SNI checks keep their share. A probe round over the rest runs without Globalping. Past the free 500 an hour with a token, each test costs a credit.',
  },
];

/** Checks of every edge from each censored country (edgeCountry.ts). */
export const COUNTRY_FIELDS: Field[] = [
  {
    kind: 'switch',
    path: 'country.enabled',
    label: 'Check edges from each country',
    helper:
      'On: each edge and spare gets a result per country, with a few uncensored control countries asked too. Off: probes work as before.',
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

/** Names for load balancer addresses; the zones are a checklist of their own (`names.zones`). */
export const NAMES_FIELDS: Field[] = [
  {
    kind: 'switch',
    path: 'names.enabled',
    label: 'Give load balancer addresses a hostname',
    helper:
      'On: each new address gets a hostname in one of the zones below, and members dial it. Apps with an Auto group also get the IP as a fallback. Off: members get IPs again. Existing hostnames stay until their address goes.',
  },
  {
    kind: 'number',
    path: 'names.moveQuietDays',
    label: 'Move a hostname to its replacement at most every',
    unit: 'days',
    helper:
      'A replaced address passes its hostname to the new one, so members need no update. If the new address is blocked within this window, the next one gets a new hostname. 0 never moves one.',
  },
];

/** Country lists (convex/countryLists.ts): community lists of what works, or is blocked, in a country. */
export const LIST_FIELDS: Field[] = [
  {
    kind: 'switch',
    path: 'lists.enabled',
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
];

/** The per-country budgets' own path (`{IR: 2}`; a country left out follows the line above). */
export const AUDIENCE_BUDGETS_PATH = 'audience.replacesPerDayByCountry';

/** The zone checklist's own path (a list of zone ids). */
export const NAME_ZONES_PATH = 'names.zones';

const pathsOf = (fields: readonly Field[]): string[] => fields.map((f) => f.path);

/** Every flat path a section owns (the rendering section adds its family rules at runtime). */
export const SECTION_PATHS: Record<
  Exclude<SettingsSection, 'maintenance' | 'freedom' | 'delivery'>,
  string[]
> = {
  basics: [...pathsOf(BASIC_SWITCHES), ...pathsOf(BASIC_NUMBERS), AUTO_PROVISION.path],
  rotation: [...pathsOf(ROTATION_FIELDS), AUDIENCE_BUDGETS_PATH],
  rendering: pathsOf(RENDER_GLOBAL_FIELDS),
  detector: pathsOf(DETECTOR_FIELDS),
  probes: [...pathsOf(PROBE_SOURCE_FIELDS), ...pathsOf(PROBE_FIELDS), ...pathsOf(COUNTRY_FIELDS)],
  l7: pathsOf(L7_FIELDS),
  names: [...pathsOf(NAMES_FIELDS), NAME_ZONES_PATH],
  lists: pathsOf(LIST_FIELDS),
};
