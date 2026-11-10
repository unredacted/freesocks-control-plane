/**
 * The groups of Servers -> Settings (pure; unit-tested in search.test.ts). Each
 * group is named after what its knobs do; the page shows one group, or all of
 * them, in the left column (`?group=`). The old cards were `?section=`: those
 * addresses keep working through `groupOfSection` (servers/lib/legacyRoutes.ts
 * rewrites them, edges/lib/routes.ts builds new links from old section names).
 *
 * Exports:
 *   SETTINGS_GROUPS / SettingsGroupId    the groups, in page order
 *   ALL_GROUPS                           the `?group=` value that shows every group
 *   parseGroup(raw)                      a `?group=` value -> a group id, or 'all'
 *   groupLabel(id)                       the group's name
 *   LEGACY_SECTIONS / groupOfSection(s)  an old `?section=` value -> its group
 */
export const SETTINGS_GROUPS = [
  {
    id: 'automatic',
    label: 'Automatic work',
    description: 'The switches that decide whether edges act on their own, and the pool defaults.',
  },
  {
    id: 'replacement',
    label: 'Replacement timing',
    description: 'Drains, holds, and how long a replaced CDN front stays up.',
  },
  {
    id: 'trust',
    label: 'Trust and open addresses',
    description:
      'Who gets trusted addresses, the budget for open ones, and when an account is suspected.',
  },
  {
    id: 'detection',
    label: 'Block detection',
    description: 'When member reports, load and probes add up to a suspected block.',
  },
  {
    id: 'probes',
    label: 'Probes',
    description: 'Where reachability is measured from, how often, and within what budget.',
  },
  {
    id: 'country-checks',
    label: 'Country checks',
    description: 'How each address is judged from every censored country.',
  },
  {
    id: 'subscriptions',
    label: 'Subscriptions',
    description: "How edge addresses appear in a member's subscription, per client family.",
  },
  {
    id: 'cdn-fronts',
    label: 'CDN fronts',
    description:
      'Limits of hostname fronts. Whether automation may pick them is in Automatic work.',
  },
  {
    id: 'address-hostnames',
    label: 'Address hostnames',
    description:
      "Hand members a hostname instead of a load balancer's IP. FCP writes the records in the zones you pick.",
  },
  {
    id: 'country-lists',
    label: 'Country lists',
    description:
      'Community lists of SNIs and addresses that work, or are blocked, in a country. Evidence only, unless a list is set to prefer its SNIs.',
  },
  {
    id: 'delivery',
    label: 'Delivery',
    description: 'Places where members get edge addresses or nothing.',
  },
  {
    id: 'client-check',
    label: 'Client check',
    description: "FCP's own sing-box and Xray clients, used to test new addresses and SNIs.",
  },
  {
    id: 'maintenance',
    label: 'Maintenance',
    description: 'Pause new edge work, and the two switches for the backend panels.',
  },
] as const;

export type SettingsGroupId = (typeof SETTINGS_GROUPS)[number]['id'];

/** The `?group=` value (and the default) that shows every group. */
export const ALL_GROUPS = 'all';
export type GroupChoice = SettingsGroupId | typeof ALL_GROUPS;

const GROUP_IDS: readonly string[] = SETTINGS_GROUPS.map((g) => g.id);

export const parseGroup = (raw: string | null | undefined): GroupChoice =>
  GROUP_IDS.includes(raw ?? '') ? (raw as SettingsGroupId) : ALL_GROUPS;

export const groupLabel = (id: SettingsGroupId): string =>
  SETTINGS_GROUPS.find((g) => g.id === id)?.label ?? id;

/** The old cards (`?section=`), each with the group that holds it now. */
export const LEGACY_SECTIONS = {
  basics: 'automatic',
  rotation: 'replacement',
  rendering: 'subscriptions',
  detector: 'detection',
  probes: 'probes',
  l7: 'cdn-fronts',
  names: 'address-hostnames',
  lists: 'country-lists',
  maintenance: 'maintenance',
  freedom: 'delivery',
  delivery: 'delivery',
} as const satisfies Record<string, SettingsGroupId>;
export type LegacySettingsSection = keyof typeof LEGACY_SECTIONS;

/** The group an old `?section=` value opens now; null for a value that never existed. */
export const groupOfSection = (section: string | null | undefined): SettingsGroupId | null =>
  section && Object.hasOwn(LEGACY_SECTIONS, section)
    ? LEGACY_SECTIONS[section as LegacySettingsSection]
    : null;
