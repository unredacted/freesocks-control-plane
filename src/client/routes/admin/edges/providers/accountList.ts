/**
 * The provider accounts list and one account's tabs (pure; unit-tested in
 * accountList.test.ts).
 *
 * Exports:
 *   sortAccounts(accounts)       enabled first, then by name (the Providers list order;
 *                                "the first account" of a provider kind is the first here)
 *   ACCOUNT_TABS / AccountTab    the `?tab` values of an account page, in order
 *   ACCOUNT_TAB_LABELS           each tab's label
 *   accountTab(value)            a `?tab` value -> its tab (anything else -> overview)
 */

export function sortAccounts<T extends { enabled: boolean; name: string }>(
  accounts: readonly T[],
): T[] {
  return [...accounts].sort(
    (a, b) => Number(!a.enabled) - Number(!b.enabled) || a.name.localeCompare(b.name),
  );
}

export const ACCOUNT_TABS = [
  'overview',
  'locations',
  'countries',
  'templates',
  'inventory',
  'credentials',
] as const;
export type AccountTab = (typeof ACCOUNT_TABS)[number];

export const ACCOUNT_TAB_LABELS: Record<AccountTab, string> = {
  overview: 'Overview',
  locations: 'Locations',
  countries: 'Countries',
  templates: 'Templates',
  inventory: 'Inventory',
  credentials: 'Credentials and DNS',
};

export function accountTab(value: string | null | undefined): AccountTab {
  return (ACCOUNT_TABS as readonly string[]).includes(value ?? '')
    ? (value as AccountTab)
    : 'overview';
}
