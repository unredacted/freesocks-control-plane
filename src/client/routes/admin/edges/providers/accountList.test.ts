import { describe, expect, it } from 'vitest';
import { ACCOUNT_TAB_LABELS, ACCOUNT_TABS, accountTab, sortAccounts } from './accountList';

describe('sortAccounts', () => {
  it('puts enabled accounts first, then sorts by name', () => {
    const sorted = sortAccounts([
      { id: '1', enabled: false, name: 'Alpha' },
      { id: '2', enabled: true, name: 'Zulu' },
      { id: '3', enabled: true, name: 'Bravo' },
    ]);
    expect(sorted.map((a) => a.id)).toEqual(['3', '2', '1']);
  });
  it('does not change the list it was given', () => {
    const list = [
      { enabled: true, name: 'b' },
      { enabled: true, name: 'a' },
    ];
    sortAccounts(list);
    expect(list[0]!.name).toBe('b');
  });
});

describe('account tabs', () => {
  it('keeps the old tab names and adds the split ones', () => {
    expect(ACCOUNT_TABS).toEqual([
      'overview',
      'locations',
      'countries',
      'templates',
      'inventory',
      'credentials',
    ]);
    expect(ACCOUNT_TAB_LABELS.credentials).toBe('Credentials and DNS');
  });
  it('reads a tab value, and falls back to the overview', () => {
    expect(accountTab('templates')).toBe('templates');
    expect(accountTab('inventory')).toBe('inventory');
    expect(accountTab('credentials')).toBe('credentials');
    expect(accountTab('')).toBe('overview');
    expect(accountTab(null)).toBe('overview');
    expect(accountTab('nope')).toBe('overview');
  });
});
