import { describe, expect, it } from 'vitest';
import { EDGE_PROVIDER_IDS } from '../../../../../shared/contracts/edges';
import { availableTo, templateRedirect } from './list';

// Two provider kinds from the catalogue; which ones does not matter.
const P = EDGE_PROVIDER_IDS[0];
const Q = EDGE_PROVIDER_IDS[1];

const accounts = [
  { id: 'acc-z', provider: P, enabled: true, name: 'Zulu' },
  { id: 'acc-b', provider: P, enabled: true, name: 'Bravo' },
  { id: 'acc-a', provider: P, enabled: false, name: 'Alpha' },
  { id: 'acc-q', provider: Q, enabled: true, name: 'Other' },
];
const templates = [
  { id: 't-shared', provider: P, accountId: null },
  { id: 't-zulu', provider: P, accountId: 'acc-z' },
  { id: 't-q', provider: Q, accountId: null },
  { id: 't-gone', provider: P, accountId: 'acc-removed' },
];

describe('availableTo', () => {
  it("lists the account's own templates and its provider's shared ones", () => {
    expect(availableTo(templates, { id: 'acc-z', provider: P }).map((t) => t.id)).toEqual([
      't-shared',
      't-zulu',
    ]);
    expect(availableTo(templates, { id: 'acc-b', provider: P }).map((t) => t.id)).toEqual([
      't-shared',
    ]);
    expect(availableTo(templates, { id: 'acc-q', provider: Q }).map((t) => t.id)).toEqual(['t-q']);
  });
});

describe('templateRedirect', () => {
  it('lands a provider filter on the first account of that provider', () => {
    expect(templateRedirect({ provider: P, template: null }, accounts, templates)).toBe(
      '/admin/servers/providers/acc-b?tab=templates',
    );
    expect(templateRedirect({ provider: Q, template: '' }, accounts, null)).toBe(
      '/admin/servers/providers/acc-q?tab=templates',
    );
  });

  it('keeps the template open on the account', () => {
    expect(templateRedirect({ provider: P, template: 't-shared' }, accounts, templates)).toBe(
      '/admin/servers/providers/acc-b?tab=templates&template=t-shared',
    );
  });

  it("goes to the account a template is only for, when it is one of the provider's", () => {
    expect(templateRedirect({ provider: P, template: 't-zulu' }, accounts, templates)).toBe(
      '/admin/servers/providers/acc-z?tab=templates&template=t-zulu',
    );
    // Its account was removed: the first account.
    expect(templateRedirect({ provider: P, template: 't-gone' }, accounts, templates)).toBe(
      '/admin/servers/providers/acc-b?tab=templates&template=t-gone',
    );
    // The templates are still loading: the first account.
    expect(templateRedirect({ provider: P, template: 't-zulu' }, accounts, null)).toBe(
      '/admin/servers/providers/acc-b?tab=templates&template=t-zulu',
    );
  });

  it('stays without a provider, with an unknown one, with no account, or for a new template', () => {
    expect(templateRedirect({ provider: null, template: 't-shared' }, accounts, templates)).toBe(
      null,
    );
    expect(templateRedirect({ provider: 'nope', template: null }, accounts, templates)).toBeNull();
    expect(templateRedirect({ provider: P, template: null }, [], templates)).toBeNull();
    expect(templateRedirect({ provider: P, template: 'new' }, accounts, templates)).toBeNull();
  });
});
