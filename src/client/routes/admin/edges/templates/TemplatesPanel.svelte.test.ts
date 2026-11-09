import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  EDGE_PROVIDER_IDS,
  type EdgeProviderAccountAdmin,
} from '../../../../../shared/contracts/edges';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import TemplatesPanel from './TemplatesPanel.svelte';

// Two provider kinds from the catalogue; which ones does not matter.
const P = EDGE_PROVIDER_IDS[0];
const Q = EDGE_PROVIDER_IDS[1];
const at = '2026-01-01T00:00:00.000Z';
const tpl = (id: string, provider: string, accountId: string | null, isDefault = false) => ({
  id,
  provider,
  accountId,
  name: `Template ${id}`,
  params: {},
  paramsHash: 'h',
  isDefault,
  updatedAt: at,
});

vi.mock('../../../../lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../lib/edgesApi')>()),
  templatesQuery: () => ({
    isPending: false,
    isError: false,
    data: {
      templates: [
        tpl('shared', P, null, true),
        tpl('mine', P, 'acc-z'),
        tpl('theirs', P, 'acc-b'),
        tpl('other-kind', Q, null, true),
      ],
      schemas: { [P]: { fields: [], defaults: {} }, [Q]: { fields: [], defaults: {} } },
    },
  }),
  providersQuery: () => ({
    isPending: false,
    isError: false,
    data: {
      accounts: [
        { id: 'acc-z', name: 'Zulu', provider: P, defaultTemplateId: null },
        { id: 'acc-b', name: 'Bravo', provider: P, defaultTemplateId: 'theirs' },
      ],
    },
  }),
}));

const account = {
  id: 'acc-z',
  name: 'Zulu',
  provider: P,
  defaultTemplateId: null,
  qualified: false,
  locations: [],
} as unknown as EdgeProviderAccountAdmin;

let app: ReturnType<typeof mountWithQuery> | null = null;
afterEach(() => {
  if (app) unmount(app);
  app = null;
});

const links = () =>
  [...document.querySelectorAll('a')].map((a) => [a.textContent?.trim(), a.getAttribute('href')]);

describe('an account Templates tab', () => {
  test('lists what the account can use, links stay on the account, and says which is in use', () => {
    app = mountWithQuery(new QueryClient(), TemplatesPanel, { account });
    flushSync();
    expect(links()).toEqual([
      ['Template shared', '/admin/servers/providers/acc-z?tab=templates&template=shared'],
      ['Template mine', '/admin/servers/providers/acc-z?tab=templates&template=mine'],
    ]);
    const rows = [...document.querySelectorAll('tbody tr')].map((r) => r.textContent ?? '');
    expect(rows[0]).toContain('Every account');
    expect(rows[0]).toContain('In use');
    expect(rows[1]).toContain('Only this account');
    expect(rows[1]).toContain('Available');
  });
});

describe('All templates', () => {
  test('lists every provider with its templates and who uses them', () => {
    app = mountWithQuery(new QueryClient(), TemplatesPanel, {});
    flushSync();
    expect(links().map(([, href]) => href)).toEqual([
      '/admin/servers/providers/templates?template=shared',
      '/admin/servers/providers/templates?template=mine',
      '/admin/servers/providers/templates?template=theirs',
      '/admin/servers/providers/templates?template=other-kind',
    ]);
    expect(document.body.textContent).toContain('Only Bravo');
    expect(document.body.textContent).toContain('2 accounts can use these.');
  });

  test('shows one provider when asked', () => {
    app = mountWithQuery(new QueryClient(), TemplatesPanel, { provider: Q });
    flushSync();
    expect(links().map(([, href]) => href)).toEqual([
      '/admin/servers/providers/templates?template=other-kind',
    ]);
  });
});
