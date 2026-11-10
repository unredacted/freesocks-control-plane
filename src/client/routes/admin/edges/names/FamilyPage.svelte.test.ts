import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, tick, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { router } from '@client/stores/router.svelte';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import FamilyPage from './FamilyPage.svelte';

/**
 * An SNI list's page and its address (docs/edges.md "Renaming a list"): a
 * rename moves the list's slug, so the page lands on the new address, and an
 * address the list had before opens it and lands on the one it has now. Both
 * replace the history entry: Back never returns to an address that only
 * redirects.
 */
vi.hoisted(() => {
  window.matchMedia ??= ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
    dispatchEvent: () => false,
  })) as never;
  Element.prototype.scrollIntoView ??= () => {};
});

const BASE = '/api/v1/admin/edges/sni';
const detail = (slug: string, label: string, formerSlugs: string[] = []) => ({
  family: {
    id: 'f-1',
    slug,
    formerSlugs,
    label,
    target: { kind: 'static', address: 'cover.example', port: 443 },
    enabled: true,
    requireH2: false,
    network: null,
    bindings: 0,
    counts: { total: 0, ready: 0, waiting: 0, failing: 0, suspended: 0, retired: 0, burned: 0 },
  },
  curatedCountries: [],
  vantage: { enabled: false, countries: [], autoApply: false, sources: [] },
  names: [],
  bindings: [],
  suggestions: 0,
});

const answers: Record<string, unknown> = {};
const patched: Array<{ path: string; body: unknown }> = [];
let patchAnswer: () => Promise<unknown> = () => Promise.reject(new Error('no writes'));

vi.mock('@client/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/api')>()),
  apiClient: {
    get: (path: string) =>
      path in answers
        ? Promise.resolve(answers[path])
        : new Promise((_, reject) => setTimeout(() => reject(new Error(`no ${path}`)), 5)),
    post: () => Promise.reject(new Error('no writes')),
    patch: (path: string, body: unknown) => {
      patched.push({ path, body });
      return patchAnswer();
    },
    put: () => Promise.reject(new Error('no writes')),
    delete: () => Promise.reject(new Error('no writes')),
  },
}));

let app: ReturnType<typeof mountWithQuery> | null = null;
const settle = async (rounds = 12) => {
  for (let i = 0; i < rounds; i++) {
    await new Promise((r) => setTimeout(r, 0));
    await tick();
  }
  flushSync();
};

async function mount(url: string, slug: string) {
  router.navigate(url, { replace: true });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  app = mountWithQuery(client, FamilyPage as never, { slug } as never);
  await settle();
}

afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
  for (const k of Object.keys(answers)) delete answers[k];
  patched.length = 0;
  patchAnswer = () => Promise.reject(new Error('no writes'));
});

const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label)!;

describe("an SNI list's page follows the list's slug", () => {
  test('an address the list had before lands on the one it has now, in place', async () => {
    // The server answers an old slug with the list as it is now.
    answers[`${BASE}/families/old-name`] = detail('new-name', 'New name', ['old-name']);
    const entries = history.length;
    await mount('/admin/servers/snis/lists/old-name?filter=all', 'old-name');
    expect(router.pathname).toBe('/admin/servers/snis/lists/new-name');
    // What the address carried stays, and no history entry was added.
    expect(router.search).toBe('?filter=all');
    expect(history.length).toBe(entries);
  });

  test('the address it has now is left alone', async () => {
    answers[`${BASE}/families/new-name`] = detail('new-name', 'New name', ['old-name']);
    await mount('/admin/servers/snis/lists/new-name', 'new-name');
    expect(router.pathname).toBe('/admin/servers/snis/lists/new-name');
    expect(document.body.textContent).toContain('New name');
  });

  test('a rename lands on the new address, replacing this one', async () => {
    answers[`${BASE}/families/fam-a`] = detail('fam-a', 'Family A');
    await mount('/admin/servers/snis/lists/fam-a', 'fam-a');
    const entries = history.length;
    patchAnswer = () => Promise.resolve({ ok: true, slug: 'shared-cover-a' });

    button('Rename').click();
    await settle(3);
    expect(document.body.textContent).toContain(
      "This page's address follows it, and the old address keeps working.",
    );
    const input = document.querySelector<HTMLInputElement>('[role="dialog"] input')!;
    input.value = 'Shared cover A';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    await settle(2);
    button('Save').click();
    await settle();

    expect(patched).toEqual([
      { path: `${BASE}/families/fam-a`, body: { label: 'Shared cover A' } },
    ]);
    expect(router.pathname).toBe('/admin/servers/snis/lists/shared-cover-a');
    expect(history.length).toBe(entries);
  });

  test('a refused rename says why and stays where it is', async () => {
    answers[`${BASE}/families/fam-a`] = detail('fam-a', 'Family A');
    await mount('/admin/servers/snis/lists/fam-a', 'fam-a');
    const { ApiCallError } = await import('@client/lib/api');
    patchAnswer = () =>
      Promise.reject(
        new ApiCallError(409, { error: { code: 'edge.sni.slug_taken', message: 'x' } } as never),
      );

    button('Rename').click();
    await settle(3);
    const input = document.querySelector<HTMLInputElement>('[role="dialog"] input')!;
    input.value = 'Second';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    await settle(2);
    button('Save').click();
    await settle();

    expect(document.body.textContent).toContain(
      'Another SNI list has, or had, the address this name gives. Pick another name.',
    );
    expect(router.pathname).toBe('/admin/servers/snis/lists/fam-a');
  });
});
