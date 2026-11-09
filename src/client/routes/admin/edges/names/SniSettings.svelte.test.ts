import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { SniConfigView } from '../../../../../shared/contracts/sni';
import { patchSniConfig, sniKeys } from '@client/lib/sniApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import SniSettings from './SniSettings.svelte';
import { KNOBS } from './lib/sniKnobs';

vi.mock('@client/lib/sniApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/sniApi')>()),
  patchSniConfig: vi.fn(),
  invalidateSni: vi.fn(),
}));

const dflt = (group: string) =>
  Object.fromEntries(KNOBS.filter((k) => k.group === group).map((k) => [k.key, k.default]));
const config: SniConfigView = {
  config: {
    enabled: true,
    autoConfirm: false,
    curatedCountries: [],
    ...dflt('lists'),
    qualifyPerTick: 60,
  } as unknown as SniConfigView['config'],
  vantage: {
    enabled: false,
    countries: [],
    sources: { globalping: true, ripeatlas: false },
    autoApply: false,
    realHost: false,
    ...dflt('checks'),
  } as unknown as SniConfigView['vantage'],
  hunt: { enabled: false, ...dflt('find') } as SniConfigView['hunt'],
  vantageSources: { globalping: true, ripeatlas: false },
};

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;
beforeEach(() => {
  vi.mocked(patchSniConfig).mockResolvedValue({ changedKeys: [] });
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(sniKeys.config, config);
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
  vi.mocked(patchSniConfig).mockReset();
});

const text = () => document.body.textContent ?? '';
const field = (label: string) => {
  const l = [...document.querySelectorAll('label')].find((x) => x.textContent?.trim() === label)!;
  return document.getElementById(l.getAttribute('for')!) as HTMLInputElement;
};
const type = (label: string, value: string) => {
  const el = field(label);
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  flushSync();
};
const saveOf = (title: string) => {
  const card = [...document.querySelectorAll('[data-slot="card"]')].find((c) =>
    c.querySelector('h2')?.textContent?.includes(title),
  )!;
  return [...card.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Save')!;
};

describe('More settings', () => {
  test('every knob is a field with its value now; a changed one says so', () => {
    app = mountWithQuery(client, SniSettings, {});
    flushSync();
    for (const k of KNOBS) expect(field(k.label)).toBeTruthy();
    expect(field('SNIs checked each run').value).toBe('60');
    expect(text()).toContain('1 changed from default');
    expect(saveOf('Checking SNIs on lists').disabled).toBe(true);
  });

  test('a card saves only what changed in it, in its block; a bad value saves nothing', async () => {
    app = mountWithQuery(client, SniSettings, {});
    flushSync();
    type('Checks an hour', '500');
    expect(text()).toContain('A whole number from 0 to 120.');
    expect(saveOf('Checks from inside countries').disabled).toBe(true);
    type('Checks an hour', '24');
    saveOf('Checks from inside countries').click();
    await vi.waitFor(() =>
      expect(patchSniConfig).toHaveBeenCalledWith({ vantage: { hourlyBudget: 24 } }),
    );
  });
});
