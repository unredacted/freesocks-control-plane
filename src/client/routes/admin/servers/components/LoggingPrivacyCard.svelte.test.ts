import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { adminLoggingLastCheckQuery } from '@client/lib/queries';
import type { RemnawaveLoggingLastCheck } from '@shared/contracts/admin';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import LoggingPrivacyCard from './LoggingPrivacyCard.svelte';

vi.mock('@client/lib/queries', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/queries')>()),
  adminLoggingLastCheckQuery: vi.fn(),
}));

const MIN = 60_000;

function check(over: Partial<RemnawaveLoggingLastCheck> = {}): RemnawaveLoggingLastCheck {
  return {
    at: Date.now() - 12 * MIN,
    source: 'automatic',
    dryRun: false,
    panels: 1,
    panelsUnreadable: 0,
    panelsBusy: 0,
    profiles: 4,
    profilesLogging: 0,
    profilesTurnedOff: 0,
    profilesSkipped: 0,
    ...over,
  };
}

let app: ReturnType<typeof mountWithQuery> | null = null;

function mount(lastCheck: RemnawaveLoggingLastCheck | null): string {
  vi.mocked(adminLoggingLastCheckQuery).mockReturnValue({
    data: { lastCheck },
    isError: false,
    isPending: false,
  } as never);
  app = mountWithQuery(new QueryClient(), LoggingPrivacyCard, {});
  flushSync();
  return (document.body.textContent ?? '').replace(/\s+/g, ' ');
}

afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
});

describe('LoggingPrivacyCard last check line', () => {
  test('a clean automatic check', () => {
    const text = mount(check());
    expect(text).toContain('Last checked 12 minutes ago (automatic): 4 profiles, no logging.');
    expect(text).toContain('FCP checks every hour and turns logging off on its own');
  });

  test('what the run turned off, what still logs, what it could not read', () => {
    expect(mount(check({ profilesLogging: 1, profilesTurnedOff: 1 }))).toContain(
      '(automatic): turned logging off on 1 profile.',
    );
    unmount(app!);
    expect(
      mount(check({ source: 'manual', dryRun: true, profilesLogging: 2, panelsUnreadable: 1 })),
    ).toContain('(by an admin): 2 profiles are logging, 1 panel could not be read.');
    unmount(app!);
    expect(mount(check({ panelsBusy: 1, profilesLogging: 1 }))).toContain(
      '1 profile is logging, 1 panel was only read while a server change runs there.',
    );
    unmount(app!);
    app = null;
  });

  test('never run yet', () => {
    expect(mount(null)).toContain('Not checked yet.');
  });

  test('no em-dash in the copy', () => {
    expect(mount(check({ profilesSkipped: 1 }))).not.toContain('—');
  });
});
