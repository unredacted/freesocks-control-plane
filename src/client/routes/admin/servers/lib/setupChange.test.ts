import { describe, expect, test } from 'vitest';
import {
  BackendSetupInput,
  BackendSetupView,
  DEFAULT_MODE_SETUP,
} from '../../../../../shared/contracts/servers';
import { setUpSlugs, setupChangeWords, setupInputOf, setupSummary } from './setupChange';

/** A ready backend as the view carries it, set up for the four default modes. */
const view = (over: Partial<BackendSetupView> = {}): BackendSetupView =>
  BackendSetupView.parse({
    exists: true,
    state: 'ready',
    step: 'done',
    code: null,
    generation: 1,
    running: false,
    profile: { name: 'FreeSocks-Config', uuid: 'p-1' },
    modes: DEFAULT_MODE_SETUP.map((m) => ({
      slug: m.slug,
      name: m.name,
      shape: m.shape,
      familySlug: m.shape.transport === 'ws' ? null : 'fam-a',
      acceptProxyProtocol: m.acceptProxyProtocol,
      ws: m.ws ?? null,
      tag: m.name.toUpperCase().replace(/-/g, '_'),
      group: { uuid: `g-${m.slug}`, renamedFrom: null },
      placement: 'bound',
      transport: { port: 443, path: null, serverNames: [], target: null },
      family: m.shape.transport === 'ws' ? 'none' : 'bound',
    })),
    templates: [],
    privacy: 'ok',
    originDns: null,
    adopted: false,
    established: true,
    updatedAt: '2026-10-20T00:00:00.000Z',
    ...over,
  });
/** The zones the sheet lists: acct-1 and acct-2 both reach example.org (the same zone id). */
const zones = [
  { id: 'zone-org', name: 'example.org' },
  { id: 'zone-net', name: 'example.net' },
];
const inOrg = { accountId: 'acct-1', zoneId: 'zone-org', zoneName: 'example.org' };

describe('the change sheet starts from the current setup', () => {
  test('every mode exactly as it was asked for, so an unchanged mode reads unchanged to the server', () => {
    const input = setupInputOf(view({ originDns: inOrg }))!;
    expect(input.profileName).toBe('FreeSocks-Config');
    expect(input.originDns).toEqual({ accountId: 'acct-1', zoneId: 'zone-org' });
    // What the server's own schema makes of it is what was set up.
    const parsed = BackendSetupInput.parse({ ...input, adopt: false });
    expect(parsed.modes.map((m) => [m.slug, m.familySlug ?? null, m.ws ?? null])).toEqual([
      ['privacy-reality', 'fam-a', null],
      ['freedom-reality', 'fam-a', null],
      ['freedom-xhttp', 'fam-a', null],
      ['freedom-ws', null, { path: '/ws', port: 8443 }],
    ]);
  });

  test('a Hysteria mode keeps its server name and Salamander setting', () => {
    const base = view();
    const withHysteria = view({
      modes: [
        ...base.modes,
        {
          ...base.modes[0]!,
          slug: 'privacy-hysteria',
          name: 'Privacy-Hysteria',
          shape: { transport: 'hysteria', fronting: 'direct' },
          familySlug: null,
          hysteria: { serverName: 'quic.example', salamander: true },
          tag: 'PRIVACY_HYSTERIA',
          family: 'none',
        },
      ],
    });
    const input = setupInputOf(withHysteria)!;
    const parsed = BackendSetupInput.parse({ ...input, adopt: false });
    expect(parsed.modes.find((m) => m.slug === 'privacy-hysteria')!.hysteria).toEqual({
      serverName: 'quic.example',
      salamander: true,
    });
  });

  test('nothing to start from without a setup', () => {
    expect(setupInputOf(null)).toBeNull();
    expect(setupInputOf(view({ exists: false, profile: null, modes: [] }))).toBeNull();
  });
});

describe('what a change does, said before it runs', () => {
  const modes = setupInputOf(view())!.modes;

  test('adding origin names is recorded at once and touches no node', () => {
    const w = setupChangeWords(
      view(),
      { modes, origin: { accountId: 'acct-1', zoneId: 'zone-org' } },
      zones,
    );
    expect(w.changed).toBe(true);
    expect(w.lines).toEqual(['WebSocket nodes get their origin hostnames under example.org.']);
    expect(w.effect).toBe(
      "Recorded at once as generation 2. Nothing changes on the backend, or on nodes that already have a hostname or serve members. A WebSocket node still waiting for a hostname gets one under example.org in a new machine revision, applied on the role's next run.",
    );
  });

  test('another account for the same zone, another zone, or none', () => {
    const current = view({ originDns: inOrg });
    const to = (accountId: string, zoneId: string) =>
      setupChangeWords(current, { modes, origin: { accountId, zoneId } }, zones);
    expect(to('acct-2', 'zone-org').lines).toEqual([
      'Origin hostnames stay under example.org, through another account.',
    ]);
    expect(to('acct-3', 'zone-net').lines).toEqual([
      'Origin hostnames move from example.org to example.net.',
    ]);
    const none = setupChangeWords(current, { modes, origin: null }, zones);
    expect(none.lines[0]).toMatch(/^No zone for origin hostnames any more/);
    expect(none.effect).toBe(
      'Recorded at once as generation 2. Nothing changes on the backend, or on nodes that already have a hostname or serve members.',
    );
  });

  test('the same account with another of its zones is another zone', () => {
    const current = view({ originDns: inOrg });
    const w = setupChangeWords(
      current,
      { modes, origin: { accountId: 'acct-1', zoneId: 'zone-net' } },
      zones,
    );
    expect(w.changed).toBe(true);
    expect(w.lines).toEqual(['Origin hostnames move from example.org to example.net.']);
    expect(w.effect).toContain('gets one under example.net');
    // A zone the lists do not show is named from the view, else not named at all.
    const unlisted = (accountId: string, zoneId: string) =>
      setupChangeWords(current, { modes, origin: { accountId, zoneId } }, []).lines;
    expect(unlisted('acct-2', 'zone-org')).toEqual([
      'Origin hostnames stay under example.org, through another account.',
    ]);
    expect(unlisted('acct-1', 'zone-net')).toEqual([
      'Origin hostnames move from example.org to another zone.',
    ]);
  });

  test('the current zone through the current account changes nothing', () => {
    const current = view({ originDns: inOrg });
    const w = setupChangeWords(
      current,
      { modes, origin: { accountId: 'acct-1', zoneId: 'zone-org' } },
      zones,
    );
    expect(w).toMatchObject({ changed: false, lines: [] });
  });

  test('an account whose zone is not picked yet changes nothing until it is', () => {
    const current = view({ originDns: inOrg });
    for (const accountId of ['acct-1', 'acct-3'])
      expect(
        setupChangeWords(current, { modes, origin: { accountId, zoneId: '' } }, zones),
      ).toMatchObject({ changed: false, lines: [] });
  });

  test('an added mode runs the setup again and says what stays', () => {
    const w = setupChangeWords(
      view({ generation: 3 }),
      {
        modes: [
          ...modes,
          {
            slug: 'freedom-extra',
            name: 'Freedom-Extra',
            shape: { transport: 'reality', fronting: 'edge-l4' },
            familySlug: 'fam-a',
            acceptProxyProtocol: false,
          },
        ],
        origin: null,
      },
      zones,
    );
    expect(w.lines).toEqual(['Adds the mode Freedom-Extra (REALITY, fronted through an edge).']);
    expect(w.effect).toMatch(/^The setup runs again as generation 4\. /);
    expect(w.effect).toContain('keep their transports, groups and placements');
    expect(w.effect).toContain('Members are not affected');
  });

  test('a mode a stopped run never set up can be taken out again', () => {
    const current = view();
    const stopped = BackendSetupView.parse({
      ...current,
      state: 'failed',
      modes: current.modes.map((m) =>
        m.slug === 'freedom-xhttp'
          ? { ...m, transport: null, group: { uuid: null, renamedFrom: null } }
          : m,
      ),
    });
    expect([...setUpSlugs(stopped)]).not.toContain('freedom-xhttp');
    const w = setupChangeWords(
      stopped,
      { modes: modes.filter((m) => m.slug !== 'freedom-xhttp'), origin: null },
      zones,
    );
    expect(w.lines).toEqual(['Takes out the mode Freedom-XHTTP, which was never set up.']);
    expect(w.effect).toBe(
      'The setup runs again as generation 2. Modes already set up keep their transports, groups and placements, and the run stops if one changed on the backend. No node can enroll or be approved until the run is done. Members are not affected.',
    );
  });

  test('the same setup changes nothing', () => {
    const w = setupChangeWords(view(), { modes, origin: null }, zones);
    expect(w).toMatchObject({ changed: false, lines: [] });
  });

  test('no em-dashes in any of it', () => {
    const all = [
      setupChangeWords(
        view(),
        { modes, origin: { accountId: 'acct-1', zoneId: 'zone-org' } },
        zones,
      ),
      setupChangeWords(view({ originDns: inOrg }), { modes, origin: null }, zones),
      setupChangeWords(
        view({ originDns: inOrg }),
        { modes, origin: { accountId: 'acct-2', zoneId: 'zone-org' } },
        zones,
      ),
    ].flatMap((w) => [...w.lines, w.effect, w.done]);
    for (const s of [...all, setupSummary(view())]) expect(s).not.toMatch(/—/);
  });
});

describe('the setup line on the Servers home', () => {
  test('says the zone, or that WebSocket nodes need a hostname of their own', () => {
    expect(setupSummary(view())).toBe(
      'Set up for 4 modes (generation 1). No zone for origin hostnames, so each WebSocket node needs one set by hand.',
    );
    expect(
      setupSummary(
        view({
          generation: 2,
          adopted: true,
          originDns: inOrg,
        }),
      ),
    ).toBe('Adopted and set up for 4 modes (generation 2). Origin hostnames under example.org.');
  });
});
