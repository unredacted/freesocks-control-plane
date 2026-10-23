import { describe, expect, it } from 'vitest';
import {
  EMPTY_ADDRESS_TRACK,
  EMPTY_HANDSHAKE_TRACK,
  batchReading,
  combinedState,
  expireAddressTrack,
  expireHandshakeTrack,
  nextAddressTrack,
  networkIdOf,
  nextHandshakeTrack,
  roundVerdict,
  stateUntil,
  trackUntil,
  type AddressTrack,
  type RoundRun,
  type RoundRunResult,
} from './verdict';

const CFG = { minProbes: 3, minNetworks: 2, minControls: 2 };
const MIN = 60_000;
const DAY = 24 * 60 * MIN;

const v = (country: string, ok: boolean, asn: string, control = false): RoundRunResult => ({
  country,
  asn,
  ok,
  ...(control ? { control: true } : {}),
});
const ext = (results: RoundRunResult[], over: Partial<RoundRun> = {}): RoundRun => ({
  source: 'checkhost',
  status: 'finished',
  family: 4,
  port: 443,
  address: '192.0.2.10',
  probeProtocol: 'tcp',
  results,
  ...over,
});
const internal = (ok: boolean, over: Partial<RoundRun> = {}): RoundRun => ({
  source: 'internal',
  status: 'finished',
  family: 4,
  port: 443,
  address: '192.0.2.10',
  probeProtocol: 'tls-sni',
  results: [{ country: 'XX', ok }],
  ...over,
});
const controls = (ok: boolean) => [v('DE', ok, 'AS1', true), v('US', ok, 'AS2', true)];

describe('roundVerdict', () => {
  it('proves an edge that works from enough vantages and passes the internal TLS check', () => {
    const r = roundVerdict(
      [
        ext([
          v('IR', true, 'AS10'),
          v('IR', true, 'AS11'),
          v('IR', true, 'AS12'),
          ...controls(true),
        ]),
        internal(true),
      ],
      'IR',
      CFG,
      true,
    );
    expect(r.result).toBe('proven');
    expect(r.ok).toBe(3);
    expect(r.controlsOk).toBe(3);
  });

  it('never proves without the internal TLS check where TLS applies', () => {
    const works = ext([v('IR', true, 'AS10'), v('IR', true, 'AS11'), v('IR', true, 'AS12')]);
    expect(roundVerdict([works], 'IR', CFG, true)).toMatchObject({
      result: 'unknown',
      reason: 'tls_unchecked',
    });
    expect(roundVerdict([works, internal(false)], 'IR', CFG, true)).toMatchObject({
      result: 'unknown',
      reason: 'tls_failed',
    });
    // A plaintext listener has no name to check.
    expect(roundVerdict([works], 'IR', CFG, false).result).toBe('proven');
  });

  it('blocks only when every vantage fails, the spread is met and the controls work', () => {
    const failing = [v('IR', false, 'AS10'), v('IR', false, 'AS11'), v('IR', false, 'AS12')];
    expect(roundVerdict([ext([...failing, ...controls(true)])], 'IR', CFG, false).result).toBe(
      'blocked',
    );
    // FCP's own check counts as one control.
    expect(
      roundVerdict(
        [ext([...failing, v('DE', true, 'AS1', true)]), internal(true, { probeProtocol: 'tcp' })],
        'IR',
        CFG,
        false,
      ).result,
    ).toBe('blocked');
  });

  it('calls it down, not blocked, when the controls fail too', () => {
    const failing = [v('IR', false, 'AS10'), v('IR', false, 'AS11'), v('IR', false, 'AS12')];
    expect(roundVerdict([ext([...failing, ...controls(false)])], 'IR', CFG, false)).toMatchObject({
      result: 'down',
      reason: 'controls_failed',
    });
  });

  it('treats a source that errors as no evidence, never as blocked', () => {
    // Globalping failed outright; check-host saw one failing vantage.
    const r = roundVerdict(
      [
        ext([], { source: 'globalping', status: 'failed' }),
        ext([v('IR', false, 'AS10'), ...controls(true)]),
      ],
      'IR',
      CFG,
      false,
    );
    expect(r).toMatchObject({ result: 'unknown', reason: 'too_few' });
    // A run still in flight or timed out is no evidence either.
    expect(
      roundVerdict(
        [
          ext([v('IR', false, 'AS10'), v('IR', false, 'AS11'), v('IR', false, 'AS12')], {
            status: 'timeout',
          }),
        ],
        'IR',
        CFG,
        false,
      ),
    ).toMatchObject({ result: 'unknown', reason: 'no_evidence' });
  });

  it('needs distinct networks: three vantages of one network are thin', () => {
    const r = roundVerdict(
      [
        ext([
          v('IR', false, 'AS10'),
          v('IR', false, 'AS10'),
          v('IR', false, 'AS10'),
          ...controls(true),
        ]),
      ],
      'IR',
      CFG,
      false,
    );
    expect(r).toMatchObject({ result: 'unknown', reason: 'too_few' });
  });

  it('never counts a vantage without a network as one, across sources either', () => {
    const anon = (ok: boolean): RoundRunResult => ({ country: 'IR', ok });
    // Two failing from one service and one from another, none with an ASN or a
    // network: that is not two networks, however many services answered.
    const r = roundVerdict(
      [
        ext([anon(false), anon(false), ...controls(true)], { source: 'globalping' }),
        ext([anon(false)], { source: 'checkhost' }),
      ],
      'IR',
      CFG,
      false,
    );
    expect(r).toMatchObject({ result: 'unknown', reason: 'too_few', networks: 0 });
    // Nor can missing metadata make a positive verdict.
    const ok = roundVerdict(
      [
        ext([anon(true), anon(true)], { source: 'globalping' }),
        ext([anon(true), v('IR', true, 'AS10')], { source: 'checkhost' }),
      ],
      'IR',
      CFG,
      false,
    );
    expect(ok).toMatchObject({ result: 'unknown', networks: 1 });
  });

  it('compares network ids normalized', () => {
    expect(networkIdOf({ asn: 'AS1234' })).toBe('AS1234');
    expect(networkIdOf({ asn: 'as1234' })).toBe('AS1234');
    expect(networkIdOf({ asn: '1234' })).toBe('AS1234');
    expect(networkIdOf({ network: ' Example Net ' })).toBe('net:example net');
    expect(networkIdOf({})).toBeNull();
    // The same network spelled two ways by two services is one network.
    const r = roundVerdict(
      [
        ext([v('IR', false, 'AS10'), v('IR', false, 'as10')], { source: 'globalping' }),
        ext([v('IR', false, '10'), ...controls(true)], { source: 'checkhost' }),
      ],
      'IR',
      CFG,
      false,
    );
    expect(r).toMatchObject({ result: 'unknown', reason: 'too_few', networks: 1 });
  });

  it('is mixed (unknown) when more than a third fail with some working', () => {
    const r = roundVerdict(
      [
        ext([
          v('IR', true, 'AS10'),
          v('IR', true, 'AS11'),
          v('IR', false, 'AS12'),
          v('IR', false, 'AS13'),
        ]),
      ],
      'IR',
      CFG,
      false,
    );
    expect(r).toMatchObject({ result: 'unknown', reason: 'mixed' });
  });

  it('takes the worst port: one blocked listener blocks the slot', () => {
    const good = ext([v('IR', true, 'AS10'), v('IR', true, 'AS11'), v('IR', true, 'AS12')]);
    const bad = ext(
      [v('IR', false, 'AS10'), v('IR', false, 'AS11'), v('IR', false, 'AS12'), ...controls(true)],
      { port: 8443 },
    );
    const r = roundVerdict([good, bad], 'IR', CFG, false);
    expect(r.result).toBe('blocked');
    expect(r.paths.map((p) => [p.port, p.result])).toEqual([
      [443, 'proven'],
      [8443, 'blocked'],
    ]);
  });

  it('follows IPv4 and reports IPv6 beside it', () => {
    const v4 = ext([v('IR', true, 'AS10'), v('IR', true, 'AS11'), v('IR', true, 'AS12')]);
    const v6 = ext(
      [v('IR', false, 'AS10'), v('IR', false, 'AS11'), v('IR', false, 'AS12'), ...controls(true)],
      { family: 6, address: '2001:db8::10' },
    );
    expect(roundVerdict([v4, v6], 'IR', CFG, false)).toMatchObject({
      result: 'proven',
      v6Result: 'blocked',
    });
  });

  it('ignores other countries and control rows for the country itself', () => {
    const r = roundVerdict(
      [
        ext([
          v('RU', false, 'AS10'),
          v('RU', false, 'AS11'),
          v('RU', false, 'AS12'),
          v('IR', true, 'AS1', true),
        ]),
      ],
      'IR',
      CFG,
      false,
    );
    expect(r).toMatchObject({ result: 'unknown', reason: 'no_evidence', ok: 0 });
  });

  it('keeps a TCP reading per path for handshake pairing', () => {
    const r = roundVerdict(
      [ext([v('IR', true, 'AS10'), v('IR', true, 'AS11'), v('IR', true, 'AS12')])],
      'IR',
      CFG,
      true,
    );
    expect(r.paths[0]).toMatchObject({ tcp: 'works', address: '192.0.2.10', port: 443, family: 4 });
  });
});

const OPTS = {
  blockedRounds: 2,
  windowMs: 14 * DAY,
  repeatMs: 30 * MIN,
  groupBlocked: false,
  countryWideHold: false,
};
const T0 = 1_000_000_000_000;
const round = (result: 'proven' | 'blocked' | 'down' | 'unknown', at: number) => ({
  result,
  reason: result === 'unknown' ? 'too_few' : result === 'down' ? 'controls_failed' : null,
  at,
});

describe('nextAddressTrack', () => {
  const proven = nextAddressTrack(EMPTY_ADDRESS_TRACK, round('proven', T0), OPTS);

  it('decides proven in one round, with an expiry', () => {
    expect(proven).toMatchObject({ state: 'proven', decidedAt: T0, until: T0 + 14 * DAY });
  });

  it('needs two blocked rounds at least 30 minutes apart to go from proven to blocked', () => {
    const one = nextAddressTrack(proven, round('blocked', T0 + DAY), OPTS);
    expect(one).toMatchObject({ state: 'proven', reason: 'needs_repeat', blockedRounds: 1 });
    expect(one.repeatAt).toBe(T0 + DAY + 30 * MIN);
    // Ten minutes later is the same look.
    const soon = nextAddressTrack(one, round('blocked', T0 + DAY + 10 * MIN), OPTS);
    expect(soon).toMatchObject({ state: 'proven', blockedRounds: 1 });
    const two = nextAddressTrack(soon, round('blocked', T0 + DAY + 31 * MIN), OPTS);
    expect(two).toMatchObject({ state: 'blocked', blockedRounds: 2, reason: 'blocked' });
    expect(two.repeatAt).toBeUndefined();
  });

  it('goes back to proven in one round', () => {
    const blocked: AddressTrack = {
      state: 'blocked',
      decidedAt: T0,
      until: T0 + DAY,
      blockedRounds: 2,
    };
    expect(nextAddressTrack(blocked, round('proven', T0 + MIN), OPTS)).toMatchObject({
      state: 'proven',
      blockedRounds: 0,
    });
  });

  it('never lets unknown or down override a decided state', () => {
    for (const r of ['unknown', 'down'] as const) {
      expect(nextAddressTrack(proven, round(r, T0 + MIN), OPTS).state).toBe('proven');
    }
    const fresh = nextAddressTrack(EMPTY_ADDRESS_TRACK, round('unknown', T0), OPTS);
    expect(fresh).toMatchObject({ state: 'unknown', reason: 'too_few' });
  });

  it('keeps a never-checked edge unknown on its first blocked round...', () => {
    expect(nextAddressTrack(EMPTY_ADDRESS_TRACK, round('blocked', T0), OPTS)).toMatchObject({
      state: 'unknown',
      reason: 'needs_repeat',
    });
  });

  it('...unless its group is already blocked there', () => {
    expect(
      nextAddressTrack(EMPTY_ADDRESS_TRACK, round('blocked', T0), { ...OPTS, groupBlocked: true }),
    ).toMatchObject({ state: 'blocked', reason: 'group_blocked' });
  });

  it('blocks an address never reached from there at once when its unreachability is sustained', () => {
    const S = { ...OPTS, sustained: true };
    // A thin round (one vantage) decides nothing alone; sustained evidence does.
    const thin = nextAddressTrack(EMPTY_ADDRESS_TRACK, round('unknown', T0), S);
    expect(thin).toMatchObject({
      state: 'blocked',
      reason: 'never_reached',
      decidedAt: T0,
      until: T0 + 14 * DAY,
    });
    // A blocked round needs no repeat either.
    expect(nextAddressTrack(EMPTY_ADDRESS_TRACK, round('blocked', T0), S)).toMatchObject({
      state: 'blocked',
      reason: 'never_reached',
      blockedRounds: 1,
    });
    // While it holds, an undecided round re-confirms the block.
    const later = nextAddressTrack(thin, round('unknown', T0 + DAY), S);
    expect(later).toMatchObject({
      state: 'blocked',
      reason: 'never_reached',
      until: T0 + 15 * DAY,
    });
    // The controls failing too (down) is broken, not blocked.
    expect(nextAddressTrack(EMPTY_ADDRESS_TRACK, round('down', T0), S).state).toBe('unknown');
    // The country-wide guard holds it like any new block.
    expect(
      nextAddressTrack(EMPTY_ADDRESS_TRACK, round('unknown', T0), { ...S, countryWideHold: true }),
    ).toMatchObject({ state: 'unknown', reason: 'country_wide' });
    // Reached once is proven at once.
    expect(nextAddressTrack(thin, round('proven', T0 + MIN), S).state).toBe('proven');
  });

  it('holds new blocks while the country-wide guard is on', () => {
    const held = nextAddressTrack(proven, round('blocked', T0 + MIN), {
      ...OPTS,
      countryWideHold: true,
    });
    expect(held).toMatchObject({ state: 'proven', reason: 'country_wide', blockedRounds: 0 });
  });

  it('expires a decided state at its until, and lets an unanswered repeat go', () => {
    expect(expireAddressTrack(proven, T0 + 14 * DAY)).toMatchObject({
      state: 'unknown',
      reason: 'expired',
    });
    expect(expireAddressTrack(proven, T0 + DAY)).toBe(proven);
    const one = nextAddressTrack(proven, round('blocked', T0), OPTS);
    const later = nextAddressTrack(one, round('unknown', T0 + 40 * MIN), OPTS);
    expect(later).toMatchObject({ state: 'proven', blockedRounds: 1 });
    expect(later.repeatAt).toBeUndefined();
  });
});

const HOPTS = { windowMs: 14 * DAY, repeatMs: 60 * MIN, groupBlocked: false };

describe('nextHandshakeTrack', () => {
  it('blocks after two paired path batches at least an hour apart', () => {
    const one = nextHandshakeTrack(
      EMPTY_HANDSHAKE_TRACK,
      { reading: 'path', at: T0, paired: true },
      HOPTS,
    );
    expect(one).toMatchObject({ state: 'none', reason: 'needs_repeat', pathBatches: [T0] });
    const soon = nextHandshakeTrack(
      one,
      { reading: 'path', at: T0 + 10 * MIN, paired: true },
      HOPTS,
    );
    expect(soon.state).toBe('none');
    const two = nextHandshakeTrack(
      soon,
      { reading: 'path', at: T0 + 61 * MIN, paired: true },
      HOPTS,
    );
    expect(two).toMatchObject({ state: 'blocked', reason: 'handshake' });
  });

  it('blocks on one paired batch when the group is already blocked there', () => {
    expect(
      nextHandshakeTrack(
        EMPTY_HANDSHAKE_TRACK,
        { reading: 'path', at: T0, paired: true },
        {
          ...HOPTS,
          groupBlocked: true,
        },
      ).state,
    ).toBe('blocked');
  });

  it('records an unpaired path batch and changes nothing else', () => {
    const r = nextHandshakeTrack(
      EMPTY_HANDSHAKE_TRACK,
      { reading: 'path', at: T0, paired: false },
      HOPTS,
    );
    expect(r).toMatchObject({ state: 'none', reason: 'no_tcp_pairing', pathBatches: [] });
  });

  it('clears only by recovery or expiry, never by a working TCP round', () => {
    const blocked = nextHandshakeTrack(
      { state: 'none', pathBatches: [T0] },
      { reading: 'path', at: T0 + 2 * 60 * MIN, paired: true },
      HOPTS,
    );
    expect(blocked.state).toBe('blocked');
    // A TCP round proving the address does not touch the handshake track.
    const addr = nextAddressTrack(EMPTY_ADDRESS_TRACK, round('proven', T0 + 3 * 60 * MIN), OPTS);
    expect(combinedState(addr, blocked)).toBe('blocked');
    // A batch where nothing conclusive came back changes nothing.
    expect(
      nextHandshakeTrack(blocked, { reading: 'none', at: T0 + 4 * 60 * MIN, paired: true }, HOPTS)
        .state,
    ).toBe('blocked');
    expect(
      nextHandshakeTrack(
        blocked,
        { reading: 'recovery', at: T0 + 5 * 60 * MIN, paired: false },
        HOPTS,
      ),
    ).toMatchObject({ state: 'none', reason: 'recovered', pathBatches: [] });
    expect(expireHandshakeTrack(blocked, blocked.until!)).toMatchObject({
      state: 'none',
      reason: 'expired',
    });
  });
});

describe('combinedState and trackUntil', () => {
  it('is blocked if either track is, proven only when the address is and the handshake is not', () => {
    const p: AddressTrack = { state: 'proven', until: T0 + 5, blockedRounds: 0 };
    expect(combinedState(p, EMPTY_HANDSHAKE_TRACK)).toBe('proven');
    expect(combinedState(EMPTY_ADDRESS_TRACK, EMPTY_HANDSHAKE_TRACK)).toBe('unknown');
    expect(combinedState(p, { state: 'blocked', until: T0 + 3, pathBatches: [] })).toBe('blocked');
    expect(trackUntil(p, { state: 'blocked', until: T0 + 3, pathBatches: [] })).toBe(T0 + 3);
    expect(trackUntil(EMPTY_ADDRESS_TRACK, EMPTY_HANDSHAKE_TRACK)).toBeUndefined();
  });

  it('a block holds while any blocking track does, not until the earliest track lapses', () => {
    const proof: AddressTrack = { state: 'proven', until: T0 + 5, blockedRounds: 0 };
    const block = { state: 'blocked' as const, until: T0 + 9, pathBatches: [] };
    expect(trackUntil(proof, block)).toBe(T0 + 5);
    expect(stateUntil(proof, block)).toBe(T0 + 9);
    const both: AddressTrack = { state: 'blocked', until: T0 + 12, blockedRounds: 2 };
    expect(stateUntil(both, block)).toBe(T0 + 12);
    expect(stateUntil(proof, EMPTY_HANDSHAKE_TRACK)).toBe(T0 + 5);
    expect(stateUntil(EMPTY_ADDRESS_TRACK, EMPTY_HANDSHAKE_TRACK)).toBeUndefined();
  });
});

describe('batchReading', () => {
  const m = (
    name: string,
    outcomes: Array<[string, 'ok' | 'reset' | 'timeout' | 'error']>,
    source = 'globalping',
  ) => ({
    name,
    source,
    results: outcomes.map(([asn, outcome]) => ({ asn, outcome })),
  });
  const o = { minVantages: 3, minNetworks: 2 };
  const names = ['a.example.org', 'b.example.org', 'c.example.org'];

  it('reads path when no name got through from enough vantages', () => {
    expect(
      batchReading(
        names.map((n) =>
          m(n, [
            ['AS1', 'reset'],
            ['AS2', 'timeout'],
            ['AS3', 'reset'],
          ]),
        ),
        o,
      ),
    ).toEqual({ reading: 'path', vantages: 3, networks: 3 });
  });

  it('counts the same probes once however many names they tried', () => {
    // Two probes, three names: two vantages, not six.
    const failing = names.map((n) =>
      m(n, [
        ['AS1', 'reset'],
        ['AS2', 'reset'],
      ]),
    );
    expect(batchReading(failing, o)).toEqual({ reading: 'none', vantages: 2, networks: 2 });
    const working = names.map((n) =>
      m(n, [
        ['AS1', 'ok'],
        ['AS2', 'ok'],
      ]),
    );
    expect(batchReading(working, o)).toEqual({ reading: 'none', vantages: 2, networks: 2 });
    // A second service's probes are other vantages.
    expect(
      batchReading(
        [
          ...failing,
          m('a.example.org', [['AS3', 'reset']], 'ripeatlas'),
          m('b.example.org', [['AS3', 'timeout']], 'ripeatlas'),
        ],
        o,
      ).reading,
    ).toBe('path');
  });

  it('reads recovery when names reach the address from enough vantages', () => {
    expect(
      batchReading(
        [
          m('a.example.org', [
            ['AS1', 'ok'],
            ['AS2', 'ok'],
            ['AS3', 'ok'],
          ]),
        ],
        o,
      ).reading,
    ).toBe('recovery');
  });

  it('reads none when one name got through but not from enough vantages, or the failures are errors', () => {
    expect(
      batchReading(
        [
          m('a.example.org', [
            ['AS1', 'ok'],
            ['AS2', 'reset'],
            ['AS3', 'reset'],
          ]),
        ],
        o,
      ).reading,
    ).toBe('none');
    expect(
      batchReading(
        [
          m('a.example.org', [
            ['AS1', 'error'],
            ['AS2', 'error'],
            ['AS3', 'error'],
          ]),
        ],
        o,
      ).reading,
    ).toBe('none');
  });
});
