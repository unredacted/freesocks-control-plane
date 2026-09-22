/**
 * The pure half of origin registration: spec validation against the catalogue
 * and the origin kind, the order-insensitive-for-names idempotency hash, the
 * name-merge ownership rules, the own-source-only prune diff and the
 * match-rule overlap check.
 */
import { ConvexError } from 'convex/values';
import { describe, expect, test } from 'vitest';
import type { Id } from '../../_generated/dataModel';
import type { RelayOrigin } from './origin';
import {
  assertNoMatchOverlap,
  diffListeners,
  fnv1a64Hex,
  listenerConfigHash,
  mergeNames,
  normalizeName,
  validateListenerSpec,
  type CanonicalListener,
  type ListenerName,
  type ListenerSpecInput,
} from './registration';

const SERVER = 'server_1' as Id<'backendServers'>;
const PANEL: RelayOrigin = { kind: 'panel-node', backendServerId: SERVER, nodeName: 'node-one' };
const WHOLE_SERVER: RelayOrigin = { kind: 'backend-server', backendServerId: SERVER };
const MANUAL: RelayOrigin = { kind: 'manual' };

const BINDING = {
  inboundTag: 'VLESS_RELAY_A',
  configProfileUuid: '11111111-1111-4111-8111-111111111111',
  configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
};

function reality(over: Partial<ListenerSpecInput> = {}): ListenerSpecInput {
  return {
    listenerKey: 'a',
    protocol: 'vless',
    streamTransport: 'raw',
    security: 'reality',
    originPort: 443,
    tlsNames: ['a.example', 'b.example'],
    realityTarget: { address: 'target.example', port: 443 },
    panelBinding: BINDING,
    ...over,
  };
}

function ws(over: Partial<ListenerSpecInput> = {}): ListenerSpecInput {
  return {
    listenerKey: 'w',
    protocol: 'vless',
    streamTransport: 'ws',
    security: 'tls',
    originPort: 443,
    tlsNames: ['ws.example'],
    transportParams: { path: '/ws' },
    originTransport: {
      scheme: 'https',
      certPublic: true,
      certNames: ['*.origin.example'],
      acceptsHostHeader: 'any',
    },
    panelBinding: {
      ...BINDING,
      inboundTag: 'VLESS_WS',
      configProfileInboundUuid: '33333333-3333-4333-8333-333333333333',
    },
    ...over,
  };
}

function shadowsocks(over: Partial<ListenerSpecInput> = {}): ListenerSpecInput {
  return {
    listenerKey: 's',
    protocol: 'shadowsocks',
    streamTransport: 'raw',
    security: 'none',
    originPort: 8388,
    panelBinding: {
      ...BINDING,
      inboundTag: 'SS_IN',
      configProfileInboundUuid: '44444444-4444-4444-8444-444444444444',
    },
    ...over,
  };
}

function code(fn: () => unknown): string | null {
  try {
    fn();
    return null;
  } catch (err) {
    if (err instanceof ConvexError) return (err.data as { code: string }).code;
    throw err;
  }
}

describe('validateListenerSpec', () => {
  test('a valid REALITY backend listener canonicalises: names normalised (order kept), remark derived, deployed defaults on', () => {
    const c = validateListenerSpec(
      reality({
        tlsNames: ['B.Example.', 'a.example', 'b.example'],
        realityTarget: { address: 'Target.Example.', port: 443 },
      }),
      { origin: PANEL },
    );
    expect(c).toMatchObject({
      listenerKey: 'a',
      protocol: 'vless',
      streamTransport: 'raw',
      security: 'reality',
      transport: 'tcp',
      originPort: 443,
      // Body order, lower-cased, trailing dot dropped, duplicates collapsed; NEVER re-sorted.
      tlsNames: ['b.example', 'a.example'],
      realityTarget: { address: 'target.example', port: 443 },
      matchRule: { kind: 'remark', remark: 'node-one-relay-a' },
      deployed: true,
    });
    expect(c.panelBinding).toEqual({
      inboundTag: 'VLESS_RELAY_A',
      configProfileUuid: BINDING.configProfileUuid,
      configProfileInboundUuid: BINDING.configProfileInboundUuid,
    });
    expect(c.transportParams).toBeUndefined();
    expect(c.providerScope).toBeUndefined();
    // Uppercase UUIDs are lower-cased in the canonical binding.
    const upper = validateListenerSpec(
      reality({
        panelBinding: { ...BINDING, configProfileUuid: BINDING.configProfileUuid.toUpperCase() },
      }),
      { origin: PANEL },
    );
    expect(upper.panelBinding?.configProfileUuid).toBe(BINDING.configProfileUuid);
  });

  test('invalid_combination is its own code; an unsupported triple never reaches the field rules', () => {
    expect(
      code(() =>
        validateListenerSpec(
          reality({ protocol: 'shadowsocks', streamTransport: 'raw', security: 'reality' }),
          { origin: PANEL },
        ),
      ),
    ).toBe('invalid_combination');
    expect(
      code(() =>
        validateListenerSpec(
          reality({ protocol: 'vless', streamTransport: 'udp', security: 'tls' }),
          {
            origin: PANEL,
          },
        ),
      ),
    ).toBe('invalid_combination');
    expect(
      code(() =>
        validateListenerSpec(reality({ streamTransport: 'ws', security: 'reality' }), {
          origin: PANEL,
        }),
      ),
    ).toBe('invalid_combination');
  });

  test('listenerKey: 1-16 lowercase alphanumerics', () => {
    for (const bad of ['', 'A', 'a-b', 'a'.repeat(17), 'with space']) {
      expect(() => validateListenerSpec(reality({ listenerKey: bad }), { origin: PANEL })).toThrow(
        /listenerKey/,
      );
    }
    expect(
      validateListenerSpec(reality({ listenerKey: 'a'.repeat(16) }), { origin: PANEL }).listenerKey,
    ).toBe('a'.repeat(16));
  });

  test('ports are validated (origin and REALITY target)', () => {
    expect(() => validateListenerSpec(reality({ originPort: 0 }), { origin: PANEL })).toThrow(
      /originPort out of range/,
    );
    expect(() => validateListenerSpec(reality({ originPort: 65536 }), { origin: PANEL })).toThrow(
      /originPort out of range/,
    );
    expect(() => validateListenerSpec(reality({ originPort: 443.5 }), { origin: PANEL })).toThrow(
      /originPort out of range/,
    );
    expect(() =>
      validateListenerSpec(reality({ realityTarget: { address: 'target.example', port: 70000 } }), {
        origin: PANEL,
      }),
    ).toThrow(/realityTarget.port out of range/);
  });

  test('server names: normalised, capped at 32, required for SNI listeners, forbidden for plain ones', () => {
    expect(() =>
      validateListenerSpec(reality({ tlsNames: ['not a host'] }), { origin: PANEL }),
    ).toThrow(/invalid server name/);
    expect(() =>
      validateListenerSpec(
        reality({ tlsNames: Array.from({ length: 33 }, (_, i) => `n${i}.example`) }),
        { origin: PANEL },
      ),
    ).toThrow(/at most 32 server names/);
    // REALITY presents a name: an empty list is refused ...
    expect(() => validateListenerSpec(reality({ tlsNames: [] }), { origin: PANEL })).toThrow(
      /needs at least one server name/,
    );
    expect(() => validateListenerSpec(reality({ tlsNames: null }), { origin: PANEL })).toThrow(
      /needs at least one server name/,
    );
    // ... unless the listener is L7-only (an http origin transport): the fronted hostname IS the name.
    const l7Only = validateListenerSpec(
      ws({
        tlsNames: [],
        originTransport: {
          scheme: 'http',
          certPublic: false,
          certNames: [],
          acceptsHostHeader: 'any',
        },
      }),
      { origin: PANEL },
    );
    expect(l7Only.tlsNames).toEqual([]);
    // Shadowsocks presents no name at all.
    expect(() =>
      validateListenerSpec(shadowsocks({ tlsNames: ['x.example'] }), { origin: PANEL }),
    ).toThrow(/presents no server name/);
    expect(validateListenerSpec(shadowsocks(), { origin: PANEL }).tlsNames).toEqual([]);
  });

  test('realityTarget: required for REALITY, refused for anything else, address validated', () => {
    expect(() => validateListenerSpec(reality({ realityTarget: null }), { origin: PANEL })).toThrow(
      /needs realityTarget/,
    );
    expect(() =>
      validateListenerSpec(reality({ realityTarget: { address: 'bad host!', port: 443 } }), {
        origin: PANEL,
      }),
    ).toThrow(/invalid realityTarget address/);
    // An IP literal is an acceptable target address.
    expect(
      validateListenerSpec(reality({ realityTarget: { address: '203.0.113.5', port: 443 } }), {
        origin: PANEL,
      }).realityTarget,
    ).toEqual({ address: '203.0.113.5', port: 443 });
    expect(() =>
      validateListenerSpec(ws({ realityTarget: { address: 'target.example', port: 443 } }), {
        origin: PANEL,
      }),
    ).toThrow(/impersonates no target/);
  });

  test('transportParams: only for HTTP transports, copied field by field', () => {
    expect(() =>
      validateListenerSpec(reality({ transportParams: { path: '/x' } }), { origin: PANEL }),
    ).toThrow(/no HTTP transport parameters/);
    const c = validateListenerSpec(
      ws({
        transportParams: {
          path: '/ws',
          host: 'h.example',
          serviceName: undefined,
          upgradeToken: 'tok',
        },
      }),
      { origin: PANEL },
    );
    expect(c.transportParams).toEqual({ path: '/ws', host: 'h.example', upgradeToken: 'tok' });
    const grpc = validateListenerSpec(
      ws({
        streamTransport: 'grpc',
        transportParams: { serviceName: 'svc' },
        tlsNames: ['g.example'],
      }),
      { origin: PANEL },
    );
    expect(grpc.transportParams).toEqual({ serviceName: 'svc' });
  });

  test('originTransport: certificate names normalised + deduped, a public https origin must name its certificate', () => {
    const c = validateListenerSpec(
      ws({
        originTransport: {
          scheme: 'https',
          certPublic: true,
          certNames: ['*.Origin.Example.', 'origin.example', 'origin.example'],
          acceptsHostHeader: 'names',
        },
      }),
      { origin: PANEL },
    );
    expect(c.originTransport).toEqual({
      scheme: 'https',
      certPublic: true,
      certNames: ['*.origin.example', 'origin.example'],
      acceptsHostHeader: 'names',
    });
    expect(() =>
      validateListenerSpec(
        ws({
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: [],
            acceptsHostHeader: 'any',
          },
        }),
        { origin: PANEL },
      ),
    ).toThrow(/must name its certificate/);
    expect(() =>
      validateListenerSpec(
        ws({
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: ['f*.example'],
            acceptsHostHeader: 'any',
          },
        }),
        { origin: PANEL },
      ),
    ).toThrow(/invalid certificate name/);
    expect(() =>
      validateListenerSpec(
        ws({
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: Array.from({ length: 17 }, (_, i) => `c${i}.example`),
            acceptsHostHeader: 'any',
          },
        }),
        { origin: PANEL },
      ),
    ).toThrow(/at most 16/);
  });

  test('panelBinding: backend-node origins only; UUIDs and the transport tag are checked', () => {
    expect(() => validateListenerSpec(reality(), { origin: WHOLE_SERVER })).toThrow(
      /panelBinding is only valid for a backend-node origin/,
    );
    expect(() => validateListenerSpec(reality(), { origin: MANUAL })).toThrow(
      /panelBinding is only valid for a backend-node origin/,
    );
    expect(() =>
      validateListenerSpec(reality({ panelBinding: { ...BINDING, configProfileUuid: 'nope' } }), {
        origin: PANEL,
      }),
    ).toThrow(/must be UUIDs/);
    expect(() =>
      validateListenerSpec(reality({ panelBinding: { ...BINDING, inboundTag: 'lower-case' } }), {
        origin: PANEL,
      }),
    ).toThrow(/inboundTag/);
  });

  test('matchRule: defaults to the remark for a bound backend listener, to `address` otherwise; a remark rule needs a binding', () => {
    // Without a binding a backend listener matches by address (no Host to own).
    const unbound = validateListenerSpec(reality({ panelBinding: null }), { origin: PANEL });
    expect(unbound.matchRule).toEqual({ kind: 'address' });
    expect(unbound.panelBinding).toBeUndefined();
    const server = validateListenerSpec(reality({ panelBinding: null }), { origin: WHOLE_SERVER });
    expect(server.matchRule).toEqual({ kind: 'address' });
    const manual = validateListenerSpec(reality({ panelBinding: null }), { origin: MANUAL });
    expect(manual.matchRule).toEqual({ kind: 'address' });
    // An explicit remark overrides the derived one (trimmed) but needs the binding.
    const explicit = validateListenerSpec(
      reality({ matchRule: { kind: 'remark', remark: '  custom-remark ' } }),
      {
        origin: PANEL,
      },
    );
    expect(explicit.matchRule).toEqual({ kind: 'remark', remark: 'custom-remark' });
    expect(() =>
      validateListenerSpec(
        reality({ panelBinding: null, matchRule: { kind: 'remark', remark: 'x' } }),
        {
          origin: PANEL,
        },
      ),
    ).toThrow(/needs a panelBinding/);
    expect(() =>
      validateListenerSpec(reality({ matchRule: { kind: 'remark', remark: '   ' } }), {
        origin: PANEL,
      }),
    ).toThrow(/invalid remark/);
    expect(() =>
      validateListenerSpec(reality({ matchRule: { kind: 'remark', remark: 'r'.repeat(129) } }), {
        origin: PANEL,
      }),
    ).toThrow(/invalid remark/);
    expect(
      validateListenerSpec(reality({ matchRule: { kind: 'whole-body' } }), { origin: PANEL })
        .matchRule,
    ).toEqual({ kind: 'whole-body' });
  });

  test('providerScope is copied (provider, optional accountId); deployed:false is honoured', () => {
    const c = validateListenerSpec(
      reality({ providerScope: { provider: 'gcore', accountId: 'acct_1' }, deployed: false }),
      { origin: PANEL },
    );
    expect(c.providerScope).toEqual({ provider: 'gcore', accountId: 'acct_1' });
    expect(c.deployed).toBe(false);
    expect(
      validateListenerSpec(reality({ providerScope: { provider: 'upcloud' } }), { origin: PANEL })
        .providerScope,
    ).toEqual({ provider: 'upcloud' });
  });

  test('normalizeName lower-cases, trims, drops the trailing dot and rejects non-hostnames', () => {
    expect(normalizeName(' A.Example. ')).toBe('a.example');
    expect(normalizeName('not a host')).toBeNull();
    expect(normalizeName(42)).toBeNull();
    expect(normalizeName('')).toBeNull();
  });
});

describe('listenerConfigHash', () => {
  const base = () => validateListenerSpec(reality(), { origin: PANEL });

  test('is deterministic and order-insensitive for names (set semantics)', () => {
    const a = validateListenerSpec(reality({ tlsNames: ['a.example', 'b.example'] }), {
      origin: PANEL,
    });
    const b = validateListenerSpec(reality({ tlsNames: ['b.example', 'a.example'] }), {
      origin: PANEL,
    });
    expect(a.tlsNames).not.toEqual(b.tlsNames); // persisted order differs ...
    expect(listenerConfigHash(a)).toBe(listenerConfigHash(b)); // ... the hash does not.
    expect(listenerConfigHash(base())).toBe(listenerConfigHash(base()));
    expect(listenerConfigHash(base())).toMatch(/^[0-9a-f]{16}$/);
  });

  test('is sensitive to every other field', () => {
    const h0 = listenerConfigHash(base());
    const variants: Array<[string, CanonicalListener]> = [
      ['names set', validateListenerSpec(reality({ tlsNames: ['a.example'] }), { origin: PANEL })],
      ['originPort', validateListenerSpec(reality({ originPort: 8443 }), { origin: PANEL })],
      [
        'target',
        validateListenerSpec(reality({ realityTarget: { address: 'other.example', port: 443 } }), {
          origin: PANEL,
        }),
      ],
      [
        'target port',
        validateListenerSpec(
          reality({ realityTarget: { address: 'target.example', port: 8443 } }),
          { origin: PANEL },
        ),
      ],
      [
        'inbound',
        validateListenerSpec(
          reality({
            panelBinding: {
              ...BINDING,
              configProfileInboundUuid: '55555555-5555-4555-8555-555555555555',
            },
          }),
          { origin: PANEL },
        ),
      ],
      [
        'transport tag',
        validateListenerSpec(reality({ panelBinding: { ...BINDING, inboundTag: 'OTHER' } }), {
          origin: PANEL,
        }),
      ],
      [
        'match rule',
        validateListenerSpec(reality({ matchRule: { kind: 'remark', remark: 'custom' } }), {
          origin: PANEL,
        }),
      ],
      [
        'provider scope',
        validateListenerSpec(reality({ providerScope: { provider: 'gcore' } }), { origin: PANEL }),
      ],
      ['deployed', validateListenerSpec(reality({ deployed: false }), { origin: PANEL })],
      [
        'security',
        validateListenerSpec(reality({ security: 'tls', realityTarget: null }), { origin: PANEL }),
      ],
    ];
    const seen = new Set<string>([h0]);
    for (const [label, c] of variants) {
      const h = listenerConfigHash(c);
      expect(h, label).not.toBe(h0);
      expect(seen.has(h), `${label} collides`).toBe(false);
      seen.add(h);
    }
    // HTTP-transport fields too.
    const w0 = listenerConfigHash(validateListenerSpec(ws(), { origin: PANEL }));
    expect(
      listenerConfigHash(
        validateListenerSpec(ws({ transportParams: { path: '/other' } }), { origin: PANEL }),
      ),
    ).not.toBe(w0);
    expect(
      listenerConfigHash(
        validateListenerSpec(
          ws({
            originTransport: {
              scheme: 'https',
              certPublic: false,
              certNames: ['*.origin.example'],
              acceptsHostHeader: 'any',
            },
          }),
          { origin: PANEL },
        ),
      ),
    ).not.toBe(w0);
    // The listenerKey itself is NOT part of the hash (the diff keys on it); only
    // the remark it DERIVES is, so pin the remark to compare.
    expect(
      listenerConfigHash(
        validateListenerSpec(
          reality({ listenerKey: 'zz', matchRule: { kind: 'remark', remark: 'node-one-relay-a' } }),
          { origin: PANEL },
        ),
      ),
    ).toBe(h0);
  });

  test('fnv1a64Hex is the documented 64-bit FNV-1a', () => {
    expect(fnv1a64Hex('')).toBe('cbf29ce484222325');
    expect(fnv1a64Hex('a')).toBe('af63dc4c8601ec8c');
    expect(fnv1a64Hex('a')).not.toBe(fnv1a64Hex('b'));
  });
});

describe('mergeNames', () => {
  const NOW = 1_700_000_000_000;
  const DRAIN = 60_000;
  const active = (name: string): ListenerName => ({ name, status: 'active' });
  const retiredBy = (name: string, by: 'admin' | 'role'): ListenerName => ({
    name,
    status: 'retired',
    retiredAt: NOW - 10,
    drainUntil: NOW + 10,
    retiredBy: by,
  });

  test('an identical set changes nothing; new names are appended in body order after the stored ones', () => {
    const same = mergeNames(
      [active('a.example'), active('b.example')],
      ['b.example', 'a.example'],
      'role',
      NOW,
      DRAIN,
    );
    expect(same.changed).toBe(false);
    expect(same.next.map((n) => n.name)).toEqual(['a.example', 'b.example']);
    const grown = mergeNames(
      [active('a.example')],
      ['c.example', 'a.example', 'b.example'],
      'role',
      NOW,
      DRAIN,
    );
    expect(grown).toMatchObject({
      added: ['c.example', 'b.example'],
      retired: [],
      reactivated: [],
      blocked: [],
      changed: true,
    });
    expect(grown.next.map((n) => n.name)).toEqual(['a.example', 'c.example', 'b.example']);
  });

  test('omitted active names are retired with a drain, tagged with the caller; already-retired names are kept as they are', () => {
    const r = mergeNames(
      [active('a.example'), active('b.example'), retiredBy('c.example', 'admin')],
      ['a.example'],
      'role',
      NOW,
      DRAIN,
    );
    expect(r.retired).toEqual(['b.example']);
    expect(r.next).toEqual([
      active('a.example'),
      {
        name: 'b.example',
        status: 'retired',
        retiredAt: NOW,
        drainUntil: NOW + DRAIN,
        retiredBy: 'role',
      },
      retiredBy('c.example', 'admin'),
    ]);
    expect(r.changed).toBe(true);
    const byAdmin = mergeNames(
      [active('a.example'), active('b.example')],
      ['a.example'],
      'admin',
      NOW,
      DRAIN,
    );
    expect(byAdmin.next[1].retiredBy).toBe('admin');
  });

  test('ownership: a role body reactivates only names the role retired; admin-retired names are BLOCKED and kept retired', () => {
    const existing = [
      retiredBy('a.example', 'admin'),
      retiredBy('b.example', 'role'),
      active('c.example'),
    ];
    const role = mergeNames(existing, ['a.example', 'b.example', 'c.example'], 'role', NOW, DRAIN);
    expect(role.blocked).toEqual(['a.example']);
    expect(role.reactivated).toEqual(['b.example']);
    expect(role.next).toEqual([
      retiredBy('a.example', 'admin'),
      active('b.example'),
      active('c.example'),
    ]);
    expect(role.changed).toBe(true);
    // Blocked alone is not a change (nothing was applied).
    const blockedOnly = mergeNames(
      [retiredBy('a.example', 'admin'), active('c.example')],
      ['a.example', 'c.example'],
      'role',
      NOW,
      DRAIN,
    );
    expect(blockedOnly).toMatchObject({ blocked: ['a.example'], changed: false });
    // An admin body reactivates anything.
    const admin = mergeNames(
      existing,
      ['a.example', 'b.example', 'c.example'],
      'admin',
      NOW,
      DRAIN,
    );
    expect(admin.reactivated).toEqual(['a.example', 'b.example']);
    expect(admin.blocked).toEqual([]);
    expect(admin.next.every((n) => n.status === 'active')).toBe(true);
    // A retired name with no `retiredBy` (older rows) counts as role-retired.
    const legacy = mergeNames(
      [{ name: 'x.example', status: 'retired', retiredAt: 1 }],
      ['x.example'],
      'role',
      NOW,
      DRAIN,
    );
    expect(legacy.reactivated).toEqual(['x.example']);
  });
});

describe('diffListeners', () => {
  type Stored = {
    listenerKey: string;
    source: 'role' | 'admin';
    configHash: string;
    retired: boolean;
  };
  const canon = (s: ListenerSpecInput) => validateListenerSpec(s, { origin: PANEL });
  const stored = (spec: CanonicalListener, source: 'role' | 'admin', retired = false): Stored => ({
    listenerKey: spec.listenerKey,
    source,
    configHash: listenerConfigHash(spec),
    retired,
  });

  test('create / update / unchanged by canonical hash; a retired row re-stated is an update', () => {
    const a = canon(reality());
    const w = canon(ws());
    const existing = [stored(a, 'role'), stored(w, 'role', true)];
    const d = diffListeners(existing, [a, w, canon(shadowsocks())], 'role', true);
    expect(d.unchanged.map((u) => u.existing.listenerKey)).toEqual(['a']);
    expect(d.update.map((u) => u.existing.listenerKey)).toEqual(['w']);
    expect(d.create.map((c) => c.listenerKey)).toEqual(['s']);
    expect(d.prune).toEqual([]);
    expect(d.owned).toEqual([]);
    // A material change (names) is an update even when the row is live.
    const changed = diffListeners(
      [stored(a, 'role')],
      [canon(reality({ tlsNames: ['a.example'] }))],
      'role',
      true,
    );
    expect(changed.update).toHaveLength(1);
    expect(changed.unchanged).toEqual([]);
    // Name ORDER alone is not a change.
    const reordered = diffListeners(
      [stored(a, 'role')],
      [canon(reality({ tlsNames: ['b.example', 'a.example'] }))],
      'role',
      true,
    );
    expect(reordered.unchanged).toHaveLength(1);
  });

  test('prune only the caller’s OWN live listeners the body omits; admin rows survive a role body and vice versa', () => {
    const a = canon(reality());
    const w = canon(ws());
    const s = canon(shadowsocks());
    const existing = [stored(a, 'role'), stored(w, 'admin'), stored(s, 'role', true)];
    const roleBody = diffListeners(existing, [], 'role', true);
    expect(roleBody.prune.map((p) => p.listenerKey)).toEqual(['a']); // not `w` (admin), not `s` (already retired)
    const adminBody = diffListeners(existing, [], 'admin', true);
    expect(adminBody.prune.map((p) => p.listenerKey)).toEqual(['w']);
    // prune:false prunes nothing at all.
    expect(diffListeners(existing, [], 'role', false).prune).toEqual([]);
  });

  test('a body key another source owns is reported as `owned`, never updated or created', () => {
    const a = canon(reality());
    const d = diffListeners(
      [stored(a, 'admin')],
      [canon(reality({ originPort: 8443 }))],
      'role',
      true,
    );
    expect(d.owned).toEqual(['a']);
    expect(d.update).toEqual([]);
    expect(d.create).toEqual([]);
    expect(d.unchanged).toEqual([]);
  });

  test('a duplicate listenerKey in one body is refused', () => {
    expect(() =>
      diffListeners([], [canon(reality()), canon(reality({ originPort: 8443 }))], 'role', true),
    ).toThrow(/duplicate listenerKey a/);
  });
});

describe('assertNoMatchOverlap', () => {
  const l = (
    listenerKey: string,
    originPort: number,
    matchRule: CanonicalListener['matchRule'],
  ) => ({
    listenerKey,
    originPort,
    matchRule,
  });

  test('distinct remarks, address rules on distinct ports and a lone whole-body rule are fine', () => {
    expect(() =>
      assertNoMatchOverlap([
        l('a', 443, { kind: 'remark', remark: 'node-relay-a' }),
        l('b', 443, { kind: 'remark', remark: 'node-relay-b' }),
        l('c', 443, { kind: 'address' }),
        l('d', 8443, { kind: 'address' }),
      ]),
    ).not.toThrow();
    expect(() => assertNoMatchOverlap([l('x', 443, { kind: 'whole-body' })])).not.toThrow();
    expect(() => assertNoMatchOverlap([])).not.toThrow();
  });

  test('two address rules on one port, two identical remarks, or whole-body beside anything → edge.match_rule_overlap', () => {
    expect(
      code(() =>
        assertNoMatchOverlap([l('a', 443, { kind: 'address' }), l('b', 443, { kind: 'address' })]),
      ),
    ).toBe('edge.match_rule_overlap');
    expect(
      code(() =>
        assertNoMatchOverlap([
          l('a', 443, { kind: 'remark', remark: 'same' }),
          l('b', 8443, { kind: 'remark', remark: 'same' }),
        ]),
      ),
    ).toBe('edge.match_rule_overlap');
    expect(
      code(() =>
        assertNoMatchOverlap([
          l('a', 443, { kind: 'whole-body' }),
          l('b', 8443, { kind: 'address' }),
        ]),
      ),
    ).toBe('edge.match_rule_overlap');
    // The message names both listeners.
    expect(() =>
      assertNoMatchOverlap([l('a', 443, { kind: 'address' }), l('b', 443, { kind: 'address' })]),
    ).toThrow(/listeners a and b both match by address on port 443/);
  });
});
