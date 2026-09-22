/// <reference types="vite/client" />
/**
 * The one server name a listener's backend Host carries (`hostSniOf`), family
 * names leaving the origins by themselves, and the Host following its name.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer, realityListener, registerRelay } from './lib/edges/testing/fixtures';
import { hostSniOf } from './relayListeners';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const active = async (t: T, id: Id<'relayListeners'>) =>
  ((await t.run((ctx) => ctx.db.get(id)))!.tlsNames ?? [])
    .filter((n) => n.status === 'active')
    .map((n) => n.name);

async function seed(names = ['one.example', 'two.example', 'three.example']) {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const { relayId, listenerIds } = await registerRelay(t, {
    listeners: [realityListener({ tlsNames: names })],
  });
  await t.mutation(internal.sniFamilies.patchConfig, {
    patch: { enabled: true, suspendAfterFails: 1 },
  });
  await t.mutation(internal.sniFamilies.create, {
    slug: 'fam',
    label: 'Fam',
    targetAddress: 'target.example',
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, { slug: 'fam', lines: names });
  return { t, relayId, listenerId: listenerIds.a as Id<'relayListeners'> };
}

describe('hostSniOf', () => {
  test('the first active name that is not known blocked anywhere, in stored order', () => {
    const n = (name: string, over = {}) => ({ name, status: 'active' as const, ...over });
    expect(
      hostSniOf({
        tlsNames: [n('a.example', { blockedIn: ['CN'] }), n('b.example'), n('c.example')],
      }),
    ).toBe('b.example');
    expect(
      hostSniOf({ tlsNames: [{ name: 'a.example', status: 'retired' }, n('b.example')] }),
    ).toBe('b.example');
    // Every name is blocked somewhere: still a name, the first active one.
    expect(
      hostSniOf({
        tlsNames: [n('a.example', { blockedIn: ['CN'] }), n('b.example', { blockedIn: ['IR'] })],
      }),
    ).toBe('a.example');
    expect(hostSniOf({ tlsNames: [] })).toBeNull();
    expect(hostSniOf({})).toBeNull();
  });
});

describe('family names leave the origins by themselves', () => {
  test('a burn retires the name on the origins, with its drain', async () => {
    const { t, listenerId } = await seed();
    const out = await t.mutation(internal.sniFamilies.setNames, {
      slug: 'fam',
      names: ['two.example'],
      action: 'burn',
    });
    expect(out.relays).toMatchObject({ listeners: 1, retired: 1, skipped: 0 });
    expect(await active(t, listenerId)).toEqual(['one.example', 'three.example']);
    const l = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    expect(l.tlsNames![1]).toMatchObject({ status: 'retired', retiredBy: 'admin' });
    expect(l.tlsNames![1].drainUntil).toBeGreaterThan(Date.now());
    // A REALITY retire keeps the operator's endpoint confirmation.
    expect(l.revision).toBe(1);
  });

  test("a BURN takes an origin's last name: a name known blocked is worse than none", async () => {
    const { t, listenerId } = await seed(['only.example']);
    const out = await t.mutation(internal.sniFamilies.setNames, {
      slug: 'fam',
      names: ['only.example'],
      action: 'burn',
    });
    expect(out.relays).toEqual({ listeners: 1, retired: 1, skipped: 0, kept: 0 });
    expect(await active(t, listenerId)).toEqual([]);
    const l = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    expect(l.tlsNames![0]).toMatchObject({ status: 'retired', retiredBy: 'admin' });
  });

  test("a name that merely stopped qualifying never takes an origin's LAST name with it", async () => {
    const { t, listenerId } = await seed(['only.example']);
    const [due] = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: due.id,
      ok: false,
      code: 'q_cert',
    });
    // Suspended in the family, still handed out: a doubtful name serves members, none serves nobody.
    expect(await active(t, listenerId)).toEqual(['only.example']);
    // A retire by an operator follows the same rule...
    await t.mutation(internal.sniFamilies.setNames, {
      slug: 'fam',
      names: ['only.example'],
      action: 'retire',
    });
    expect(await active(t, listenerId)).toEqual(['only.example']);
  });

  test('a suspended name leaves when others remain', async () => {
    const { t, listenerId } = await seed();
    const due = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
    const two = due.find((n) => n.name === 'two.example')!;
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: two.id,
      ok: false,
      code: 'q_cert',
    });
    expect(await active(t, listenerId)).toEqual(['one.example', 'three.example']);
  });

  test('an origin that is rotating is skipped and counted, never forced', async () => {
    const { t, relayId, listenerId } = await seed();
    const rotationId = await t.run((ctx) =>
      ctx.db.insert('edgeRotations', {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        phase: 'provisioning',
        stepVersion: 1,
        cancelRequested: false,
        hostPlan: [],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    await t.run((ctx) => ctx.db.patch(relayId, { activeRotationId: rotationId }));
    const out = await t.mutation(internal.sniFamilies.setNames, {
      slug: 'fam',
      names: ['two.example'],
      action: 'burn',
    });
    expect(out.relays).toMatchObject({ listeners: 0, skipped: 1 });
    expect(await active(t, listenerId)).toContain('two.example');
  });
});

describe('the Host follows its server name', () => {
  async function withHost(
    t: T,
    relayId: Id<'relays'>,
    listenerId: Id<'relayListeners'>,
    sni: string,
  ) {
    await t.run(async (ctx) => {
      await ctx.db.patch(relayId, { hostMode: 'fcp' });
      await ctx.db.patch(listenerId, {
        host: {
          state: 'present',
          uuid: 'h-1',
          ownership: 'fcp',
          intended: {
            remark: 'node-one-relay-a',
            address: '198.51.100.7',
            port: 443,
            sni,
            host: null,
            inboundUuid: 'i',
          },
        },
      });
    });
  }
  const stubPanel = () => {
    const writes: Record<string, unknown>[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_input: string | URL, init: RequestInit = {}) => {
        if ((init.method ?? 'GET').toUpperCase() === 'PATCH')
          writes.push(JSON.parse(init.body as string));
        return new Response(JSON.stringify({ response: {} }), {
          headers: { 'content-type': 'application/json' },
        });
      }),
    );
    return writes;
  };

  test("the Host is rewritten with the listener's next choice, address and port unchanged", async () => {
    const { t, relayId, listenerId } = await seed();
    await withHost(t, relayId, listenerId, 'one.example');
    const writes = stubPanel();
    await t.mutation(internal.relayListeners.retireName, {
      id: listenerId,
      names: ['one.example'],
    });
    expect(await t.action(internal.hostOps.resyncSni, { listenerId })).toEqual({ written: true });
    expect(writes).toEqual([
      { uuid: 'h-1', address: '198.51.100.7', port: 443, sni: 'two.example' },
    ]);
    const l = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    expect(l.host!.intended!.sni).toBe('two.example');
    // Already in step: nothing is written twice.
    expect(await t.action(internal.hostOps.resyncSni, { listenerId })).toEqual({ written: false });
    expect(writes).toHaveLength(1);
  });

  test('judging the Host name blocked somewhere moves the Host onto the next safe name', async () => {
    const { t, relayId, listenerId } = await seed();
    await withHost(t, relayId, listenerId, 'one.example');
    stubPanel();
    await t.mutation(internal.sniFamilies.setCountry, {
      slug: 'fam',
      names: ['one.example'],
      country: 'CN',
      state: 'blocked',
    });
    // The rewrite is scheduled from the judgement itself, like a retire does.
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    expect(scheduled.some((f) => f.name.includes('resyncSni'))).toBe(true);
    expect(await t.action(internal.hostOps.resyncSni, { listenerId })).toEqual({ written: true });
    const l = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    expect(l.host!.intended!.sni).toBe('two.example');
    // Judging a name that is not the Host's schedules nothing.
    await t.mutation(internal.sniFamilies.setCountry, {
      slug: 'fam',
      names: ['three.example'],
      country: 'CN',
      state: 'blocked',
    });
    const again = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    expect(again.filter((f) => f.name.includes('resyncSni'))).toHaveLength(1);
  });

  test('a Host the machine is working on, an operator-owned Host and a rotating origin are left alone', async () => {
    const { t, relayId, listenerId } = await seed();
    await withHost(t, relayId, listenerId, 'gone.example');
    const writes = stubPanel();
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(listenerId))!;
      await ctx.db.patch(listenerId, {
        host: {
          ...l.host!,
          op: { kind: 'create', opId: 'x', claimedAt: 1, expiresAt: 2, attempts: 1 },
        },
      });
    });
    expect(await t.action(internal.hostOps.resyncSni, { listenerId })).toEqual({ written: false });
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(listenerId))!;
      const { op: _op, ...host } = l.host!;
      await ctx.db.patch(listenerId, { host });
      await ctx.db.patch(relayId, { hostMode: 'operator' });
    });
    expect(await t.action(internal.hostOps.resyncSni, { listenerId })).toEqual({ written: false });
    expect(writes).toEqual([]);
  });
});
