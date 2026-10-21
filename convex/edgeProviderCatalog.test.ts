/// <reference types="vite/client" />
/**
 * An account is the whole provider account: what its credentials reach is
 * listed into its catalog (convex/edgeProviderCatalog.ts) for the pickers, and
 * any listed zone becomes a location once the provider confirms it
 * (`edgeProviderOps.createLocation` through the adapter's `checkLocation`).
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { edgeProviderFor, __setEdgeProviderForTests } from './lib/edges/providers/registry';
import { EdgeProviderError } from './lib/edges/providers/http';
import { createAccount } from './lib/edges/testing/fixtures';
import type { LocationCheckResult } from './lib/edges/providers/types';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  __setEdgeProviderForTests('cloudflare', null);
  __setEdgeProviderForTests('fastly', null);
  vi.useRealTimers();
});

const ZONE_A = 'a'.repeat(32);
const ZONE_B = 'b'.repeat(32);

/** A Cloudflare adapter whose listing and zone check answer as the test says. */
function cloudflareAnswering(opts: {
  zones?: () => Array<{ id: string; label: string; facts?: Record<string, string> }>;
  zonesError?: string;
  check?: (cfg: { zoneId: string; zoneName: string }) => LocationCheckResult;
}) {
  const listings: number[] = [];
  __setEdgeProviderForTests('cloudflare', {
    ...edgeProviderFor('cloudflare'),
    testCredentials: async () => ({ ok: true }),
    discoverOptions: async () => {
      listings.push(Date.now());
      return opts.zonesError
        ? { errors: { zones: opts.zonesError }, errorDetails: { zones: 'refused' } }
        : { zones: opts.zones?.() ?? [] };
    },
    checkLocation: async (cfg: { zoneId: string; zoneName: string }) =>
      opts.check?.(cfg) ?? {
        ok: true,
        label: cfg.zoneName,
        observed: { zoneSslMode: 'full', websockets: 'on', zoneStatus: 'active' },
      },
  } as never);
  return listings;
}

describe('the catalog: what an account reaches', () => {
  test('a refresh stores every list; a failed one keeps the last items and says why', async () => {
    const t = convexTest(schema, modules);
    const accountId = await createAccount(t, { provider: 'cloudflare', settings: {} });
    cloudflareAnswering({
      zones: () => [
        { id: ZONE_A, label: 'example.org', facts: { status: 'active' } },
        { id: ZONE_B, label: 'example.net', facts: { status: 'pending' } },
      ],
    });
    expect(await t.action(internal.edgeProviderOps.refreshCatalog, { accountId })).toEqual({
      refreshed: true,
    });
    const view = await t.query(internal.edgeProviderCatalog.view, { accountId });
    expect(view.kinds.zones).toMatchObject({
      items: [
        { id: ZONE_A, label: 'example.org', facts: { status: 'active' } },
        { id: ZONE_B, label: 'example.net', facts: { status: 'pending' } },
      ],
      truncated: false,
      error: null,
    });
    // Right after a listing, another one answers from the stored rows.
    expect(await t.action(internal.edgeProviderOps.refreshCatalog, { accountId })).toEqual({
      refreshed: false,
    });
    vi.useFakeTimers({ now: Date.now() + 60_000 });
    cloudflareAnswering({ zonesError: '10000' });
    expect(await t.action(internal.edgeProviderOps.refreshCatalog, { accountId })).toEqual({
      refreshed: true,
    });
    expect(
      (await t.query(internal.edgeProviderCatalog.view, { accountId })).kinds.zones,
    ).toMatchObject({
      error: '10000',
      errorDetail: 'refused',
      items: [{ id: ZONE_A }, { id: ZONE_B }],
    });
  });

  test("an account's catalog goes with it", async () => {
    const t = convexTest(schema, modules);
    const accountId = await createAccount(t, { provider: 'cloudflare', settings: {} });
    cloudflareAnswering({ zones: () => [{ id: ZONE_A, label: 'example.org' }] });
    await t.action(internal.edgeProviderOps.refreshCatalog, { accountId });
    await t.mutation(internal.edgeProviderAccounts.remove, { id: accountId });
    expect(await t.run((ctx) => ctx.db.query('edgeProviderCatalog').collect())).toEqual([]);
  });
});

describe('a zone becomes a location once the provider confirms it', () => {
  test('a listed zone picked by id is checked, named and observed', async () => {
    const t = convexTest(schema, modules);
    const accountId = await createAccount(t, { provider: 'cloudflare', settings: {} });
    const checked: string[] = [];
    cloudflareAnswering({
      zones: () => [{ id: ZONE_B, label: 'example.net', facts: { status: 'active' } }],
      check: (cfg) => {
        checked.push(`${cfg.zoneId}:${cfg.zoneName}`);
        return { ok: true, label: 'example.net', observed: { zoneSslMode: 'strict' } };
      },
    });
    await t.action(internal.edgeProviderOps.refreshCatalog, { accountId });
    const made = await t.action(internal.edgeProviderOps.createLocation, {
      accountId,
      placement: { zoneId: ZONE_B },
    });
    expect(made.created).toBe(true);
    expect(checked).toEqual([`${ZONE_B}:example.net`]);
    const [loc] = await t.query(internal.edgeLocations.listForAccount, { accountId });
    expect(loc).toMatchObject({
      id: made.id,
      label: 'example.net',
      placeKey: 'anycast',
      placement: { zoneId: ZONE_B, zoneName: 'example.net' },
      observed: { zoneSslMode: 'strict' },
      checkError: null,
    });
    // It is the account's default now: its first location.
    expect(
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: accountId }))!
        .defaultLocationId,
    ).toBe(made.id);
  });

  test("a zone id typed by hand, not in the catalog, takes the provider's name for it", async () => {
    const t = convexTest(schema, modules);
    const accountId = await createAccount(t, { provider: 'cloudflare', settings: {} });
    cloudflareAnswering({
      check: (cfg) => ({
        ok: true,
        label: 'typed.example.org',
        zoneName: 'typed.example.org',
        observed: { zoneSslMode: 'full' },
        ...(cfg.zoneName ? { detail: 'named' } : {}),
      }),
    });
    const made = await t.action(internal.edgeProviderOps.createLocation, {
      accountId,
      placement: { zoneId: ZONE_B },
    });
    const [loc] = await t.query(internal.edgeLocations.listForAccount, { accountId });
    expect(loc).toMatchObject({
      id: made.id,
      placement: { zoneId: ZONE_B, zoneName: 'typed.example.org' },
    });
  });

  test('a zone the key cannot read, one the provider refuses, and an unreachable provider say so', async () => {
    const t = convexTest(schema, modules);
    const accountId = await createAccount(t, { provider: 'cloudflare', settings: {} });
    const zone = { zoneId: ZONE_A, zoneName: 'example.org' };
    cloudflareAnswering({ check: () => ({ ok: false, code: '81044' }) });
    await expect(
      t.action(internal.edgeProviderOps.createLocation, { accountId, placement: zone }),
    ).rejects.toThrow(/location_not_offered/);
    cloudflareAnswering({ check: () => ({ ok: false, code: 'zone_paused' }) });
    await expect(
      t.action(internal.edgeProviderOps.createLocation, { accountId, placement: zone }),
    ).rejects.toThrow(/location_unusable/);
    __setEdgeProviderForTests('cloudflare', {
      ...edgeProviderFor('cloudflare'),
      checkLocation: async () => {
        throw new EdgeProviderError('cloudflare 500 on location', {
          provider: 'cloudflare',
          step: 'location',
          status: 500,
          retryable: true,
          timedOut: false,
        });
      },
    } as never);
    await expect(
      t.action(internal.edgeProviderOps.createLocation, { accountId, placement: zone }),
    ).rejects.toThrow(/location_unchecked/);
    expect(await t.query(internal.edgeLocations.listForAccount, { accountId })).toEqual([]);
  });

  test("a front's zone is its DNS account's, checked with that account; a front account is no DNS account", async () => {
    const t = convexTest(schema, modules);
    const dnsId = await createAccount(t, { provider: 'cloudflare', name: 'acct-dns' });
    const frontId = await createAccount(t, {
      provider: 'fastly',
      name: 'acct-front',
      settings: { certificateAuthority: 'certainly' },
    });
    const seen: Array<{ dns?: { zoneId: string; accountId: string }; tls?: string }> = [];
    __setEdgeProviderForTests('fastly', {
      ...edgeProviderFor('fastly'),
      checkLocation: async (cfg: {
        dns?: { zoneId: string; accountId: string };
        tlsConfigurationId?: string;
      }) => {
        seen.push({ dns: cfg.dns, tls: cfg.tlsConfigurationId });
        return { ok: true, label: 'example.org (TLS 1.3)' };
      },
    } as never);
    const made = await t.action(internal.edgeProviderOps.createLocation, {
      accountId: frontId,
      placement: {
        dnsAccountId: dnsId,
        zoneId: ZONE_A,
        zoneName: 'example.org',
        tlsConfigurationId: 'tls-13',
      },
    });
    expect(made.created).toBe(true);
    expect(seen).toEqual([
      { dns: expect.objectContaining({ zoneId: ZONE_A, accountId: dnsId }), tls: 'tls-13' },
    ]);
    await expect(
      t.action(internal.edgeProviderOps.createLocation, {
        accountId: frontId,
        placement: { dnsAccountId: frontId, zoneId: ZONE_A, zoneName: 'example.org' },
      }),
    ).rejects.toThrow(/dns_account_unusable/);
    // The DNS account cannot go while the front's zone location writes through it.
    await expect(
      t.mutation(internal.edgeProviderAccounts.remove, { id: dnsId as Id<'edgeProviderAccounts'> }),
    ).rejects.toThrow(/account_referenced/);
  });
});
