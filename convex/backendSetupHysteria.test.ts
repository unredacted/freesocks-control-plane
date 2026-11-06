/// <reference types="vite/client" />
/**
 * "Set up this backend" with a Hysteria 2 mode beside a REALITY one
 * (docs/servers.md "Setting up a backend"):
 *
 *  - the created profile carries a QUIC inbound on UDP 443 with a fresh
 *    self-signed certificate, beside REALITY on TCP 443;
 *  - FCP reads the certificate's two pins back from the observed profile and
 *    records the transport; the Hysteria mode needs no server-name family;
 *  - the certificate's private key is in no row, response or audit entry;
 *  - a backend type that cannot serve UDP is refused up front;
 *  - "Add a transport" makes a Hysteria transport with its certificate made in
 *    the attempt, and the preview never carries it.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { insertPanelServer } from './lib/edges/testing/fixtures';
import { installFakeBackend } from './lib/edges/testing/fakeBackend';
import { signValue } from './lib/cookies';
import { certificatePins } from './lib/backend/hysteriaCert';
import { ProfilePatchPreview } from '../src/shared/contracts/servers';

const modules = import.meta.glob('./**/*.*s');

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function until<R>(get: () => Promise<R>, ok: (r: R) => boolean): Promise<R> {
  for (let i = 0; i < 600; i++) {
    const row = await get();
    if (ok(row)) return row;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('did not settle');
}

const realityMode = {
  slug: 'privacy-reality',
  name: 'Privacy-Reality',
  shape: { transport: 'reality' as const, fronting: 'direct' as const },
  familySlug: 'fam-direct',
  acceptProxyProtocol: false,
};
const hysteriaMode = {
  slug: 'privacy-hysteria',
  name: 'Privacy-Hysteria',
  shape: { transport: 'hysteria' as const, fronting: 'direct' as const },
  acceptProxyProtocol: false,
  hysteria: { serverName: 'quic.example', salamander: false },
};

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const panel = installFakeBackend();
  await t.mutation(internal.seed.seedConnectionModes, {});
  // The Hysteria leaf is a catalog row of its own (the built-in arrives later).
  await t.run(async (ctx) => {
    await ctx.db.insert('connectionModes', {
      slug: 'privacy-hysteria',
      familySlug: 'privacy',
      deliveryStyle: 'rawConfig',
      enabled: false,
      isFamilyDefault: false,
      backends: ['remnawave'],
      order: 5,
      updatedAt: Date.now(),
    });
  });
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
  await t.mutation(internal.sniFamilies.create, {
    slug: 'fam-direct',
    label: 'fam-direct',
    targetAddress: 'decoy-a.example',
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, {
    slug: 'fam-direct',
    lines: ['decoy-a.example'],
  });
  for (const n of (await t.query(internal.sniFamilies.dueForQualification, {})).names)
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: n.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
    });
  return { t, serverId, panel };
}

describe('setting a backend up with a Hysteria mode', () => {
  test('the profile carries a pinned QUIC transport beside REALITY, and FCP knows its pins', async () => {
    const { t, serverId, panel } = await seed();
    const started = await t.mutation(internal.backendSetup.start, {
      backendServerId: serverId,
      input: {
        profileName: 'FreeSocks-Config',
        modes: [realityMode, hysteriaMode],
        originDns: null,
        adopt: false,
      },
    });
    const row = await until(
      () => t.run((ctx) => ctx.db.get(started.setupId)),
      (r) => !!r && !r.claim,
    );
    expect(row!.state).toBe('ready');

    // What the backend got: QUIC on UDP 443 under a real certificate for the one name.
    const config = panel.profiles[0].config as { inbounds: Record<string, any>[] };
    const hy = config.inbounds.find((i) => i.tag === 'PRIVACY_HYSTERIA')!;
    expect(hy).toMatchObject({ protocol: 'hysteria', port: 443, listen: '::' });
    expect(hy.streamSettings.network).toBe('hysteria');
    expect(hy.streamSettings.tlsSettings.serverName).toBe('quic.example');
    expect(hy.streamSettings.finalmask).toEqual({ quicParams: { congestion: 'bbr' } });
    const certLines = hy.streamSettings.tlsSettings.certificates[0].certificate as string[];
    const keyLines = hy.streamSettings.tlsSettings.certificates[0].key as string[];
    const pins = certificatePins(certLines)!;
    expect(pins.pinHex).toMatch(/^[0-9a-f]{64}$/);

    // What FCP kept: the pins, read back from the observed profile; never the key.
    const stored = await t.run((ctx) => ctx.db.query('panelProfiles').collect());
    const inbound = stored[0]!.inbounds.find((i) => i.tag === 'PRIVACY_HYSTERIA')!;
    expect(inbound.hysteriaAuth).toMatchObject({
      pinHex: pins.pinHex,
      spkiB64: pins.spkiB64,
      serverName: 'quic.example',
      alpn: ['h3'],
      obfs: false,
    });
    expect(inbound.hysteriaAuth!.digest).toMatch(/^[0-9a-f]{64}$/);
    const mode = row!.modes.find((m) => m.slug === 'privacy-hysteria')!;
    expect(mode).toMatchObject({
      family: 'none',
      hysteria: { serverName: 'quic.example', salamander: false },
      transport: { port: 443, serverNames: ['quic.example'] },
    });
    // The private key appears nowhere FCP writes.
    const keyBody = keyLines.slice(1, -1).join('');
    const everything = JSON.stringify(
      await t.run(async (ctx) => ({
        setups: await ctx.db.query('panelSetups').collect(),
        profiles: await ctx.db.query('panelProfiles').collect(),
        audit: await ctx.db.query('auditLog').collect(),
        obligations: await ctx.db.query('backendObligations').collect(),
      })),
    );
    expect(keyBody.length).toBeGreaterThan(40);
    expect(everything).not.toContain(keyBody.slice(0, 40));
  });

  test('Salamander on: the password is made in the attempt, and only its presence is recorded', async () => {
    const { t, serverId, panel } = await seed();
    const started = await t.mutation(internal.backendSetup.start, {
      backendServerId: serverId,
      input: {
        profileName: 'FreeSocks-Config',
        modes: [
          realityMode,
          { ...hysteriaMode, hysteria: { serverName: 'quic.example', salamander: true } },
        ],
        originDns: null,
        adopt: false,
      },
    });
    await until(
      () => t.run((ctx) => ctx.db.get(started.setupId)),
      (r) => !!r && !r.claim,
    );
    const config = panel.profiles[0].config as { inbounds: Record<string, any>[] };
    const hy = config.inbounds.find((i) => i.tag === 'PRIVACY_HYSTERIA')!;
    const password = hy.streamSettings.finalmask.udp[0].settings.password as string;
    expect(password).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const stored = await t.run((ctx) => ctx.db.query('panelProfiles').collect());
    expect(stored[0]!.inbounds.find((i) => i.tag === 'PRIVACY_HYSTERIA')!.hysteriaAuth!.obfs).toBe(
      true,
    );
    expect(JSON.stringify(stored)).not.toContain(password);
  });

  test('a Hysteria mode without a server name is refused before anything is sent', async () => {
    const { t, serverId, panel } = await seed();
    await expect(
      t.mutation(internal.backendSetup.start, {
        backendServerId: serverId,
        input: {
          profileName: 'FreeSocks-Config',
          modes: [{ ...hysteriaMode, hysteria: { serverName: '', salamander: false } }],
          originDns: null,
          adopt: false,
        },
      }),
    ).rejects.toThrow(/servers\.modes_invalid/);
    expect(panel.profiles).toHaveLength(0);
  });
});

describe('adding a Hysteria transport to a profile', () => {
  test('previewed without material, sent with a certificate made in the attempt', async () => {
    const { t, serverId, panel } = await seed();
    const started = await t.mutation(internal.backendSetup.start, {
      backendServerId: serverId,
      input: {
        profileName: 'FreeSocks-Config',
        modes: [realityMode],
        originDns: null,
        adopt: false,
      },
    });
    await until(
      () => t.run((ctx) => ctx.db.get(started.setupId)),
      (r) => !!r && !r.claim,
    );
    const adminUserId = await t.run((ctx) =>
      ctx.db.insert('adminUsers', {
        username: 'op',
        displayName: 'Op',
        isActive: true,
        updatedAt: Date.now(),
      }),
    );
    const sid = `asid-${Math.random().toString(36).slice(2)}`;
    await t.mutation(internal.sessions.create, {
      sid,
      kind: 'admin',
      adminUserId,
      ttlMs: 3_600_000,
    });
    const cookie = `fs_admin_session=${await signValue(sid, 'test-admin-sign')}`;
    const call = (method: string, path: string, body?: unknown) =>
      t.fetch(`/api/v1/admin/servers/panel-a/${path}`, {
        method,
        headers: { cookie, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    const profileUuid = panel.profiles[0].uuid as string;
    const res = await call('POST', `profiles/${profileUuid}/preview`, {
      ops: [
        {
          op: 'addInboundFromTemplate',
          transportTag: 'PRIVACY_HYSTERIA',
          template: { kind: 'hysteria', port: 443, serverName: 'quic.example' },
        },
      ],
    });
    expect(res.status).toBe(200);
    const preview = ProfilePatchPreview.parse(await res.json());
    expect(preview.changes).toEqual([
      { transportTag: 'PRIVACY_HYSTERIA', field: 'transport', before: null, after: 'hysteria' },
    ]);
    expect(JSON.stringify(preview)).not.toContain('BEGIN');
    const applied = await call('POST', `profiles/${profileUuid}/apply`, {
      ops: preview.ops,
      baseToken: preview.baseToken,
      expectedToken: preview.expectedToken,
      transportUuids: preview.transportUuids,
    });
    expect(applied.status).toBe(200);
    const added = await until(
      async () =>
        (panel.profiles[0].config as { inbounds: Record<string, any>[] }).inbounds.find(
          (i) => i.tag === 'PRIVACY_HYSTERIA',
        ),
      (i) => !!i,
    );
    const certLines = added!.streamSettings.tlsSettings.certificates[0].certificate as string[];
    expect(certificatePins(certLines)).not.toBeNull();
    expect(added!.streamSettings.tlsSettings.certificates[0].key[0]).toBe(
      '-----BEGIN EC PRIVATE KEY-----',
    );
  });
});
