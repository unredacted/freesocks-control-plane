// @vitest-environment node
/**
 * HYSTERIA ON A REAL BACKEND (docs/privacy.md, docs/client-compatibility.md
 * § "Hysteria in the client catalog"): what the delivery guard rests on, against
 * the live panel rather than the fake one (lib/edges/testing/fakeBackend.ts).
 *
 *  - the backend takes FCP's own Hysteria transport (`buildTransport`, with a
 *    certificate from `generateHysteriaCertificate`) in one profile beside a
 *    REALITY transport;
 *  - it takes FCP's Hysteria Host as FCP writes it (`desiredExtraHost` through
 *    the provider's `hostBody`): the pin, ALPN h3, TLS, and FCP's per-format
 *    rewrites (`hysteriaHostMapper`), and reads them back;
 *  - a key in both groups (the Hysteria mode and its REALITY backup) gets both
 *    entries, and for EVERY User-Agent the client manifest lists
 *    (tests/compat/manifest.ts) the body the backend writes passes FCP's guard
 *    (`guardHysteria`) with nothing dropped, every Hysteria entry verified by
 *    the expected pin. So with the rewrites in place the guard never has to
 *    drop anything, whatever app asks.
 *
 * No node is connected: the bodies are what the backend generates. The tunnel
 * itself is the Hysteria engines job's (scripts/compat/hysteria.sh). Needs a
 * 3.x backend (the Host pin and rewrites are 3.x fields); a 2.x override skips.
 * Run via `bun run test:integration:remnawave`. Fixture values are RFC 5737 /
 * `.example` only.
 */
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { afterAll, describe, expect, test } from 'vitest';
import { clients } from '../../../tests/compat/manifest';
import { buildTransport } from '../backend/profileTemplate';
import { generateHysteriaCertificate } from '../backend/hysteriaCert';
import { desiredExtraHost } from '../backend/extraModes';
import { guardHysteria } from '../hysteriaGuard';
import { MENTIONS_HYSTERIA, scanHysteria } from '../hysteriaPins';
import {
  remnawaveCreateProfile,
  remnawaveFetchSubscription,
  remnawaveIssueUser,
  remnawaveManageCreateHost,
  remnawaveReadHosts,
  type RemnawaveConfig,
} from './remnawave';

const BASE_URL = process.env.REMNAWAVE_TEST_URL;
const API_TOKEN = process.env.REMNAWAVE_TEST_TOKEN;
const BACKEND_MAJOR = Number(/:(\d+)\./.exec(process.env.REMNAWAVE_TEST_IMAGE ?? '')?.[1] ?? 3);
const ENABLED = !!BASE_URL && !!API_TOKEN && BACKEND_MAJOR >= 3;

const RUN = randomUUID().slice(0, 8);
const SERVER_NAME = 'hy.example';
const NODE_ADDRESS = '203.0.113.20';
const CERT = generateHysteriaCertificate(SERVER_NAME);
const PINS = { pinHex: [CERT.pinHex], spkiB64: [CERT.spkiB64] };

async function api(method: string, path: string, body?: unknown): Promise<any> {
  const res = await fetch(new URL(`/api/${path}`, BASE_URL), {
    method,
    headers: { authorization: `Bearer ${API_TOKEN}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`backend ${method} ${path.split('/')[0]}: HTTP ${res.status}`);
  const text = await res.text();
  return text.trim() ? JSON.parse(text).response : undefined;
}

/** A REALITY transport beside the Hysteria one, as two modes of one node share a profile. */
function realityInbound(tag: string) {
  const { privateKey } = generateKeyPairSync('x25519');
  return {
    tag,
    listen: '::',
    port: 443,
    protocol: 'vless',
    settings: { clients: [], decryption: 'none' },
    streamSettings: {
      network: 'raw',
      security: 'reality',
      realitySettings: {
        target: 'decoy.example:443',
        serverNames: ['decoy.example'],
        privateKey: privateKey
          .export({ type: 'pkcs8', format: 'der' })
          .subarray(-32)
          .toString('base64url'),
        shortIds: [''],
      },
    },
  };
}

describe.skipIf(!ENABLED)('remnawave backend: a Hysteria Host as FCP writes it', () => {
  const cfg: RemnawaveConfig = { baseUrl: BASE_URL!, apiToken: API_TOKEN!, timeoutMs: 30_000 };
  const created = {
    users: [] as string[],
    hosts: [] as string[],
    squads: [] as string[],
    profiles: [] as string[],
  };
  let shortId = '';
  let subscriptionUrl = '';

  afterAll(async () => {
    const quiet = (p: Promise<unknown>) => p.catch(() => undefined);
    for (const u of created.users) await quiet(api('DELETE', `users/${u}`));
    for (const u of created.hosts) await quiet(api('DELETE', `hosts/${u}`));
    for (const u of created.squads) await quiet(api('DELETE', `internal-squads/${u}`));
    for (const u of created.profiles) await quiet(api('DELETE', `config-profiles/${u}`));
  });

  test('the backend takes the transport, the Host with its pin and rewrites, and a key in both groups', async () => {
    const hyTag = `PRIVACY_HYSTERIA_${RUN}`;
    const rTag = `PRIVACY_REALITY_${RUN}`;
    const hysteria = buildTransport(
      {
        slug: 'privacy-hysteria',
        name: `Privacy-Hysteria-${RUN}`,
        shape: { transport: 'hysteria', fronting: 'direct' },
        hysteria: { serverName: SERVER_NAME, salamander: false },
      },
      undefined,
      { certificate: CERT.certificate, key: CERT.key },
    );
    hysteria.tag = hyTag;
    const { profileUuid } = await remnawaveCreateProfile(cfg, {
      name: `FCP hysteria ${RUN}`,
      config: {
        log: { loglevel: 'none' },
        inbounds: [realityInbound(rTag), hysteria],
        outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
      },
    });
    created.profiles.push(profileUuid);
    const profile = await api('GET', `config-profiles/${profileUuid}`);
    const inboundOf = (tag: string) =>
      (profile.inbounds as Array<{ uuid: string; tag: string; type?: string }>).find(
        (i) => i.tag === tag,
      )!;
    const hy = inboundOf(hyTag);
    const reality = inboundOf(rTag);
    expect(hy, 'the backend kept the Hysteria inbound').toBeTruthy();
    expect(reality).toBeTruthy();

    const squads: string[] = [];
    for (const [name, inbound] of [
      [`Privacy-Reality-${RUN}`, reality.uuid],
      [`Privacy-Hysteria-${RUN}`, hy.uuid],
    ] as const) {
      const squad = await api('POST', 'internal-squads', { name, inbounds: [inbound] });
      created.squads.push(squad.uuid);
      squads.push(squad.uuid);
    }

    // The REALITY Host, plain; the Hysteria Host exactly as FCP writes it.
    const rHost = await api('POST', 'hosts', {
      inbound: { configProfileUuid: profileUuid, configProfileInboundUuid: reality.uuid },
      remark: `node-${RUN} | decoy.example`,
      address: NODE_ADDRESS,
      port: 443,
      sni: 'decoy.example',
      fingerprint: 'chrome',
    });
    created.hosts.push(rHost.uuid);
    const want = desiredExtraHost({
      nodeName: `node-${RUN}`,
      originAddress: NODE_ADDRESS,
      port: 443,
      auth: { serverName: SERVER_NAME, pinHex: CERT.pinHex, spkiB64: CERT.spkiB64 },
    });
    const { hostUuid } = await remnawaveManageCreateHost(cfg, {
      remark: want.remark,
      address: want.address,
      port: want.port,
      sni: want.sni,
      alpn: want.alpn,
      securityLayer: want.securityLayer,
      pinnedPeerCertSha256: want.pinnedPeerCertSha256,
      mapper: want.mapper,
      inbound: { configProfileUuid: profileUuid, configProfileInboundUuid: hy.uuid },
    });
    created.hosts.push(hostUuid);
    // Read back as FCP observes it: a hand edit of the pin or the rewrites is drift.
    const seen = (await remnawaveReadHosts(cfg)).find((h) => h.hostUuid === hostUuid);
    expect(seen?.pinnedPeerCertSha256).toBe(CERT.pinHex);
    expect(seen?.mapperJson).toBe(want.mapperJson);

    const issued = await remnawaveIssueUser(cfg, {
      username: `fcp_hy_${RUN}`,
      placement: squads[1]!,
      extraPlacements: [squads[0]!],
      tag: 'MEMBER',
      expireAt: null,
      trafficLimitBytes: 1024 ** 3,
    });
    created.users.push(issued.backendUserId);
    shortId = issued.backendShortId;
    subscriptionUrl = issued.subscriptionUrl;
  }, 120_000);

  test('every app body carries both entries, and the Hysteria one passes the guard untouched', async () => {
    const uas = ['', ...clients.flatMap((c) => c.userAgents)];
    let pinned = 0;
    for (const ua of uas) {
      const { content } = await remnawaveFetchSubscription(
        cfg,
        shortId,
        ua || undefined,
        subscriptionUrl,
      );
      const label = ua || '(no User-Agent)';
      // Legacy Clash leaves both out (it has neither VLESS nor Hysteria 2): the
      // app notice answers it (docs/client-compatibility.md).
      if (!MENTIONS_HYSTERIA.test(content)) continue;
      const out = guardHysteria(content, PINS);
      expect(out, label).toEqual({ kind: 'kept', content, dropped: 0 });
      const scan = scanHysteria(content, PINS);
      expect(scan.entries.length, label).toBeGreaterThan(0);
      for (const e of scan.entries) expect(e.trust, label).toBe('pinned');
      pinned += scan.entries.length;
    }
    // At least the link list, sing-box and Mihomo bodies carried the entry.
    expect(pinned).toBeGreaterThanOrEqual(3);
  }, 120_000);
});
