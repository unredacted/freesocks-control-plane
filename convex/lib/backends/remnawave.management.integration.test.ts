// @vitest-environment node
/**
 * MANAGEMENT CONTRACT PROBE: pins, against a REAL Remnawave backend, the write
 * behaviours that server management is designed around (docs/backends.md,
 * "Management contract"). These are not FCP provider functions yet; the probe
 * speaks the backend API directly so the facts are established BEFORE any code
 * depends on them:
 *
 *  - an inbound keeps its uuid across a config PATCH while its tag and
 *    protocol are unchanged (listener bindings, Hosts and mode groups hang off it);
 *  - the backend has no conditional update (a bogus precondition is ignored), so
 *    exclusive-writer coordination is FCP's job;
 *  - an auth rejection (401) stores nothing, so it may sit on the pre-mutation
 *    allowlist; an INVALID CONFIG also stores nothing but answers 500, and a
 *    5xx can never be on that list, so that outcome is settled by reading back;
 *  - what the backend normalises on write (the change token must apply the same
 *    normalisation or every verify would false-fail);
 *  - inbound tags are unique backend-wide, not per profile;
 *  - the node, mode group and Host write shapes.
 *
 * No node is connected to this backend, so nothing here proves node-side effects
 * (application, restart completion): that is the managed-node harness's job.
 *
 * Gated like the user-lifecycle test; run via `bun run test:integration:remnawave`.
 * Fixture values are RFC 5737 / `.example` only.
 */
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { afterAll, describe, expect, test } from 'vitest';
import { PROVIDERS } from './registry';
import { remnawaveObservePanel } from './remnawave';

const BASE_URL = process.env.REMNAWAVE_TEST_URL;
const API_TOKEN = process.env.REMNAWAVE_TEST_TOKEN;

interface Answer {
  status: number;
  /** The unwrapped `response`, or the raw JSON when the backend did not wrap it. */
  data: any;
}

/** Raw backend call that never throws on a status: the probe asserts on it. */
async function api(
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
  opts: { token?: string; headers?: Record<string, string> } = {},
): Promise<Answer> {
  const res = await fetch(new URL(`/api/${path}`, BASE_URL), {
    method,
    headers: {
      authorization: `Bearer ${opts.token ?? API_TOKEN}`,
      'content-type': 'application/json',
      accept: 'application/json',
      ...opts.headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(20_000),
  });
  const text = await res.text();
  let json: any = undefined;
  try {
    json = text.trim() ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: res.status, data: json && 'response' in json ? json.response : json };
}

const ok = (a: Answer) => a.status >= 200 && a.status < 300;

function realityKeypair(): { privateKey: string; publicKey: string } {
  const keys = generateKeyPairSync('x25519');
  return {
    privateKey: keys.privateKey
      .export({ type: 'pkcs8', format: 'der' })
      .subarray(-32)
      .toString('base64url'),
    publicKey: keys.publicKey
      .export({ type: 'spki', format: 'der' })
      .subarray(-32)
      .toString('base64url'),
  };
}

function realityInbound(tag: string, port: number, serverNames: string[]) {
  const { privateKey } = realityKeypair();
  return {
    tag,
    port,
    protocol: 'vless',
    settings: { clients: [], decryption: 'none' },
    streamSettings: {
      network: 'tcp',
      security: 'reality',
      realitySettings: {
        target: 'target.example:443',
        serverNames,
        privateKey,
        shortIds: ['0123456789abcdef'],
      },
    },
  };
}

const profileConfig = (inbounds: unknown[]) => ({
  log: { loglevel: 'none' },
  inbounds,
  outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
});

const inboundsOf = (profile: any): { uuid: string; tag: string }[] => profile?.inbounds ?? [];
const uuidOfTag = (profile: any, tag: string) =>
  inboundsOf(profile).find((i) => i.tag === tag)?.uuid ?? null;
const rawInbound = (profile: any, tag: string) =>
  (profile?.config?.inbounds ?? []).find((i: any) => i.tag === tag);

describe.skipIf(!BASE_URL || !API_TOKEN)('remnawave management contract (integration)', () => {
  // Tags are unique backend-wide, so every run uses its own.
  const run = randomUUID().slice(0, 8);
  const tagA = `fcp-a-${run}`;
  const tagB = `fcp-b-${run}`;
  const created = {
    profiles: [] as string[],
    squads: [] as string[],
    hosts: [] as string[],
    nodes: [] as string[],
  };
  let profileUuid = '';
  /** Behaviours that are recorded rather than required; printed once at the end. */
  const observed: Record<string, unknown> = {};

  afterAll(async () => {
    for (const u of created.hosts) await api('DELETE', `hosts/${u}`);
    for (const u of created.nodes) await api('DELETE', `nodes/${u}`);
    for (const u of created.squads) await api('DELETE', `internal-squads/${u}`);
    for (const u of created.profiles) await api('DELETE', `config-profiles/${u}`);
    console.info(`[management-contract] observed ${JSON.stringify(observed)}`);
  });

  test('profile create returns one derived inbound row per tag', async () => {
    const made = await api('POST', 'config-profiles', {
      name: `FCP contract ${run}`,
      config: profileConfig([
        realityInbound(tagA, 20443, ['a.example', 'b.example']),
        realityInbound(tagB, 20444, ['c.example']),
      ]),
    });
    expect(made.status).toBe(201);
    profileUuid = made.data.uuid;
    created.profiles.push(profileUuid);
    expect(
      inboundsOf(made.data)
        .map((i) => i.tag)
        .sort(),
    ).toEqual([tagA, tagB].sort());
    expect(uuidOfTag(made.data, tagA)).toMatch(/^[0-9a-f-]{36}$/);
  });

  test('an inbound keeps its uuid across a config PATCH while tag and protocol hold', async () => {
    const before = await api('GET', `config-profiles/${profileUuid}`);
    const config = structuredClone(before.data.config);
    rawInbound({ config }, tagA).streamSettings.realitySettings.serverNames = [
      'a.example',
      'b.example',
      'd.example',
    ];
    const patched = await api('PATCH', 'config-profiles', { uuid: profileUuid, config });
    expect(ok(patched)).toBe(true);
    const after = await api('GET', `config-profiles/${profileUuid}`);
    expect(uuidOfTag(after.data, tagA)).toBe(uuidOfTag(before.data, tagA));
    expect(uuidOfTag(after.data, tagB)).toBe(uuidOfTag(before.data, tagB));
    expect(rawInbound(after.data, tagA).streamSettings.realitySettings.serverNames).toEqual([
      'a.example',
      'b.example',
      'd.example',
    ]);
  });

  test("FCP's observation reads the live backend and carries nothing secret", async () => {
    const seen = await remnawaveObservePanel(
      { baseUrl: BASE_URL!, apiToken: API_TOKEN!, timeoutMs: 20_000 },
      'integration-digest-key',
    );
    const mine = seen.profiles.find((p) => p.profileUuid === profileUuid)!;
    expect(mine).toBeTruthy();
    expect(mine.shapeHash).toMatch(/^[0-9a-f]{64}$/);
    expect(mine.changeToken).toMatch(/^[0-9a-f]{64}$/);
    const a = mine.inbounds.find((i) => i.tag === tagA)!;
    expect(a).toMatchObject({ protocol: 'vless', port: 20443, security: 'reality' });
    expect(a.configProfileInboundUuid).toMatch(/^[0-9a-f-]{36}$/);
    expect(a.reality).toEqual({
      target: 'target.example:443',
      serverNames: ['a.example', 'b.example', 'd.example'],
    });
    // Derived from the private key the backend holds; a real X25519 public key.
    expect(a.realityAuth?.publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.realityAuth?.digest).toMatch(/^[0-9a-f]{64}$/);
    const blob = JSON.stringify(seen);
    const raw = await api('GET', `config-profiles/${profileUuid}`);
    const sk = rawInbound(raw.data, tagA).streamSettings.realitySettings.privateKey as string;
    expect(sk.length).toBeGreaterThan(20);
    expect(blob).not.toContain(sk);
    expect(blob).not.toContain('0123456789abcdef');
    expect(blob).not.toContain('rawInbound');
    // What is read now equals what was read a moment ago: the token is stable.
    const again = await remnawaveObservePanel(
      { baseUrl: BASE_URL!, apiToken: API_TOKEN!, timeoutMs: 20_000 },
      'integration-digest-key',
    );
    expect(again.profiles.find((p) => p.profileUuid === profileUuid)!.changeToken).toBe(
      mine.changeToken,
    );
  });

  test('a guarded profile edit lands with exactly the token FCP predicted', async () => {
    const cfg = {
      type: 'remnawave' as const,
      baseUrl: BASE_URL!,
      apiToken: API_TOKEN!,
      timeoutMs: 20_000,
    };
    const w = PROVIDERS.remnawave.panelWrites!;
    const KEY = 'integration-digest-key';
    const ops = [
      {
        op: 'setRealityServerNames' as const,
        inboundTag: tagA,
        names: ['a.example', 'b.example', 'd.example', 'e.example'],
      },
      { op: 'setRealityTarget' as const, inboundTag: tagA, target: 'target.example:8443' },
    ];
    const before = await api('GET', `config-profiles/${profileUuid}`);
    const sk = rawInbound(before.data, tagA).streamSettings.realitySettings.privateKey;
    const preview = await w.previewProfilePatch(cfg, profileUuid, ops, KEY);
    expect(preview.changed).toBe(true);
    expect(JSON.stringify(preview)).not.toContain(sk);

    // A stale token is refused and nothing is sent.
    expect(await w.applyProfilePatch(cfg, profileUuid, ops, 'not-the-token', KEY)).toEqual({
      sent: false,
      reason: 'profile_changed',
    });
    expect((await w.readProfile(cfg, profileUuid, KEY)).changeToken).toBe(preview.baseToken);

    expect(await w.applyProfilePatch(cfg, profileUuid, ops, preview.baseToken, KEY)).toEqual({
      sent: true,
    });
    const after = await w.readProfile(cfg, profileUuid, KEY);
    // The backend normalises on write; the prediction must survive that exactly.
    expect(after.changeToken).toBe(preview.expectedToken);
    const a = after.inbounds.find((i) => i.tag === tagA)!;
    expect(a.reality).toEqual({ target: 'target.example:8443', serverNames: ops[0].names });
    expect(a.configProfileInboundUuid).toBe(preview.inboundUuids[tagA]);
    // Key material went through untouched.
    const raw = await api('GET', `config-profiles/${profileUuid}`);
    expect(rawInbound(raw.data, tagA).streamSettings.realitySettings.privateKey).toBe(sk);
    // Applying the same edit again is a no-op: no write, no node work.
    expect(await w.applyProfilePatch(cfg, profileUuid, ops, after.changeToken, KEY)).toEqual({
      sent: false,
      reason: 'nothing_to_change',
    });
    // Leave the names as the next test expects them.
    const reset = [
      {
        op: 'setRealityServerNames' as const,
        inboundTag: tagA,
        names: ['a.example', 'b.example', 'd.example'],
      },
      { op: 'setRealityTarget' as const, inboundTag: tagA, target: 'target.example:443' },
    ];
    const back = await w.previewProfilePatch(cfg, profileUuid, reset, KEY);
    await w.applyProfilePatch(cfg, profileUuid, reset, back.baseToken, KEY);
  });

  test('records what the backend normalises on write', async () => {
    const before = await api('GET', `config-profiles/${profileUuid}`);
    const config = structuredClone(before.data.config);
    const rs = rawInbound({ config }, tagB).streamSettings.realitySettings;
    const { publicKey } = realityKeypair();
    rs.serverNames = ['C.Example', 'c.example', ' e.example '];
    rs.publicKey = publicKey;
    rawInbound({ config }, tagB).settings.clients = [
      { id: randomUUID(), email: 'probe', flow: 'xtls-rprx-vision' },
    ];
    const patched = await api('PATCH', 'config-profiles', { uuid: profileUuid, config });
    expect(ok(patched)).toBe(true);
    const after = await api('GET', `config-profiles/${profileUuid}`);
    const stored = rawInbound(after.data, tagB);
    // The change token applies EXACTLY this normalisation (lib/backend/digest.ts
    // `normalizeForToken`): whitespace trimmed, case and duplicates kept, the
    // submitted publicKey kept, `settings.clients` cleared. A backend that
    // normalises differently would make every predicted token false-fail.
    expect(stored.streamSettings.realitySettings.serverNames).toEqual([
      'C.Example',
      'c.example',
      'e.example',
    ]);
    expect(stored.streamSettings.realitySettings.publicKey).toBe(publicKey);
    expect(stored.settings.clients).toEqual([]);
    // The backend must never hand back the client list it was sent.
    expect(JSON.stringify(after.data)).not.toContain('"email":"probe"');
  });

  test('there is no conditional update: a bogus precondition is ignored', async () => {
    const before = await api('GET', `config-profiles/${profileUuid}`);
    const patched = await api(
      'PATCH',
      'config-profiles',
      { uuid: profileUuid, config: before.data.config },
      {
        headers: {
          'if-match': '"not-the-current-version"',
          'if-unmodified-since': 'Thu, 01 Jan 1970 00:00:00 GMT',
        },
      },
    );
    // A backend that honoured preconditions would answer 412 here.
    expect(patched.status).not.toBe(412);
    expect(ok(patched)).toBe(true);
  });

  test('a profile-name-only PATCH is accepted and leaves the config alone', async () => {
    const before = await api('GET', `config-profiles/${profileUuid}`);
    const renamed = await api('PATCH', 'config-profiles', {
      uuid: profileUuid,
      name: `FCP contract ${run} b`,
    });
    expect(ok(renamed)).toBe(true);
    const after = await api('GET', `config-profiles/${profileUuid}`);
    expect(after.data.name).toBe(`FCP contract ${run} b`);
    expect(after.data.config).toEqual(before.data.config);
    expect(uuidOfTag(after.data, tagA)).toBe(uuidOfTag(before.data, tagA));
  });

  test('an invalid config is refused and nothing is stored', async () => {
    const before = await api('GET', `config-profiles/${profileUuid}`);
    const bad = await api('PATCH', 'config-profiles', {
      uuid: profileUuid,
      config: { inbounds: 'not-an-array' },
    });
    // The pinned backend answers 500 here, not a 4xx, and the ledger's rules are
    // built on that: a 5xx can never sit on the pre-mutation allowlist (a
    // gateway can answer one while upstream commits), so this outcome is
    // `uncertain` and is settled by reading back, exactly as this test does. A
    // backend that moved it to a 4xx would let the classification be revisited;
    // pin the status so that cannot happen silently. FCP validates a config's
    // shape itself before it ever sends one.
    expect(bad.status).toBe(500);
    const after = await api('GET', `config-profiles/${profileUuid}`);
    expect(after.data.config).toEqual(before.data.config);
  });

  test('an auth rejection stores nothing', async () => {
    const before = await api('GET', `config-profiles/${profileUuid}`);
    const denied = await api(
      'PATCH',
      'config-profiles',
      { uuid: profileUuid, name: 'should never land' },
      { token: 'not-a-valid-token' },
    );
    expect([401, 403]).toContain(denied.status);
    observed.badTokenStatus = denied.status;
    const after = await api('GET', `config-profiles/${profileUuid}`);
    expect(after.data.name).toBe(before.data.name);
  });

  test('inbound tags are unique backend-wide, not per profile', async () => {
    const clash = await api('POST', 'config-profiles', {
      name: `FCP contract ${run} clash`,
      config: profileConfig([realityInbound(tagA, 20450, ['z.example'])]),
    });
    if (ok(clash)) created.profiles.push(clash.data.uuid);
    // A deterministic uniqueness collision, not a retryable or uncertain
    // failure: the management code classifies it by this status.
    expect(clash.status).toBe(409);
    const profiles = await api('GET', 'config-profiles');
    const rows = profiles.data.configProfiles ?? profiles.data;
    expect(rows.filter((p: any) => p.name === `FCP contract ${run} clash`)).toEqual([]);
  });

  test('changing an inbound protocol under the same tag replaces its uuid', async () => {
    const before = await api('GET', `config-profiles/${profileUuid}`);
    const config = structuredClone(before.data.config);
    const idx = config.inbounds.findIndex((i: any) => i.tag === tagB);
    config.inbounds[idx] = {
      tag: tagB,
      port: 20444,
      protocol: 'trojan',
      settings: { clients: [] },
      streamSettings: { network: 'tcp', security: 'none' },
    };
    const patched = await api('PATCH', 'config-profiles', { uuid: profileUuid, config });
    // The backend ACCEPTS this and replaces the inbound's uuid, which is why a
    // patch op may never change an inbound's protocol (lib/backend/patchOps.ts):
    // every Host, mode group and listener binding hangs off that uuid. A backend that
    // started refusing it would call for different handling, so the outcome is
    // pinned, not merely recorded.
    expect(patched.status).toBe(200);
    const after = await api('GET', `config-profiles/${profileUuid}`);
    expect(uuidOfTag(after.data, tagA)).toBe(uuidOfTag(before.data, tagA));
    expect(uuidOfTag(after.data, tagB)).not.toBe(uuidOfTag(before.data, tagB));
  });

  test("FCP's management writes drive the live backend, and every result is read back", async () => {
    const cfg = {
      type: 'remnawave' as const,
      baseUrl: BASE_URL!,
      apiToken: API_TOKEN!,
      timeoutMs: 20_000,
    };
    const w = PROVIDERS.remnawave.panelWrites!;
    const profile = await api('GET', `config-profiles/${profileUuid}`);
    const a = uuidOfTag(profile.data, tagA)!;
    const inbound = { configProfileUuid: profileUuid, configProfileInboundUuid: a };

    const { hostUuid } = await w.createHost(cfg, {
      remark: `fcp-w-${run}`,
      address: '192.0.2.30',
      port: 443,
      sni: 'a.example',
      fingerprint: 'chrome',
      alpn: 'h2',
      inbound,
    });
    created.hosts.push(hostUuid);
    await w.updateHost(cfg, hostUuid, {
      sni: null,
      fingerprint: 'firefox',
      remark: `fcp-w-${run}-b`,
    });
    let seen = (await w.readHosts(cfg)).find((h) => h.hostUuid === hostUuid)!;
    // `null` clears a text field; an untouched field keeps its value.
    expect(seen).toMatchObject({
      remark: `fcp-w-${run}-b`,
      sni: null,
      fingerprint: 'firefox',
      alpn: 'h2',
      address: '192.0.2.30',
      configProfileInboundUuid: a,
    });
    await w.reorderHosts(cfg, [{ hostUuid, viewPosition: 7 }]);
    seen = (await w.readHosts(cfg)).find((h) => h.hostUuid === hostUuid)!;
    expect(seen.viewPosition).toBe(7);
    await w.deleteHost(cfg, hostUuid);
    expect((await w.readHosts(cfg)).some((h) => h.hostUuid === hostUuid)).toBe(false);
    created.hosts = created.hosts.filter((u) => u !== hostUuid);

    const { squadUuid } = await w.createSquad(cfg, { name: `fcpw-${run}`, inboundUuids: [a] });
    created.squads.push(squadUuid);
    await w.updateSquad(cfg, squadUuid, { name: `fcpw-${run}-b` });
    let squad = (await w.readSquads(cfg)).find((x) => x.squadUuid === squadUuid)!;
    expect(squad).toMatchObject({ name: `fcpw-${run}-b`, inboundUuids: [a] });
    await w.updateSquad(cfg, squadUuid, { inboundUuids: [] });
    squad = (await w.readSquads(cfg)).find((x) => x.squadUuid === squadUuid)!;
    expect(squad.inboundUuids).toEqual([]);
    await w.deleteSquad(cfg, squadUuid);
    expect((await w.readSquads(cfg)).some((x) => x.squadUuid === squadUuid)).toBe(false);
    created.squads = created.squads.filter((u) => u !== squadUuid);

    const b = uuidOfTag(profile.data, tagB)!;
    const { nodeUuid } = await w.createNode(cfg, {
      name: `fcpw-${run}`,
      address: '192.0.2.40',
      countryCode: 'NL',
      configProfileUuid: profileUuid,
      activeInboundUuids: [a],
    });
    created.nodes.push(nodeUuid);
    const node = async () => (await w.readNodeStatus(cfg)).find((n) => n.nodeUuid === nodeUuid)!;
    expect(await node()).toMatchObject({
      name: `fcpw-${run}`,
      address: '192.0.2.40',
      countryCode: 'NL',
      configProfileUuid: profileUuid,
      activeInboundUuids: [a],
      isDisabled: false,
    });
    // A rename leaves the profile assignment alone; the assignment travels as one.
    await w.updateNode(cfg, nodeUuid, { name: `fcpw-${run}-b` });
    expect(await node()).toMatchObject({ name: `fcpw-${run}-b`, activeInboundUuids: [a] });
    await w.updateNode(cfg, nodeUuid, {
      profile: { configProfileUuid: profileUuid, activeInboundUuids: [a, b] },
    });
    expect((await node()).activeInboundUuids.sort()).toEqual([a, b].sort());
    await w.setNodeEnabled(cfg, nodeUuid, false);
    expect((await node()).isDisabled).toBe(true);
    await w.setNodeEnabled(cfg, nodeUuid, true);
    expect((await node()).isDisabled).toBe(false);
    await w.restartNode(cfg, nodeUuid);
    await w.deleteNode(cfg, nodeUuid);
    // The backend queues the removal: the row leaves shortly after, not with the answer.
    let gone = false;
    for (let i = 0; i < 20 && !gone; i++) {
      gone = !(await w.readNodeStatus(cfg)).some((n) => n.nodeUuid === nodeUuid);
      if (!gone) await new Promise((r) => setTimeout(r, 250));
    }
    expect(gone).toBe(true);
    created.nodes = created.nodes.filter((u) => u !== nodeUuid);
  });

  test('mode groups: create, rename, change inbounds, delete', async () => {
    const profile = await api('GET', `config-profiles/${profileUuid}`);
    const a = uuidOfTag(profile.data, tagA)!;
    const b = uuidOfTag(profile.data, tagB)!;
    const made = await api('POST', 'internal-squads', { name: `fcp-${run}`, inbounds: [a] });
    expect(made.status).toBe(201);
    const squadUuid = made.data.uuid as string;
    created.squads.push(squadUuid);
    expect(made.data.inbounds.map((i: any) => i.uuid)).toEqual([a]);

    const renamed = await api('PATCH', 'internal-squads', {
      uuid: squadUuid,
      name: `fcp-${run}-b`,
    });
    expect(ok(renamed)).toBe(true);
    expect(renamed.data.name).toBe(`fcp-${run}-b`);
    // A rename alone must not drop the inbound assignment.
    expect(renamed.data.inbounds.map((i: any) => i.uuid)).toEqual([a]);

    const moved = await api('PATCH', 'internal-squads', { uuid: squadUuid, inbounds: [a, b] });
    expect(ok(moved)).toBe(true);
    expect(moved.data.inbounds.map((i: any) => i.uuid).sort()).toEqual([a, b].sort());

    const gone = await api('DELETE', `internal-squads/${squadUuid}`);
    expect(ok(gone)).toBe(true);
    created.squads = created.squads.filter((u) => u !== squadUuid);
    const list = await api('GET', 'internal-squads');
    const rows = list.data.internalSquads ?? list.data;
    expect(rows.some((s: any) => s.uuid === squadUuid)).toBe(false);
  });

  test('hosts: create with the full field set, edit, rebind, reorder, delete', async () => {
    const profile = await api('GET', `config-profiles/${profileUuid}`);
    const a = uuidOfTag(profile.data, tagA)!;
    const made = await api('POST', 'hosts', {
      inbound: { configProfileUuid: profileUuid, configProfileInboundUuid: a },
      remark: `fcp-${run}`,
      address: '192.0.2.10',
      port: 443,
      sni: 'a.example',
      fingerprint: 'chrome',
      alpn: 'h2',
      isDisabled: false,
    });
    expect(made.status).toBe(201);
    const hostUuid = made.data.uuid as string;
    created.hosts.push(hostUuid);
    expect(made.data.fingerprint).toBe('chrome');
    expect(made.data.alpn).toBe('h2');

    // A partial PATCH changes only what it names.
    const edited = await api('PATCH', 'hosts', {
      uuid: hostUuid,
      remark: `fcp-${run}-b`,
      fingerprint: 'firefox',
    });
    expect(ok(edited)).toBe(true);
    expect(edited.data.remark).toBe(`fcp-${run}-b`);
    expect(edited.data.fingerprint).toBe('firefox');
    expect(edited.data.address).toBe('192.0.2.10');
    expect(edited.data.sni).toBe('a.example');

    // Host attributes do not enforce uniqueness: an identical create is a second Host.
    const twin = await api('POST', 'hosts', {
      inbound: { configProfileUuid: profileUuid, configProfileInboundUuid: a },
      remark: `fcp-${run}-b`,
      address: '192.0.2.10',
      port: 443,
    });
    // Pinned: this is why a create whose answer was lost is settled by
    // DISCOVERY and never by a second create (lib/backend/ops.ts).
    expect(twin.status).toBe(201);
    created.hosts.push(twin.data.uuid);
    expect(twin.data.uuid).not.toBe(hostUuid);

    const reordered = await api('POST', 'hosts/actions/reorder', {
      hosts: created.hosts.map((uuid, i) => ({ uuid, viewPosition: created.hosts.length - i })),
    });
    observed.reorderStatus = reordered.status;
    expect(ok(reordered)).toBe(true);

    for (const u of [...created.hosts]) {
      const gone = await api('DELETE', `hosts/${u}`);
      expect(ok(gone)).toBe(true);
    }
    created.hosts = [];
  });

  test('nodes: create a backend row, rename, disable, enable, restart, delete', async () => {
    const profile = await api('GET', `config-profiles/${profileUuid}`);
    const a = uuidOfTag(profile.data, tagA)!;
    const made = await api('POST', 'nodes', {
      name: `fcp-${run}`,
      address: '192.0.2.20',
      port: 2222,
      countryCode: 'XX',
      configProfile: { activeConfigProfileUuid: profileUuid, activeInbounds: [a] },
    });
    expect(made.status).toBe(201);
    const nodeUuid = made.data.uuid as string;
    created.nodes.push(nodeUuid);
    expect(made.data.configProfile.activeConfigProfileUuid).toBe(profileUuid);
    // The fields a lifecycle observation would have to be built from (recorded).
    observed.nodeStatusFields = ['isConnected', 'isConnecting', 'xrayUptime', 'lastStatusChange']
      .filter((k) => k in made.data)
      .sort();
    observed.xrayUptimeOnNeverConnectedNode = made.data.xrayUptime ?? null;

    const renamed = await api('PATCH', 'nodes', {
      uuid: nodeUuid,
      name: `fcp-${run}-b`,
      tags: ['FCP_MANAGED'],
    });
    expect(ok(renamed)).toBe(true);
    expect(renamed.data.name).toBe(`fcp-${run}-b`);
    expect(renamed.data.tags).toEqual(['FCP_MANAGED']);
    expect(renamed.data.configProfile.activeConfigProfileUuid).toBe(profileUuid);

    const disabled = await api('POST', `nodes/${nodeUuid}/actions/disable`);
    expect(ok(disabled)).toBe(true);
    expect(disabled.data.isDisabled).toBe(true);
    // Not a no-op contract: a repeat is recorded so the caller knows to check state first.
    const disabledAgain = await api('POST', `nodes/${nodeUuid}/actions/disable`);
    observed.repeatDisableStatus = disabledAgain.status;

    const enabled = await api('POST', `nodes/${nodeUuid}/actions/enable`);
    expect(ok(enabled)).toBe(true);
    expect(enabled.data.isDisabled).toBe(false);

    const restarted = await api('POST', `nodes/${nodeUuid}/actions/restart`, {
      forceRestart: true,
    });
    observed.restartBody = restarted.data;
    // 202: the answer means "queued", not "restarted". The ledger settles a
    // restart by the node's own clock for exactly this reason.
    expect(restarted.status).toBe(202);

    const gone = await api('DELETE', `nodes/${nodeUuid}`);
    expect(ok(gone)).toBe(true);
    created.nodes = [];
  });
});
