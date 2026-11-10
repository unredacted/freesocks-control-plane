import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

// Every command is scoped to the runner's disposable compose project/volumes.
export async function testMigration({
  env,
  targetImage,
  compose,
  capture,
  ready,
  api,
  run,
  authorization,
  keys,
  composeArgs,
  healthcheck,
}) {
  const oldKeys = structuredClone(keys);
  const legacyImage = env.CAP_TEST_IMAGE;
  const bot = await api('/server/settings/apikeys', { name: 'migration fixture' }, authorization);
  await api('/server/keys', undefined, `Bot ${bot.apiKey}`);
  const legacyKey = await api(
    '/server/keys',
    { name: 'pre-SHA256 fixture', protocol: 'sha256-pow' },
    authorization,
  );
  const seedLegacy = () =>
    compose(
      'exec',
      '-T',
      'cap',
      'bun',
      '-e',
      `
    const db = new Bun.RedisClient(process.env.REDIS_URL);
    await db.send('HSET', [${JSON.stringify(`key:${legacyKey.siteKey}`)}, 'secretHash',
      await Bun.password.hash(${JSON.stringify(legacyKey.secretKey)})]); db.close();
  `,
    );
  seedLegacy();
  const legacyCheck = await fetch(`${env.FCP_CAP_TEST_URL}/cap/${legacyKey.siteKey}/siteverify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      secret: legacyKey.secretKey,
      response: `${legacyKey.siteKey}:old:token`,
    }),
  });
  assert.equal(legacyCheck.status, 404, 'the Argon2 fixture must be accepted by v3');
  // v3 upgrades an Argon2 hash on successful verification. Restore the old
  // format to represent a site key that has not been verified since that change.
  seedLegacy();
  compose('exec', '-T', 'valkey', 'valkey-cli', 'SAVE');
  compose('exec', '-T', 'valkey', 'cp', '/data/dump.rdb', '/data/v3.rdb');
  compose('stop', 'cap');
  env.CAP_TEST_IMAGE = targetImage;
  compose('up', '-d', 'cap');
  await ready();

  const request = (path, options = {}) =>
    fetch(`${env.FCP_CAP_TEST_URL}/cap${path}`, {
      ...options,
      signal: AbortSignal.timeout(5000),
    });
  assert.equal(
    (await request('/server/keys', { headers: { authorization } })).status,
    401,
    'v3 dashboard sessions must be invalidated',
  );
  assert.equal(
    (await request('/server/keys', { headers: { authorization: `Bot ${bot.apiKey}` } })).status,
    401,
    'v3 API keys must be invalidated',
  );
  for (const key of Object.values(keys)) {
    const response = await request(`/${key.siteKey}/siteverify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ secret: key.secretKey, response: `${key.siteKey}:old:token` }),
    });
    // Recent v3 releases already wrote SHA-256 site secrets. They keep working.
    assert.equal(response.status, 404);
    assert.equal((await response.json()).error, 'Token not found');
  }
  const outdated = await request(`/${legacyKey.siteKey}/siteverify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      secret: legacyKey.secretKey,
      response: `${legacyKey.siteKey}:old:token`,
    }),
  });
  assert.equal(outdated.status, 403);
  assert.match((await outdated.json()).error, /Reset the secret/);
  const session = await api('/auth/login', { admin_key: env.CAP_TEST_ADMIN_KEY });
  const auth = `Bearer ${Buffer.from(JSON.stringify({ token: session.session_token, hash: session.hashed_token })).toString('base64')}`;
  const migrated = await api('/server/keys', undefined, auth);
  assert.equal(migrated.length, Object.keys(keys).length + 1);
  assert.deepEqual(
    migrated.filter((key) => key.secretOutdated).map((key) => key.siteKey),
    [legacyKey.siteKey],
  );
  for (const key of [...Object.values(keys), legacyKey]) {
    const rotated = await api(`/server/keys/${key.siteKey}/rotate-secret`, {}, auth);
    key.secretKey = rotated.secretKey;
  }
  const newBot = await api('/server/settings/apikeys', { name: 'v4 fixture' }, auth);
  await api('/server/keys', undefined, `Bot ${newBot.apiKey}`);
  env.FCP_CAP_TEST_KEYS = JSON.stringify(keys);
  env.FCP_CAP_TEST_V4 = '1';
  console.log('[cap integration] v4 rotated secrets: real browser solves');
  run('bunx', ['playwright', 'test', '--config', 'tests/cap/playwright.config.ts']);

  // A dashboard setting must not re-enable forwarded IP collection. Send
  // identifiable sentinels through the real public proxy and inspect state.
  const headers = { 'content-type': 'application/json', authorization: auth };
  const settings = await request('/server/settings/headers', {
    method: 'PUT',
    headers,
    body: JSON.stringify({
      ipHeader: 'X-Forwarded-For',
      countryHeader: 'CF-IPCountry',
      asnHeader: '',
    }),
  });
  assert.equal(settings.status, 200);
  const markers = ['198.51.100.217', '2001:db8::217', 'fcp-private-user-agent-217'];
  const visitorHeaders = {
    'x-forwarded-for': markers.slice(0, 2).join(', '),
    'x-real-ip': markers[0],
    'cf-connecting-ip': markers[0],
    'cf-ipcountry': 'ZZ',
    'user-agent': markers[2],
  };
  await request(`/${keys.hashwx.siteKey}/challenge`, { method: 'POST', headers: visitorHeaders });
  await request('/auth/login', {
    method: 'POST',
    headers: { ...visitorHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({ admin_key: 'invalid-fixture-password' }),
  });
  // Check the actual installed modules, including in-memory event listeners
  // (which otherwise feed webhooks) and the fingerprint before persistence.
  compose(
    'exec',
    '-T',
    'cap',
    'bun',
    '-e',
    `
    const { requestContext } = await import('./src/events/context.js');
    const ctx = await requestContext(new Request('https://test.invalid/', {headers: ${JSON.stringify(visitorHeaders)}}),
      {requestIP: () => ({address: '172.19.0.2'})});
    if(ctx.ip !== '172.19.0.2' || ctx.fp || ctx.country || ctx.asn || ctx.lang || ctx.origin)
      throw new Error('Request context retained visitor data');
    const { onEvent, recordEvent, flush } = await import('./src/events/index.js');
    let emitted = false; onEvent(() => { emitted = true; });
    recordEvent({...ctx, type:'challenge', outcome:'pass', site_key:'fixture'}); await flush();
    if(emitted) throw new Error('Event escaped to a listener');
    const db = new Bun.RedisClient(process.env.REDIS_URL);
    for (const key of await db.send('KEYS', ['*'])) {
      const type = await db.send('TYPE', [key]);
      const command = {string:'GET', hash:'HGETALL', set:'SMEMBERS', list:'LRANGE', zset:'ZRANGE'}[type];
      if(!command) throw new Error('Uninspected Valkey type: ' + type);
      const args = ['list','zset'].includes(type) ? [key, '0', '-1'] : [key];
      const text = key + JSON.stringify(await db.send(command, args));
      if(${JSON.stringify(markers)}.some(marker => text.includes(marker))) throw new Error('Visitor data persisted in Valkey');
    }
    db.close();
    process.stdout.write('Request context and Valkey privacy verified\\n');
  `,
  );
  const dataVolume = capture('ps', '-q', 'cap');
  const volume = run(
    'docker',
    [
      'inspect',
      '--format',
      '{{range .Mounts}}{{if eq .Destination "/usr/src/app/data"}}{{.Name}}{{end}}{{end}}',
      dataVolume,
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  assert.ok(volume, 'Cap analytics must use an explicit named volume');
  compose('up', '-d', '--force-recreate', 'cap');
  await ready();
  const recreatedId = capture('ps', '-q', 'cap');
  assert.notEqual(recreatedId, dataVolume);
  assert.equal(
    run(
      'docker',
      [
        'inspect',
        '--format',
        '{{range .Mounts}}{{if eq .Destination "/usr/src/app/data"}}{{.Name}}{{end}}{{end}}',
        recreatedId,
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    ),
    volume,
  );
  await api('/server/keys', undefined, auth);

  compose('stop', 'valkey');
  let unavailable;
  // Cap reuses a successful PING for one second. Wait for that cache to expire.
  for (let attempt = 0; attempt < 10; attempt++) {
    unavailable = await request('/health');
    if (unavailable.status === 503) break;
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  assert.equal(unavailable.status, 503, 'readiness must fail when Valkey is down');
  const health = spawnSync('docker', [...composeArgs, 'exec', '-T', 'cap', ...healthcheck], {
    env,
    stdio: 'pipe',
  });
  assert.equal(health.status, 1, 'the production healthcheck must reject HTTP 503');
  compose('start', 'valkey');
  await ready();
  compose('stop', 'cap');
  assert.equal(
    (await request('/health?fcp-private-user-agent-217', { headers: visitorHeaders })).status,
    502,
  );
  const logs = capture('logs', '--no-color', 'cap', 'web');
  for (const marker of markers)
    assert.ok(!logs.includes(marker), 'Visitor data escaped to container logs');
  compose(
    'run',
    '--rm',
    '--no-deps',
    '--entrypoint',
    'bun',
    'cap',
    '-e',
    `
    const {DuckDBInstance} = await import('@duckdb/node-api');
    const db = await DuckDBInstance.create('/usr/src/app/data/events.duckdb');
    const conn = await db.connect();
    const rows = (await conn.runAndReadAll('SELECT count(*) AS n FROM events')).getRowObjectsJS();
    if(Number(rows[0].n) !== 0) throw new Error('Per-request events persisted');
    conn.closeSync(); db.closeSync();
    process.stdout.write('DuckDB contains no request events\\n');
  `,
  );

  // Restore the exact pre-upgrade snapshot, then prove both old credentials
  // and browser solves work again. No production data or services are used.
  compose('stop', 'valkey');
  compose(
    'run',
    '--rm',
    '--no-deps',
    '--entrypoint',
    'sh',
    'valkey',
    '-c',
    'cp /data/v3.rdb /data/dump.rdb',
  );
  env.CAP_TEST_IMAGE = legacyImage;
  compose('up', '-d', 'valkey', 'cap');
  await ready();
  await api('/server/keys', undefined, authorization);
  await api('/server/keys', undefined, `Bot ${bot.apiKey}`);
  env.FCP_CAP_TEST_KEYS = JSON.stringify(oldKeys);
  delete env.FCP_CAP_TEST_V4;
  console.log('[cap integration] restored v3 snapshot: real browser solves');
  run('bunx', ['playwright', 'test', '--config', 'tests/cap/playwright.config.ts']);
  console.log(
    '[cap integration] migration, rotation, persistence, readiness, privacy and rollback passed',
  );
}
