import { randomUUID, generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { remnawaveIssueUser } from '../../convex/lib/backends/remnawave';

export const compose = [
  'compose',
  '-p',
  'fcp-compat',
  '-f',
  'docker-compose.remnawave-test.yml',
  '-f',
  'docker-compose.compat.yml',
];
export function docker(...args: string[]) {
  return execFileSync('docker', [...compose, ...args], {
    encoding: 'utf8',
    timeout: 60_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}
export async function seedPanel() {
  if (
    process.env.FCP_COMPAT_ISOLATED !== '1' ||
    process.env.REMNAWAVE_TEST_URL !== 'http://localhost:3000'
  )
    throw new Error('Run with test:compat in the disposable local stack');
  const cfg = {
    baseUrl: process.env.REMNAWAVE_TEST_URL,
    apiToken: process.env.REMNAWAVE_TEST_TOKEN!,
    timeoutMs: 15_000,
  };
  // Fixture API responses stay in memory. Never include raw errors with credentials.
  async function api(path: string, method = 'GET', body?: unknown): Promise<any> {
    const res = await fetch(new URL(`/api/${path}`, cfg.baseUrl), {
      method,
      headers: { authorization: `Bearer ${cfg.apiToken}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`Test panel ${method} ${path.split('/')[0]}: HTTP ${res.status}`);
    return (await res.json()).response;
  }
  const keys = generateKeyPairSync('x25519');
  const privateKey = keys.privateKey
    .export({ type: 'pkcs8', format: 'der' })
    .subarray(-32)
    .toString('base64url');
  const publicKey = keys.publicKey
    .export({ type: 'spki', format: 'der' })
    .subarray(-32)
    .toString('base64url');
  const shortId = '1234567890abcdef';
  const profile = await api('config-profiles', 'POST', {
    name: 'FCP compatibility',
    config: {
      inbounds: [
        {
          tag: 'compat-reality',
          port: 443,
          protocol: 'vless',
          settings: { clients: [], decryption: 'none' },
          streamSettings: {
            network: 'tcp',
            security: 'reality',
            realitySettings: {
              dest: 'compat-origin:8443',
              serverNames: ['compat-origin'],
              privateKey,
              publicKey,
              shortIds: [shortId],
            },
          },
        },
      ],
      outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
    },
  });
  const inbound = profile.inbounds[0];
  const squad = await api('internal-squads', 'POST', {
    name: 'FCP compatibility',
    inbounds: [inbound.uuid],
  });
  await api('hosts', 'POST', {
    inbound: { configProfileUuid: profile.uuid, configProfileInboundUuid: inbound.uuid },
    remark: 'compat-node',
    address: 'compat-proxy',
    port: 443,
    sni: 'compat-origin',
    fingerprint: 'chrome',
  });
  const templates = await api('subscription-templates');
  for (const template of templates.subscriptionTemplates ?? templates.templates ?? templates) {
    if (template.templateType === 'SINGBOX') {
      await api('subscription-templates', 'PATCH', {
        uuid: template.uuid,
        templateJson: {
          log: { level: 'error' },
          inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: 1080 }],
          outbounds: [{ type: 'selector', tag: 'proxy', outbounds: [] }],
          route: { final: 'proxy' },
        },
      });
    } else if (['MIHOMO', 'CLASH'].includes(template.templateType)) {
      const yaml =
        'mixed-port: 1080\nallow-lan: false\nmode: rule\nlog-level: error\nproxies: []\nproxy-groups:\n  - name: proxy\n    type: select\n    proxies: []\nrules:\n  - MATCH,proxy\n';
      await api('subscription-templates', 'PATCH', {
        uuid: template.uuid,
        encodedTemplateYaml: Buffer.from(yaml).toString('base64'),
      });
    }
  }
  const issued = await remnawaveIssueUser(cfg, {
    username: `compat_${randomUUID().slice(0, 8)}`,
    placement: squad.uuid,
    tag: 'COMPAT',
    expireAt: null,
    trafficLimitBytes: 1024 ** 3,
  });
  const rawUser = await api(`users/${issued.backendUserId}`);
  const uuid = rawUser.vlessUuid;
  if (typeof uuid !== 'string') throw new Error('Panel user lacks VLESS credential');
  writeFileSync(
    '.cache/compat/runtime/server.json',
    JSON.stringify({
      log: { level: 'error' },
      inbounds: [
        {
          type: 'vless',
          listen: '::',
          listen_port: 443,
          users: [{ uuid, flow: 'xtls-rprx-vision' }],
          tls: {
            enabled: true,
            server_name: 'compat-origin',
            reality: {
              enabled: true,
              private_key: privateKey,
              short_id: [shortId],
              handshake: { server: 'compat-origin', server_port: 8443 },
            },
          },
        },
      ],
      outbounds: [{ type: 'direct' }],
    }),
  );
  docker('up', '-d', 'compat-origin', 'compat-proxy', 'compat-client');
  return { cfg, issued, api };
}
