import { randomUUID, generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { remnawaveIssueUser } from '../../convex/lib/backends/remnawave';
import { addressRemark } from '../../convex/lib/backend/hostRemark';
import {
  SUBSCRIPTION_TEMPLATES,
  desiredTemplateBody,
  type TemplateFamily,
} from '../../convex/lib/backend/subscriptionTemplates';
import { compose } from './compose';
import { COMPAT_NODE, COMPAT_ENDPOINTS } from './fixture';

/** The seeded node's name: it must never reach a member body. */
export { COMPAT_NODE } from './fixture';
export const COMPAT_REMARK = addressRemark(COMPAT_NODE, 'compat-origin');
/** The selector group's name in the backend's own subscription templates. */
export const COMPAT_TEMPLATE_GROUP = '→ Remnawave';

type PanelApi = (path: string, method?: string, body?: unknown) => Promise<any>;

/**
 * Install one set of subscription templates on the test panel:
 *  - `fixture`: minimal, test-owned ones (a SOCKS listener, the selector
 *    group, a final rule to it) for the transport checks, with the group named
 *    as the backend's own templates name it: members receive it renamed
 *    (convex/lib/memberEntryNames.ts), and the real clients must accept that;
 *  - `shipped`: the templates FCP ships, byte for byte what backend setup and
 *    its re-sync write (convex/backendSetup.ts `reconcileTemplates`), so an
 *    engine runs what a member's client receives.
 */
export async function useTemplates(api: PanelApi, set: 'fixture' | 'shipped') {
  const templates = await api('subscription-templates');
  for (const template of templates.subscriptionTemplates ?? templates.templates ?? templates) {
    const family = template.templateType as TemplateFamily;
    if (set === 'shipped') {
      if (family in SUBSCRIPTION_TEMPLATES)
        await api('subscription-templates', 'PATCH', {
          uuid: template.uuid,
          ...desiredTemplateBody(SUBSCRIPTION_TEMPLATES[family]),
        });
    } else if (family === 'SINGBOX') {
      await api('subscription-templates', 'PATCH', {
        uuid: template.uuid,
        templateJson: {
          log: { level: 'error' },
          inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: 1080 }],
          outbounds: [{ type: 'selector', tag: COMPAT_TEMPLATE_GROUP, outbounds: [] }],
          route: { final: COMPAT_TEMPLATE_GROUP },
        },
      });
    } else if (family === 'MIHOMO' || family === 'CLASH') {
      const yaml = `mixed-port: 1080\nallow-lan: false\nmode: rule\nlog-level: error\nproxies: []\nproxy-groups:\n  - name: '${COMPAT_TEMPLATE_GROUP}'\n    type: select\n    proxies: []\nrules:\n  - MATCH,${COMPAT_TEMPLATE_GROUP}\n`;
      await api('subscription-templates', 'PATCH', {
        uuid: template.uuid,
        encodedTemplateYaml: Buffer.from(yaml).toString('base64'),
      });
    }
  }
}

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
      inbounds: COMPAT_ENDPOINTS.map((endpoint) => ({
        tag: `compat-reality-${endpoint.port}`,
        port: endpoint.port,
        protocol: 'vless',
        settings: { clients: [], decryption: 'none' },
        streamSettings: {
          network: 'tcp',
          security: 'reality',
          realitySettings: {
            dest: 'compat-origin:8443',
            serverNames: [endpoint.serverName],
            privateKey,
            publicKey,
            shortIds: [shortId],
          },
        },
      })),
      outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
    },
  });
  const squad = await api('internal-squads', 'POST', {
    name: 'FCP compatibility',
    inbounds: profile.inbounds.map((inbound: { uuid: string }) => inbound.uuid),
  });
  for (const endpoint of COMPAT_ENDPOINTS) {
    const inbound = profile.inbounds.find(
      (inbound: { tag: string }) => inbound.tag === `compat-reality-${endpoint.port}`,
    );
    if (!inbound) throw new Error('Panel did not create a compatibility inbound');
    await api('hosts', 'POST', {
      inbound: { configProfileUuid: profile.uuid, configProfileInboundUuid: inbound.uuid },
      // FCP's own address remark for a direct node (`<node> | <server name>`):
      // members receive it renamed (convex/lib/memberEntryNames.ts).
      remark: addressRemark(COMPAT_NODE, endpoint.serverName),
      address: endpoint.server,
      port: endpoint.port,
      sni: endpoint.serverName,
      fingerprint: 'chrome',
    });
  }
  await useTemplates(api, 'fixture');
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
      inbounds: COMPAT_ENDPOINTS.map((endpoint) => ({
        type: 'vless',
        listen: '::',
        listen_port: endpoint.port,
        users: [{ uuid, flow: 'xtls-rprx-vision' }],
        tls: {
          enabled: true,
          server_name: endpoint.serverName,
          reality: {
            enabled: true,
            private_key: privateKey,
            short_id: [shortId],
            handshake: { server: 'compat-origin', server_port: 8443 },
          },
        },
      })),
      outbounds: [{ type: 'direct' }],
    }),
  );
  docker('up', '-d', 'compat-origin', 'compat-proxy', 'compat-client');
  return { cfg, issued, api };
}
