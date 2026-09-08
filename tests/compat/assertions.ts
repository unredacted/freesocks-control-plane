import { parse } from 'yaml';
import type { Format } from './manifest';

/** Never print a failed response: subscription bodies contain credentials. */
export function assertSubscription(body: string, format: Format): void {
  if (format === 'singbox') {
    let config;
    try {
      config = JSON.parse(body);
    } catch {
      throw new Error('Expected sing-box JSON; received non-JSON subscription');
    }
    if (
      !Array.isArray(config.outbounds) ||
      !config.outbounds.some((o: { type: string }) => o.type === 'vless')
    )
      throw new Error('No VLESS outbound in sing-box subscription');
  } else if (format === 'mihomo') {
    const config = parse(body);
    if (
      !Array.isArray(config?.proxies) ||
      !config.proxies.some((p: { type: string }) => p.type === 'vless')
    )
      throw new Error('No VLESS proxy in Mihomo subscription');
  } else if (format === 'links') {
    const content = body.trim().startsWith('vless://')
      ? body.trim()
      : Buffer.from(body.trim(), 'base64').toString('utf8');
    const links = content.split(/\r?\n/).filter(Boolean);
    if (!links.length || links.some((line) => !line.startsWith('vless://')))
      throw new Error('Expected VLESS subscription links');
    for (const line of links) {
      const url = new URL(line);
      if (!url.hostname || !url.port || !/^[0-9a-f-]{36}$/i.test(url.username))
        throw new Error('Incomplete VLESS link');
    }
  } else if (!body.startsWith('ss://')) throw new Error('Expected Outline access key');
}
