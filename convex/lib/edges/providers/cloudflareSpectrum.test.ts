/**
 * The Spectrum adapter's own rules: what the relay Worker is and is not
 * given, the application body, the DNS-derived addresses and when an edge
 * counts as active. The wire shapes are pinned by wireContract.test.ts.
 */
import { afterEach, describe, expect, test } from 'vitest';
import {
  SPECTRUM_RELAY_WORKER,
  SPECTRUM_WORKER_COMPATIBILITY_DATE,
  SPECTRUM_WORKER_MODULE,
  __setSpectrumResolver,
  spectrumAddressesOf,
  spectrumAppBody,
  spectrumAppName,
  spectrumProvider,
  spectrumWorkerMetadata,
} from './cloudflareSpectrum';
import { locationEdgeCapOf } from './capabilities';
import { placeKeyOf, ANYCAST_PLACE } from '../locations';
import type { SpectrumConfig } from './types';

const cfg: SpectrumConfig = {
  type: 'cloudflareSpectrum',
  apiToken: 'SECRET_CF_TOKEN',
  zoneId: '023e105f4ecef8ad9ca31a8372d0c353',
  zoneName: 'Example.NET.',
};

afterEach(() => __setSpectrumResolver(null));

describe('the relay Worker', () => {
  test('pipes both ways with half-close and never reads the member address', () => {
    expect(SPECTRUM_RELAY_WORKER).toContain('async connect(socket, env)');
    expect(SPECTRUM_RELAY_WORKER).toContain('allowHalfOpen: true');
    expect(SPECTRUM_RELAY_WORKER).toContain('secureTransport: "off"');
    expect(SPECTRUM_RELAY_WORKER).toContain('socket.readable.pipeTo(origin.writable)');
    expect(SPECTRUM_RELAY_WORKER).toContain('origin.readable.pipeTo(socket.writable)');
    // Nothing about the member is read or printed.
    expect(SPECTRUM_RELAY_WORKER).not.toMatch(/remoteAddress|opened|console\./);
    // No fetch handler: the Worker answers nothing on HTTP.
    expect(SPECTRUM_RELAY_WORKER).not.toContain('fetch(');
  });

  test('gets the node as plain-text bindings, with logs and Logpush off', () => {
    const m = spectrumWorkerMetadata({ address: '198.51.100.7', port: 8443 }, {});
    expect(m).toEqual({
      main_module: SPECTRUM_WORKER_MODULE,
      compatibility_date: SPECTRUM_WORKER_COMPATIBILITY_DATE,
      bindings: [
        { type: 'plain_text', name: 'ORIGIN_HOST', text: '198.51.100.7' },
        { type: 'plain_text', name: 'ORIGIN_PORT', text: '8443' },
      ],
      observability: { enabled: false },
      logpush: false,
    });
    expect(
      spectrumWorkerMetadata({ address: '198.51.100.7', port: 443 }, { cpuLimitMs: 300_000 }),
    ).toMatchObject({ limits: { cpu_ms: 300_000 } });
  });
});

describe('the application', () => {
  const spec = {
    name: 'fcp-relay-node-a-0badf00d',
    listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
  };

  test('its DNS name is stable, under the zone, and never carries the edge name', () => {
    const name = spectrumAppName(cfg, spec);
    expect(name).toBe(spectrumAppName(cfg, spec));
    expect(name).toMatch(/^[a-z0-9]{12}\.example\.net$/);
    expect(name).not.toContain('node-a');
    expect(spectrumAppName(cfg, { name: 'fcp-relay-node-b-0badf00d' })).not.toBe(name);
  });

  test('forwards one TCP port to the Worker; IPv4 only when asked', () => {
    expect(spectrumAppBody(cfg, 'x.example.net', 443, 'tag1', { ipFamily: 'dual' })).toEqual({
      zone_id: cfg.zoneId,
      dns: { type: 'CNAME', name: 'x.example.net' },
      protocol: 'tcp/443',
      traffic_type: 'worker',
      origin_worker_id: 'tag1',
      edge_ips: { type: 'dynamic', connectivity: 'all' },
    });
    expect(spectrumAppBody(cfg, 'x.example.net', 8443, 'tag1', { ipFamily: 'ipv4' })).toMatchObject(
      { protocol: 'tcp/8443', edge_ips: { connectivity: 'ipv4' } },
    );
  });

  test('an IPv6-only template is refused (publishing needs an IPv4)', () => {
    expect(spectrumProvider.templateSchema.safeParse({ ipFamily: 'ipv6' }).success).toBe(false);
    expect(spectrumProvider.defaultTemplate).toEqual({ ipFamily: 'dual' });
  });

  test('two listeners or a UDP one are refused before anything is made', async () => {
    const [worker] = spectrumProvider.planProvision(cfg, spec, spectrumProvider.defaultTemplate);
    const empty = { steps: [], resources: [] };
    for (const bad of [
      {
        ...spec,
        listeners: [...spec.listeners, { edgePort: 8443, members: spec.listeners[0]!.members }],
      },
      { ...spec, listeners: [{ ...spec.listeners[0]!, transport: 'udp' as const }] },
    ])
      await expect(
        spectrumProvider.runStep(cfg, worker!, bad, spectrumProvider.defaultTemplate, empty),
      ).rejects.toMatchObject({ meta: { retryable: false } });
  });
});

describe('addresses', () => {
  test('come from DNS; a name with no record yet answers nothing', async () => {
    __setSpectrumResolver(() => ({
      resolve4: async () => ['203.0.113.9', '203.0.113.2'],
      resolve6: async () => {
        throw Object.assign(new Error('no data'), { code: 'ENODATA' });
      },
    }));
    expect(await spectrumAddressesOf('x.example.net')).toEqual({ v4: '203.0.113.2' });
  });

  test('a failed lookup is an error, not an empty answer', async () => {
    __setSpectrumResolver(() => ({
      resolve4: async () => {
        throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
      },
      resolve6: async () => [],
    }));
    await expect(spectrumAddressesOf('x.example.net')).rejects.toMatchObject({
      meta: { code: 'dns_lookup_failed' },
    });
  });
});

describe('places', () => {
  test('a zone is not a place (anycast), and holds one edge whatever its own cap', () => {
    expect(
      placeKeyOf({ type: 'cloudflareSpectrum', zoneId: cfg.zoneId, zoneName: 'example.net' }),
    ).toBe(ANYCAST_PLACE);
    expect(locationEdgeCapOf('cloudflareSpectrum', null)).toBe(1);
    expect(locationEdgeCapOf('cloudflareSpectrum', 5)).toBe(1);
    expect(locationEdgeCapOf('cloudflareSpectrum', 0)).toBe(0);
    // Other providers keep the location's own cap.
    expect(locationEdgeCapOf('gcore', null)).toBeNull();
    expect(locationEdgeCapOf('gcore', 3)).toBe(3);
  });
});
