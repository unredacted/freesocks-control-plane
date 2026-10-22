import { describe, expect, it } from 'vitest';
import { EDGE_PROVIDER_IDS } from '../../shared/contracts/edges';
import {
  DNS_ACCOUNT_BLURB,
  EDGE_PROVIDER_META,
  addressLine,
  defaultProviderFor,
  dnsProviderNames,
  frontsNode,
  providerGroupOf,
  providerGroups,
} from './edgeProviderMeta';

describe('edge provider meta', () => {
  it('has an entry for every provider id', () => {
    expect(Object.keys(EDGE_PROVIDER_META).sort()).toEqual([...EDGE_PROVIDER_IDS].sort());
  });

  it('pairs the L7 layer with hostname addressing and HTTP transports', () => {
    for (const id of EDGE_PROVIDER_IDS) {
      const m = EDGE_PROVIDER_META[id];
      if (m.layer === 'l7') {
        expect(m.addressKind).toBe('hostname');
        expect(m.l7Transports.length).toBeGreaterThan(0);
      } else {
        expect(m.addressKind).toBe('ip');
        expect(m.l7Transports).toEqual([]);
      }
    }
  });

  it('mirrors the per-provider transport capability', () => {
    expect(EDGE_PROVIDER_META.cloudflare.l7Transports).toEqual([
      'ws',
      'httpupgrade',
      'grpc',
      'xhttp',
    ]);
    expect(EDGE_PROVIDER_META.fastly.l7Transports).toEqual(['ws']);
  });

  it('offers a DNS account only from providers that host DNS', () => {
    expect(EDGE_PROVIDER_META.fastly.needsDnsAccount).toBe(true);
    expect(EDGE_PROVIDER_META.fastly.providesDns).toBe(false);
  });

  it('offers a shared wildcard certificate only where fronts can share one', () => {
    expect(
      Object.entries(EDGE_PROVIDER_META)
        .filter(([, m]) => m.sharedCertificates)
        .map(([id]) => id),
    ).toEqual(['fastly']);
  });

  it('groups providers by what an account is for: L4, L7, then DNS', () => {
    const groups = providerGroups(EDGE_PROVIDER_IDS);
    expect(groups.map((g) => [g.id, g.title])).toEqual([
      ['l4', 'L4 edge providers'],
      ['l7', 'L7 edge providers'],
      ['dns', 'DNS providers'],
    ]);
    expect(groups.find((g) => g.id === 'l4')!.providers).toEqual([
      'gcore',
      'upcloud',
      'scaleway',
      'ovh',
    ]);
    expect(groups.find((g) => g.id === 'l7')!.providers).toEqual(['fastly']);
    // Cloudflare is a DNS provider here, listed ONLY as one (never as an L7 front).
    expect(groups.find((g) => g.id === 'dns')!.providers).toEqual(['cloudflare']);
    expect(providerGroupOf('cloudflare')).toBe('dns');
    // Every provider sits in exactly one group.
    expect(groups.flatMap((g) => g.providers).sort()).toEqual([...EDGE_PROVIDER_IDS].sort());
  });

  it('names the supported DNS providers and says what a DNS account does', () => {
    expect(dnsProviderNames(EDGE_PROVIDER_IDS)).toEqual(['Cloudflare']);
    expect(DNS_ACCOUNT_BLURB).toMatch(/never member traffic/);
    for (const g of providerGroups(EDGE_PROVIDER_IDS)) expect(g.blurb).not.toMatch(/\u2014/);
  });

  it('an add-account form opens on an edge provider the caller can use, never a DNS provider', () => {
    expect(defaultProviderFor(EDGE_PROVIDER_IDS)).toBe('gcore');
    expect(defaultProviderFor(EDGE_PROVIDER_IDS, ['l4'])).toBe('gcore');
    // An L7-only node opens on the L7 edge provider, not on the DNS provider listed before it.
    expect(defaultProviderFor(EDGE_PROVIDER_IDS, ['l7'])).toBe('fastly');
    expect(defaultProviderFor(['cloudflare', 'fastly'], ['l7'])).toBe('fastly');
    // Nothing fits the layers: still an edge provider, the form says why it cannot be used.
    expect(defaultProviderFor(['cloudflare', 'gcore'], ['l7'])).toBe('gcore');
  });

  it('a DNS provider can host DNS; a provider that needs a DNS account is an edge provider', () => {
    for (const id of EDGE_PROVIDER_IDS) {
      const m = EDGE_PROVIDER_META[id];
      if (m.role === 'dns') expect(m.providesDns).toBe(true);
      if (m.needsDnsAccount) expect(m.role).toBe('edge');
    }
  });

  it('a WebSocket node is offered no load balancer; any other node is offered every provider', () => {
    for (const id of EDGE_PROVIDER_IDS) {
      expect(frontsNode(id, true)).toBe(EDGE_PROVIDER_META[id].layer === 'l7');
      expect(frontsNode(id, false)).toBe(true);
    }
    // An id the console does not know is left to the server.
    expect(frontsNode('unknown', true)).toBe(true);
  });

  it('prefers the hostname over IP literals in one address line', () => {
    expect(addressLine({ v4: '198.51.100.7', v6: null, hostname: 'a.example' })).toBe('a.example');
    expect(addressLine({ v4: '198.51.100.7', v6: '2001:db8::1', hostname: null })).toBe(
      '198.51.100.7 · 2001:db8::1',
    );
    expect(addressLine({ v4: null, v6: null, hostname: null })).toBe('-');
    expect(addressLine({ v4: '198.51.100.7', v6: '2001:db8::1' }, ' / ')).toBe(
      '198.51.100.7 / 2001:db8::1',
    );
  });
});
