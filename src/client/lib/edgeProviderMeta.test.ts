import { describe, expect, it } from 'vitest';
import { EDGE_PROVIDER_IDS } from '../../shared/contracts/edges';
import {
  EDGE_PROVIDER_META,
  addressLine,
  dnsProviderIds,
  layerLabel,
  providerAddressKind,
  providerLabel,
  providerLayer,
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
    expect(EDGE_PROVIDER_META.cloudflare.l7Transports).toEqual(['ws', 'httpupgrade', 'grpc']);
    expect(EDGE_PROVIDER_META.fastly.l7Transports).toEqual(['ws']);
  });

  it('offers a DNS account only from providers that host DNS', () => {
    expect(dnsProviderIds()).toEqual(['cloudflare']);
    expect(EDGE_PROVIDER_META.fastly.needsDnsAccount).toBe(true);
    expect(EDGE_PROVIDER_META.fastly.providesDns).toBe(false);
  });

  it('labels providers and layers', () => {
    expect(providerLabel('cloudflare')).toBe('Cloudflare');
    expect(providerLabel(null)).toBe('adopted');
    expect(providerLayer('fastly')).toBe('l7');
    expect(providerLayer(null)).toBe('l4');
    expect(providerAddressKind('cloudflare')).toBe('hostname');
    expect(providerAddressKind('gcore')).toBe('ip');
    expect(layerLabel('l7')).toBe('L7');
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
