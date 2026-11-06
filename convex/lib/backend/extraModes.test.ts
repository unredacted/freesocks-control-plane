import { describe, expect, test } from 'vitest';
import {
  desiredExtraHost,
  extraHostDiff,
  extraModeProblem,
  extraRevision,
  extraTransportOn,
} from './extraModes';
import { hostMapperJson, hysteriaHostMapper } from './hostMapper';

const primary = {
  slug: 'privacy-reality',
  shape: { transport: 'reality' as const, fronting: 'direct' as const },
  transport: { uuid: 'r', port: 443, serverNames: ['decoy.example'] },
};
const extra = {
  slug: 'privacy-hysteria',
  shape: { transport: 'hysteria' as const, fronting: 'direct' as const },
  transport: { uuid: 'h', port: 443, serverNames: ['quic.example'] },
};
const base = {
  primary,
  extra,
  served: [] as string[],
  primaryOpening: { port: 443, protocol: 'tcp' as const },
  extraOpening: { port: 443, protocol: 'udp' as const },
  primaryNames: ['decoy.example'],
  extraName: 'quic.example',
};

describe('extraModeProblem', () => {
  test('Hysteria on UDP 443 beside REALITY on TCP 443 is fine', () => {
    expect(extraModeProblem(base)).toBeNull();
    expect(extraModeProblem({ ...base, fallbackModeSlug: 'privacy-reality' })).toBeNull();
  });
  test.each([
    ['servers.mode_unknown', { extra: undefined }],
    ['servers.extra_mode_present', { served: ['privacy-hysteria'] }],
    ['servers.extra_mode_present', { extra: { ...extra, slug: 'privacy-reality' } }],
    ['servers.extra_mode_unsupported', { extra: { ...extra, shape: primary.shape } }],
    [
      'servers.extra_mode_node_not_direct',
      { primary: { ...primary, shape: { transport: 'reality', fronting: 'edge-l4' } } },
    ],
    ['servers.extra_mode_fallback_missing', { fallbackModeSlug: 'freedom-reality' }],
    ['servers.extra_mode_certificate', { extraOpening: null }],
    ['servers.port_taken', { extraOpening: { port: 443, protocol: 'tcp' } }],
    // Another extra mode of the node already listens there.
    ['servers.port_taken', { otherOpenings: [{ port: 443, protocol: 'udp' }] }],
    ['servers.extra_mode_name_collision', { extraName: 'Decoy.Example' }],
  ])('%s', (code, over) => {
    expect(extraModeProblem({ ...base, ...(over as object) } as typeof base)).toBe(code);
  });
});

describe('the address and its revision', () => {
  const auth = { serverName: 'quic.example', pinHex: 'ab'.repeat(32), spkiB64: 'c3Bracm==' };
  const want = desiredExtraHost({
    nodeName: 'node-a',
    originAddress: '203.0.113.10',
    port: 443,
    auth,
  });

  test('pinned, h3, TLS, with the rewrites that make every format pin', () => {
    expect(want).toMatchObject({
      remark: 'node-a | quic.example',
      address: '203.0.113.10',
      port: 443,
      sni: 'quic.example',
      alpn: 'h3',
      securityLayer: 'TLS',
      pinnedPeerCertSha256: auth.pinHex,
    });
    expect(want.mapper).toEqual(hysteriaHostMapper(auth));
    expect(want.mapperJson).toBe(hostMapperJson(want.mapper));
  });

  test('the diff names only what moved', () => {
    const have = { ...want, mapperJson: want.mapperJson };
    expect(extraHostDiff(have, want)).toBeNull();
    expect(extraHostDiff({ ...have, pinnedPeerCertSha256: 'x', mapperJson: null }, want)).toEqual({
      pinnedPeerCertSha256: auth.pinHex,
      mapper: want.mapper,
    });
  });

  test('the revision moves with the certificate identity and with the address', () => {
    const r = extraRevision({ transportUuid: 'h', authDigest: 'd1', host: want });
    expect(extraRevision({ transportUuid: 'h', authDigest: 'd1', host: want })).toBe(r);
    expect(extraRevision({ transportUuid: 'h', authDigest: 'd2', host: want })).not.toBe(r);
    expect(
      extraRevision({ transportUuid: 'h', authDigest: 'd1', host: { ...want, port: 8443 } }),
    ).not.toBe(r);
  });

  test('the transport is on from activating until its address is gone', () => {
    expect(extraTransportOn('waiting_firewall')).toBe(false);
    expect(extraTransportOn('activating')).toBe(true);
    expect(extraTransportOn('serving')).toBe(true);
    expect(extraTransportOn('removing', 'host-1')).toBe(true);
    expect(extraTransportOn('removing')).toBe(false);
  });
});

describe('hostMapperJson', () => {
  test('canonical, and null for an empty mapper', () => {
    expect(hostMapperJson({})).toBeNull();
    expect(hostMapperJson({ base64: [], mihomo: [] })).toBeNull();
    expect(hostMapperJson(null)).toBeNull();
    const a = hostMapperJson({
      mihomo: [{ op: 'unset', to: 'x' }],
      base64: [{ to: 'y', op: 'unset' }],
    });
    const b = hostMapperJson({
      base64: [{ op: 'unset', to: 'y' }],
      mihomo: [{ to: 'x', op: 'unset' }],
    });
    expect(a).toBe(b);
  });
});
