import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { addressRemark } from './backend/hostRemark';
import { MIHOMO_YAML } from './backend/subscriptionTemplates/MIHOMO';
import { encodeBase64 } from './edges/render/base64';
import { askMlkemKeyShare, MLKEM_KEY_SHARE_OPTION } from './realityKeyShares';
import { finishMemberBody } from './subscriptionDelivery';

const UUID = '11111111-2222-3333-4444-555555555555';
type Obj = Record<string, unknown>;

// The proxies the backend's Mihomo generator writes for a Host WITHOUT the
// Mihomo override (no `support-x25519mlkem768`). Example values only.
const REALITY: Obj = {
  name: 'reality',
  type: 'vless',
  server: '192.0.2.10',
  port: 443,
  uuid: UUID,
  'packet-encoding': 'xudp',
  flow: 'xtls-rprx-vision',
  tls: true,
  servername: 'www.decoy-a.example',
  'client-fingerprint': 'chrome',
  'reality-opts': { 'public-key': 'PUBKEY', 'short-id': '0123' },
};
const XHTTP: Obj = {
  name: 'xhttp',
  type: 'vless',
  server: '192.0.2.11',
  port: 443,
  uuid: UUID,
  tls: true,
  servername: 'www.decoy-b.example',
  network: 'xhttp',
  'client-fingerprint': 'chrome',
  'reality-opts': { 'public-key': 'PUBKEY', 'short-id': 'ab' },
  'xhttp-opts': {
    path: '/x',
    mode: 'stream-one',
    'download-settings': {
      server: '192.0.2.12',
      port: 443,
      tls: true,
      servername: 'www.decoy-c.example',
      'reality-opts': { 'public-key': 'PUBKEY2', 'short-id': 'cd' },
    },
  },
};
const WS_TLS: Obj = {
  name: 'ws',
  type: 'vless',
  server: 'cdn.example',
  port: 443,
  uuid: UUID,
  tls: true,
  servername: 'cdn.example',
  network: 'ws',
  'ws-opts': { path: '/ws', headers: { Host: 'cdn.example' } },
};

/** The backend's Mihomo template with these proxies spliced in, as it serves it. */
function body(proxies: Obj[]): string {
  const doc = YAML.parse(MIHOMO_YAML) as Obj & { 'proxy-groups': Obj[] };
  doc.proxies = proxies;
  doc['proxy-groups'][0]!.proxies = proxies.map((p) => p.name);
  return YAML.stringify(doc);
}

const asked = (opts: unknown) => ({ ...(opts as Obj), [MLKEM_KEY_SHARE_OPTION]: true });

describe('askMlkemKeyShare', () => {
  test('every REALITY proxy asks, the XHTTP download leg too, and nothing else moves', () => {
    const before = body([REALITY, XHTTP, WS_TLS]);
    const out = askMlkemKeyShare(before);
    expect(out.added).toBe(3);
    const doc = YAML.parse(out.content) as Obj & { proxies: Obj[] };
    const expected = YAML.parse(before) as Obj & { proxies: Obj[] };
    expected.proxies[0]!['reality-opts'] = asked(REALITY['reality-opts']);
    expected.proxies[1]!['reality-opts'] = asked(XHTTP['reality-opts']);
    const download = (expected.proxies[1]!['xhttp-opts'] as Obj)['download-settings'] as Obj;
    download['reality-opts'] = asked(download['reality-opts']);
    expect(doc).toEqual(expected);
    // A short id that reads like a number stays the string the node expects.
    expect((doc.proxies[0]!['reality-opts'] as Obj)['short-id']).toBe('0123');
  });

  test('a finished body comes back as it was', () => {
    const once = askMlkemKeyShare(body([REALITY, XHTTP])).content;
    expect(askMlkemKeyShare(once)).toEqual({ content: once, added: 0 });
  });

  test('a key the Host already sets stays, either way', () => {
    const off = {
      ...REALITY,
      'reality-opts': { 'public-key': 'P', [MLKEM_KEY_SHARE_OPTION]: false },
    };
    const on = { ...REALITY, name: 'on', 'reality-opts': asked({ 'public-key': 'P' }) };
    const both = body([off, on]);
    expect(askMlkemKeyShare(both)).toEqual({ content: both, added: 0 });
  });

  test('a body without a REALITY proxy, or not a Clash body, comes back verbatim', () => {
    const link = `vless://${UUID}@192.0.2.10:443?security=reality&type=tcp&sni=a.example&fp=chrome&pbk=P&sid=ab#x`;
    for (const content of [
      body([WS_TLS]),
      link,
      encodeBase64(link),
      JSON.stringify({ outbounds: [{ type: 'vless', tls: { reality: { enabled: true } } }] }),
      JSON.stringify([{ remarks: 'x', outbounds: [] }]),
      '<html>proxies:</html>',
      'proxies: [unclosed',
      'proxies: just a string',
      '',
    ])
      expect(askMlkemKeyShare(content)).toEqual({ content, added: 0 });
  });

  test('a proxy that is not an object, or REALITY options that are not, is skipped', () => {
    const odd = body([REALITY]).replace('proxies:\n', 'proxies:\n  - just-a-name\n');
    const out = askMlkemKeyShare(odd);
    expect(out.added).toBe(1);
    const strange = body([{ ...REALITY, 'reality-opts': 'PUBKEY' }]);
    expect(askMlkemKeyShare(strange)).toEqual({ content: strange, added: 0 });
  });
});

describe('finishMemberBody', () => {
  test('names the entries and asks for the key share, whatever the naming', () => {
    const NODE = 'quiet-amber-falcon';
    const named = { ...REALITY, name: addressRemark(NODE, 'www.decoy-a.example') };
    for (const naming of [{ siteName: 'FreeSocks', place: 'Example City' }, null]) {
      const doc = YAML.parse(finishMemberBody(body([named]), naming)) as { proxies: Obj[] };
      expect(doc.proxies[0]!['reality-opts']).toEqual(asked(REALITY['reality-opts']));
      if (naming) expect(doc.proxies[0]!.name).not.toContain(NODE);
    }
  });
});
