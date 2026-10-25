import { describe, expect, test } from 'vitest';
import { bodyMentionsAny } from './subscriptionDelivery';

describe('bodyMentionsAny (the leak check of a placeholder handed out as it is)', () => {
  const v6 = '2001:db8::10';
  test('every spelling of an address the renderer would call the same counts', () => {
    // An expanded, bracketed IPv6 inside a URL in a field no codec reads.
    expect(
      bodyMentionsAny(
        JSON.stringify({ dns: { servers: [{ address: 'https://[2001:0DB8:0:0:0:0:0:10]/q' }] } }),
        [v6],
      ),
    ).toBe(true);
    // An unbracketed IPv6 followed by a port.
    expect(bodyMentionsAny('server: 2001:db8:0::10:443', [v6])).toBe(true);
    // A name with a trailing dot, in any case.
    expect(bodyMentionsAny('host: Node.Example.ORG.', ['node.example.org'])).toBe(true);
    // An IPv4 literal anywhere in a line.
    expect(bodyMentionsAny('socks://203.0.113.7:1080', ['203.0.113.7'])).toBe(true);
    // Inside a base64 link list, and percent-encoded.
    expect(bodyMentionsAny(btoa('note 203.0.113.7'), ['203.0.113.7'])).toBe(true);
    expect(bodyMentionsAny('x?h=%5B2001%3Adb8%3A%3A10%5D', [v6])).toBe(true);
    // A name that embeds the address.
    expect(bodyMentionsAny('server: 203.0.113.7.nip.io', ['203.0.113.7'])).toBe(true);
  });
  test('other addresses, and no addresses at all, do not', () => {
    const body = 'vless://u@0.0.0.0:1?security=reality#Expired\nhttps://203.0.113.70/';
    expect(bodyMentionsAny(body, ['203.0.113.7'])).toBe(false);
    expect(bodyMentionsAny(body, ['2001:db8::11'])).toBe(false);
    expect(bodyMentionsAny(body, [])).toBe(false);
    expect(bodyMentionsAny(body, [''])).toBe(false);
  });
});
