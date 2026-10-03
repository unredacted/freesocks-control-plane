import { describe, expect, test } from 'vitest';
import { ADDRESS_SEP, HOST_REMARK_MAX, addressRemark, ownsAddress, remarkTag } from './hostRemark';

describe('addressRemark', () => {
  test('keeps the readable form when it fits', () => {
    expect(addressRemark('node-a', 'dl.example')).toBe('node-a | dl.example');
  });

  test('never exceeds the backend cap, even for the longest node name and a long server name', () => {
    const name = 'n'.repeat(30); // node names are 3 to 30 characters
    for (const sni of ['a-much-longer-server-name.example.org', `${'x'.repeat(60)}.example`]) {
      const r = addressRemark(name, sni);
      expect(r.length).toBeLessThanOrEqual(HOST_REMARK_MAX);
      expect(ownsAddress(name, r)).toBe(true);
    }
    // The case found on beta: a generated three-word name and a 15+ character name.
    const r = addressRemark('yammers-differs-noodled', 'android.clients.example.com');
    expect(r.length).toBeLessThanOrEqual(HOST_REMARK_MAX);
    expect(r.startsWith(`yammers-differs-noodled${ADDRESS_SEP}`)).toBe(true);
  });

  test('is deterministic and tells different names apart', () => {
    const node = 'yammers-differs-noodled';
    expect(addressRemark(node, 'one-long-name.example.org')).toBe(
      addressRemark(node, 'one-long-name.example.org'),
    );
    expect(addressRemark(node, 'one-long-name.example.org')).not.toBe(
      addressRemark(node, 'two-long-name.example.org'),
    );
  });

  test('the tag is short, lowercase, has no dot, and ignores case', () => {
    const tag = remarkTag('Some.Name.Example');
    expect(tag).toMatch(/^[0-9a-z]{7}$/);
    expect(tag).toBe(remarkTag('some.name.example'));
  });

  test('a node never claims another node whose name it prefixes', () => {
    expect(ownsAddress('node-a', addressRemark('node-a-west', 'x.example'))).toBe(false);
  });
});
