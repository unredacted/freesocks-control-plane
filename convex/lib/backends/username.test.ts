import { describe, expect, test } from 'vitest';
import { BACKEND_USERNAME_MAX, BACKEND_USERNAME_RE, boundedUsername } from './username';
import { testCredentialUsername } from '../../edgeTestCredentials';
import { qualificationUsername } from '../../relayQualification';

// The longest node name FCP accepts (nodeIntents: 3 to 30) and an origin slug
// longer than any node name, with characters a username cannot carry.
const LONG_NODE = 'a-thirty-character-node-name-x';
const LONG_SLUG = 'Node.One/Very-Long-Relay-Slug-Name-That-Goes-On';

describe('backend usernames', () => {
  test('a name that fits is unchanged', () => {
    expect(boundedUsername('fcp-test-link-', 'outline-one', 'abcd1234')).toBe(
      'fcp-test-link-outline-one-abcd1234',
    );
    expect(boundedUsername('freesocks-', 'member', '0123456789abcdef')).toBe(
      'freesocks-member-0123456789abcdef',
    );
  });

  test('a long label is cut, never the suffix, and no dash is left dangling', () => {
    const u = boundedUsername('fcp-qualify-', LONG_SLUG, 'abcd1234');
    expect(u).toHaveLength(BACKEND_USERNAME_MAX);
    expect(u).toBe('fcp-qualify-node-one-very-l-abcd1234');
    expect(boundedUsername('fcp-test-rehearse-', 'abcdefgh-ijkl', 'abcd1234')).toBe(
      'fcp-test-rehearse-abcdefgh-abcd1234',
    );
  });

  test('a label cut to nothing drops its dash', () => {
    expect(boundedUsername('fcp-', '---', 'abcd1234')).toBe('fcp-abcd1234');
    expect(boundedUsername('p-'.repeat(9), 'label', 'x'.repeat(18))).toBe(
      `${'p-'.repeat(9)}${'x'.repeat(18)}`,
    );
  });

  test('every name FCP builds stays within the backend rule', () => {
    const built = [
      testCredentialUsername(LONG_NODE, 'test_link', 'abcd1234'),
      testCredentialUsername(LONG_NODE, 'rehearsal', 'abcd1234'),
      testCredentialUsername(LONG_SLUG, 'rehearsal', 'abcd1234'),
      qualificationUsername(LONG_SLUG, 'abcd1234'),
      boundedUsername(
        'freesocks-',
        'a-tier-slug-of-sixty-four-characters-is-what-admins-may-type-in',
        '0123456789abcdef',
      ),
    ];
    for (const u of built) {
      expect(u, u).toMatch(BACKEND_USERNAME_RE);
      expect(u.length, u).toBeLessThanOrEqual(BACKEND_USERNAME_MAX);
    }
    expect(built[0]).toBe('fcp-test-link-a-thirty-char-abcd1234');
  });
});
