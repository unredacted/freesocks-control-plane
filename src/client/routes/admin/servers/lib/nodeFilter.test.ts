import { describe, expect, test } from 'vitest';
import { nodeMatches } from './nodeFilter';

describe('nodeMatches', () => {
  test('an empty or blank query matches every node', () => {
    expect(nodeMatches('', 'amber-fluent-harbor', null)).toBe(true);
    expect(nodeMatches('   ', 'amber-fluent-harbor', 'node1.example.org')).toBe(true);
  });

  test('matches the node name or the machine name, ignoring case', () => {
    expect(nodeMatches('fluent', 'amber-fluent-harbor', null)).toBe(true);
    expect(nodeMatches('NODE1', 'amber-fluent-harbor', 'node1.example.org')).toBe(true);
    expect(nodeMatches(' example ', 'amber-fluent-harbor', 'node1.example.org')).toBe(true);
  });

  test('no match on either name', () => {
    expect(nodeMatches('relay', 'amber-fluent-harbor', 'node1.example.org')).toBe(false);
    expect(nodeMatches('relay', 'amber-fluent-harbor', null)).toBe(false);
  });
});
