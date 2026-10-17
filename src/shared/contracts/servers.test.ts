import { describe, expect, test } from 'vitest';
import { NodeRegistration } from './servers';

const base = {
  roleContractVersion: 2,
  mode: 'privacy-reality',
  observed: { management: { address: '192.0.2.10', port: 2222 } },
};

describe('NodeRegistration machineName', () => {
  test('a usable machine name is kept', () => {
    expect(NodeRegistration.parse({ ...base, machineName: 'node1.example.org' }).machineName).toBe(
      'node1.example.org',
    );
  });

  test('an unusable one reads as absent and never fails the registration', () => {
    for (const machineName of ['x'.repeat(254), 42, { name: 'node1' }, null]) {
      const parsed = NodeRegistration.safeParse({ ...base, machineName });
      expect(parsed.success).toBe(true);
      expect(parsed.data?.machineName).toBeUndefined();
    }
  });
});
