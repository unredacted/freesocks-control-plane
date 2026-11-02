import { describe, expect, test } from 'vitest';
import { machineNameShown } from './machineName';

describe('machineNameShown', () => {
  test('a machine name that differs from the node name is shown', () => {
    expect(machineNameShown('amber-fluent-harbor', 'xray1-relay-site-fs-ce')).toBe(
      'xray1-relay-site-fs-ce',
    );
  });

  test('a machine name equal to the node name is left out, ignoring case and spaces', () => {
    expect(machineNameShown('xray1-relay-site-fs-ce', 'xray1-relay-site-fs-ce')).toBeNull();
    expect(machineNameShown('Xray1-Relay-Site-FS-CE', 'xray1-relay-site-fs-ce')).toBeNull();
    expect(machineNameShown(' xray1-relay-site-fs-ce', 'xray1-relay-site-fs-ce  ')).toBeNull();
  });

  test('no machine name (an adopted node) shows nothing', () => {
    expect(machineNameShown('amber-fluent-harbor', null)).toBeNull();
    expect(machineNameShown('amber-fluent-harbor', undefined)).toBeNull();
    expect(machineNameShown('amber-fluent-harbor', '  ')).toBeNull();
  });
});
