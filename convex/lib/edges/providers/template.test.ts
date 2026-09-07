import { describe, expect, test } from 'vitest';
import { canonicalJson, parseTemplateParams, renderTemplateValue } from './template';
import { GcoreTemplate } from './gcore';

const spec = {
  name: 'fcp-relay-o1-01234567',
  listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 8443 }] }],
};

describe('templates', () => {
  test('placeholders are substituted in strings anywhere in the tree; other types pass through', () => {
    const out = renderTemplateValue(
      {
        a: 'lb-{{name}}',
        nested: { b: '{{originAddress}}:{{originPort}}', n: 5, list: ['{{edgePort}}', 'x', true] },
        unknown: '{{nope}}',
      },
      spec,
    );
    expect(out).toEqual({
      a: 'lb-fcp-relay-o1-01234567',
      nested: { b: '198.51.100.7:8443', n: 5, list: ['443', 'x', true] },
      unknown: '{{nope}}',
    });
  });

  test('canonicalJson sorts keys recursively so hashes are stable', () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: 2 } })).toBe(
      '{"a":{"c":2,"d":[3,{"y":2,"z":1}]},"b":1}',
    );
  });

  test('parseTemplateParams validates stored JSON through the adapter schema and defaults missing fields', () => {
    const t = parseTemplateParams(GcoreTemplate, '{"flavor":"lb1-2-4"}');
    expect(t.flavor).toBe('lb1-2-4');
    expect(t.healthMonitor.delay).toBe(10);
    expect(() => parseTemplateParams(GcoreTemplate, '{"flavor":""}')).toThrow();
    expect(parseTemplateParams(GcoreTemplate, 'not json').flavor).toBe('lb1-1-2');
  });
});
