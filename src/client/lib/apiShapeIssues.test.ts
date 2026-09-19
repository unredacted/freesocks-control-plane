import { describe, expect, test } from 'vitest';
import { z } from 'zod';
import { responseShapeIssues } from './api';

describe('responseShapeIssues', () => {
  test('names the rejected fields and never their values', () => {
    const schema = z.object({
      node: z.object({ name: z.string() }),
      layers: z.array(z.enum(['l4'])),
    });
    const res = schema.safeParse({ node: { name: 7 }, layers: ['SECRET_VALUE'] });
    expect(res.success).toBe(false);
    if (res.success) return;
    const words = responseShapeIssues(res.error.issues);
    expect(words).toContain('node.name');
    expect(words).toContain('layers.0');
    expect(words).not.toContain('SECRET_VALUE');
  });

  test('caps the list and says how many were left out', () => {
    const issues = Array.from({ length: 9 }, (_, i) => ({ path: ['f', i], code: 'invalid_type' }));
    expect(responseShapeIssues(issues)).toContain('and 3 more');
    expect(responseShapeIssues([{ path: [], code: 'invalid_type' }])).toBe('(root) (invalid_type)');
  });
});
