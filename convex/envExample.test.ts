/// <reference types="vite/client" />
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';

/**
 * Drift lock: every DEPLOYMENT env var the backend reads statically
 * (`process.env.NAME` in convex/, excluding tests) must be documented in
 * `.env.convex.example` — so an operator populating `.env.convex` from the
 * example can't miss one (this is what let POP_REQUIRED go undiscovered).
 *
 * Scope + limits: only statically-referenced `process.env.NAME` is scanned.
 * Billing rails read their secrets via `dbOrEnv` → `process.env[name]` (dynamic),
 * so they're outside this check (already listed in the example); test-only vars
 * (REMNAWAVE_TEST_*) live in *.test.ts and are skipped.
 */
const sources = import.meta.glob('./**/*.ts', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;

// Deployment vars read statically but deliberately NOT in the example. Empty
// today; add an entry (with a reason) only if a var should stay undocumented.
const ALLOW_ABSENT = new Set<string>([]);

describe('.env.convex.example completeness', () => {
  test('every deployment env var convex/ reads is documented in .env.convex.example', () => {
    const read = new Set<string>();
    for (const [path, src] of Object.entries(sources)) {
      if (path.includes('/_generated/')) continue;
      if (/\.test\.ts$/.test(path)) continue; // unit + integration tests aren't deployment code
      for (const m of src.matchAll(/process\.env\.([A-Z_][A-Z0-9_]*)/g)) read.add(m[1]);
    }

    const example = readFileSync(
      fileURLToPath(new URL('../.env.convex.example', import.meta.url)),
      'utf8',
    );
    // A key is "documented" if it appears as `KEY=` on a line, commented or not.
    const documented = new Set(
      [...example.matchAll(/^#?\s*([A-Z_][A-Z0-9_]*)=/gm)].map((m) => m[1]),
    );

    const missing = [...read].filter((v) => !documented.has(v) && !ALLOW_ABSENT.has(v)).sort();
    expect(
      missing,
      `read by convex/ but missing from .env.convex.example: ${missing.join(', ')}`,
    ).toEqual([]);
  });
});
