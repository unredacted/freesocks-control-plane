/// <reference types="vite/client" />
/**
 * The HPKE seal/open, epoch keygen and manifest signing run in V8 actions and
 * httpActions, where randomness is fresh on every call. Inside a query or a
 * mutation, Convex seeds `crypto.getRandomValues` and `Math.random` per
 * execution, so a retried or replayed execution repeats them: a seal there
 * would reuse an ephemeral key and nonce, silently. This pins the boundary
 * structurally: no module that registers a query or mutation may import any of
 * that code, directly or through any chain of imports.
 */
import { describe, expect, test } from 'vitest';

const sources: Record<string, string> = {
  ...(import.meta.glob('./**/*.{ts,mjs}', {
    query: '?raw',
    import: 'default',
    eager: true,
  }) as Record<string, string>),
  ...(import.meta.glob('../src/shared/**/*.ts', {
    query: '?raw',
    import: 'default',
    eager: true,
  }) as Record<string, string>),
};

/** Repo-relative path (`convex/x.ts`, `src/shared/...`) for each source. */
const files = new Map<string, string>();
for (const [key, src] of Object.entries(sources)) {
  if (/\.test\.ts$|\/_generated\//.test(key)) continue;
  const path = key.startsWith('./') ? `convex/${key.slice(2)}` : key.replace(/^\.\.\//, '');
  files.set(path, src);
}

const SENSITIVE = [
  'convex/lib/hpkeServer.ts',
  'convex/lib/hpkeCrypto.ts',
  'src/shared/crypto/hpke.ts',
  'src/shared/crypto/channel.ts',
  'src/shared/crypto/manifest.ts',
];

const stripComments = (src: string) =>
  src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');

function normalize(parts: string[]): string {
  const out: string[] = [];
  for (const p of parts) {
    if (p === '..') out.pop();
    else if (p !== '.' && p !== '') out.push(p);
  }
  return out.join('/');
}

function resolve(from: string, spec: string): string | null {
  const base = normalize([...from.split('/').slice(0, -1), ...spec.split('/')]);
  const noJs = base.replace(/\.js$/, '');
  for (const c of [base, `${noJs}.ts`, `${base}.ts`, `${base}/index.ts`, `${base}.mjs`]) {
    if (files.has(c)) return c;
  }
  return null;
}

/** Runtime (non type-only) relative imports and re-exports of a module. */
function importsOf(path: string): string[] {
  const src = stripComments(files.get(path) ?? '');
  const specs: string[] = [];
  const stmt = /^\s*(import|export)\s+(type\s+)?([\s\S]*?)\bfrom\s+['"](\.[^'"]+)['"]/gm;
  for (const m of src.matchAll(stmt)) if (!m[2]) specs.push(m[4]!);
  for (const m of src.matchAll(/^\s*import\s+['"](\.[^'"]+)['"]/gm)) specs.push(m[1]!);
  for (const m of src.matchAll(/\bimport\(\s*['"](\.[^'"]+)['"]\s*\)/g)) specs.push(m[1]!);
  return specs.map((s) => resolve(path, s)).filter((p): p is string => p !== null);
}

/** Every module reachable from `start`, with one import chain to each. */
function reach(start: string): Map<string, string[]> {
  const seen = new Map<string, string[]>([[start, [start]]]);
  const queue = [start];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const next of importsOf(cur)) {
      if (seen.has(next)) continue;
      seen.set(next, [...seen.get(cur)!, next]);
      queue.push(next);
    }
  }
  return seen;
}

const REGISTERS = /\b(?:internalQuery|internalMutation|query|mutation)\s*\(\s*\{/;
const registering = [...files.keys()].filter(
  (p) => p.startsWith('convex/') && REGISTERS.test(stripComments(files.get(p)!)),
);

describe('HPKE code never reaches a query or mutation', () => {
  test('the scan sees the code it guards', () => {
    for (const s of SENSITIVE) expect(files.has(s), s).toBe(true);
    expect(registering.length).toBeGreaterThan(100);
    // Positive control: the HTTP router does reach the seal/open helpers.
    expect(reach('convex/http.ts').has('convex/lib/hpkeServer.ts')).toBe(true);
    expect(reach('convex/lib/hpke.ts').has('src/shared/crypto/channel.ts')).toBe(true);
  });

  test('no query/mutation module imports seal, open, keygen or signing code', () => {
    const violations: string[] = [];
    for (const file of registering) {
      const reached = reach(file);
      for (const s of SENSITIVE) {
        const chain = reached.get(s);
        if (chain) violations.push(chain.join(' -> '));
      }
    }
    expect(violations).toEqual([]);
  });
});
