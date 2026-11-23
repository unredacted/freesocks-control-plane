// @vitest-environment node
/**
 * The npm packages that run inside the Convex backend, each with a reason.
 *
 * Convex gives no isolation between a function and the deployment's secrets:
 * every function, in the V8 isolate and in the `"use node"` executor alike, can
 * read every deployment env var (SESSION_SIGNING_KEY, ACCOUNT_ID_PEPPER, the
 * HPKE and manifest keys, backend tokens) and call every internal function. A
 * compromised dependency is therefore a compromised deployment. This list is
 * the review point: adding a package to the backend bundle fails this test until
 * it is added here with what it does and why a hand-written client would not
 * do (docs/convex-security.md, "Runtime dependencies").
 *
 * The set is computed from source: every non-test file under convex/ (the
 * Convex CLI bundles each one as an entry point) plus every local file they
 * import, including src/shared.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, normalize, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';

const CONVEX = fileURLToPath(new URL('.', import.meta.url));
const REPO = join(CONVEX, '..');

/** package → why it is in the backend. Keep reasons short and concrete. */
const RUNTIME_PACKAGES: Record<string, string> = {
  convex: 'the Convex runtime itself',
  zod: 'request validation shared with the client contracts',
  yaml: 'Clash/Mihomo subscription bodies (parse + render)',
  '@noble/curves': 'audited curve math (x25519, ed25519) for keys and digests',
  '@noble/hashes': 'audited hashes (blake3) for VLESS Encryption material',
  '@noble/post-quantum': 'ML-KEM-768 for VLESS Encryption',
  '@hpke/core': 'HPKE request sealing (CDN blinding), shared with the client',
  '@hpke/chacha20poly1305': 'HPKE AEAD, shared with the client',
  '@hpke/hybridkem-x-wing': 'HPKE post-quantum KEM, shared with the client',
  '@simplewebauthn/server': 'WebAuthn verification for admin and member passkeys',
  '@aws-sdk/client-s3': 'S3-compatible subscription mirrors (SigV4 signing)',
  '@aws-sdk/client-cloudfront': 'CloudFront edge provider adapter',
  '@aws-sdk/client-acm': 'CloudFront certificates (ACM)',
  '@scaleway/sdk-client': 'Scaleway load-balancer edge provider adapter',
  '@scaleway/sdk-lb': 'Scaleway load-balancer edge provider adapter',
  cloudflare: 'Cloudflare DNS and fronting adapter',
  fastly: 'Fastly edge provider adapter',
  'tencentcloud-sdk-nodejs-teo': 'EdgeOne edge provider adapter (TC3 signing)',
  globalping: 'Globalping probe measurements',
  tldts: 'registrable-domain parsing for country lists and SNI hunting',
  'naughty-words': 'filters generated edge address names',
  'wordlist-english': 'word source for generated edge address names',
  // Test helpers under convex/lib/edges/testing/ (bundled as entry points by the
  // CLI's every-file rule, never called by a deployed function).
  vitest: 'test helpers only (convex/lib/edges/testing/)',
  'convex-test': 'test helpers only (convex/lib/edges/testing/)',
};

function entryFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name !== '_generated' && name !== 'node_modules') out.push(...entryFiles(full));
    } else if (name.endsWith('.ts') && !name.endsWith('.test.ts') && !name.endsWith('.d.ts')) {
      out.push(full);
    }
  }
  return out;
}

const IMPORT =
  /(?:^|\n)\s*(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)|(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g;

function resolveLocal(from: string, spec: string): string | null {
  const p = normalize(join(dirname(from), spec));
  const candidates = [
    p,
    `${p}.ts`,
    p.endsWith('.js') ? `${p.slice(0, -3)}.ts` : '',
    join(p, 'index.ts'),
  ];
  for (const c of candidates) {
    if (c && c.endsWith('.ts') && existsSync(c) && statSync(c).isFile()) return c;
  }
  return null;
}

function bundledPackages(): Map<string, Set<string>> {
  const seen = new Set<string>();
  const packages = new Map<string, Set<string>>();
  const queue = entryFiles(CONVEX);
  while (queue.length) {
    const file = queue.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const src = readFileSync(file, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:])\/\/.*$/gm, '$1');
    for (const m of src.matchAll(IMPORT)) {
      const spec = m[1] ?? m[2] ?? m[3];
      if (spec.startsWith('.')) {
        const local = resolveLocal(file, spec);
        if (local) queue.push(local);
        continue;
      }
      if (spec.startsWith('node:') || spec.startsWith('cloudflare:')) continue;
      const parts = spec.split('/');
      const name = spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
      if (!packages.has(name)) packages.set(name, new Set());
      packages.get(name)!.add(relative(REPO, file));
    }
  }
  return packages;
}

describe('backend runtime dependencies', () => {
  const found = bundledPackages();

  test('every package bundled into the backend is listed with a reason', () => {
    const unlisted = [...found.keys()]
      .filter((p) => !(p in RUNTIME_PACKAGES))
      .map((p) => `${p} (from ${[...found.get(p)!].slice(0, 2).join(', ')})`);
    expect(unlisted).toEqual([]);
  });

  test('the list has no stale entries', () => {
    expect(Object.keys(RUNTIME_PACKAGES).filter((p) => !found.has(p))).toEqual([]);
  });

  test('the scan sees the code it should', () => {
    expect(found.get('convex')?.size ?? 0).toBeGreaterThan(100);
    // Through a relative import into src/shared, not a convex/ file directly.
    expect([...(found.get('@hpke/core') ?? [])].some((f) => f.startsWith('src/shared/'))).toBe(
      true,
    );
  });
});
