// @vitest-environment node
/// <reference types="vite/client" />
/**
 * The raw Convex surface stays closed.
 *
 * The deploy port (:3210) serves every PUBLIC Convex function to anyone who can
 * reach it, with no rate limit and no auth. FCP keeps exactly one public
 * function, `publicConfig.get`; everything else is internal and only reachable
 * through the HTTP router, where auth, scopes, PoP and rate limits live. This
 * file makes a second public function a failing build, and keeps the public
 * function's declared return shape in step with the client contract.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import type { GenericValidator } from 'convex/values';
import type { z } from 'zod';
import { PublicConfig } from '../src/shared/contracts/auth';
import { api } from './_generated/api';
import schema from './schema';
import { publicConfigReturns } from './lib/publicConfigReturns';

const ROOT = fileURLToPath(new URL('.', import.meta.url));

/** The only public functions allowed, as `file:export`. */
const ALLOWED_PUBLIC = new Set(['publicConfig:get']);

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name === '_generated' || name === 'node_modules') continue;
      out.push(...sourceFiles(full));
    } else if (/\.ts$/.test(name) && !/\.test\.ts$/.test(name) && !name.endsWith('.d.ts')) {
      out.push(full);
    }
  }
  return out;
}

describe('public Convex functions', () => {
  test('only publicConfig.ts imports a public function builder', () => {
    const offenders: string[] = [];
    for (const file of sourceFiles(ROOT)) {
      const src = readFileSync(file, 'utf8');
      const rel = relative(ROOT, file);
      // Builders from the generated server module, or the generic ones from convex/server.
      const imports = [
        ...src.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"][./]*_generated\/server['"]/g),
        ...src.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"]convex\/server['"]/g),
      ];
      for (const m of imports) {
        const names = m[1]
          .split(',')
          .map((s) =>
            s
              .trim()
              .replace(/^type\s+/, '')
              .split(/\s+as\s+/)[0]
              .trim(),
          )
          .filter(Boolean);
        for (const n of names) {
          if (!/^(query|mutation|action|queryGeneric|mutationGeneric|actionGeneric)$/.test(n))
            continue;
          if (rel === 'publicConfig.ts' && n === 'query') continue;
          offenders.push(`${rel}: ${n}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  test('the only registered public function is publicConfig.get', async () => {
    const modules = import.meta.glob(['./**/*.ts', '!./**/*.test.ts', '!./_generated/**']);
    const publicFns: string[] = [];
    for (const [path, load] of Object.entries(modules)) {
      const mod = (await load()) as Record<string, unknown>;
      const file = path.replace(/^\.\//, '').replace(/\.ts$/, '');
      for (const [name, value] of Object.entries(mod)) {
        if (value && typeof value === 'function' && (value as { isPublic?: boolean }).isPublic) {
          publicFns.push(`${file}:${name}`);
        }
      }
    }
    expect(publicFns.sort()).toEqual([...ALLOWED_PUBLIC].sort());
  }, 120_000);
});

// ---------------------------------------------------------------------------
// publicConfig.get: the Convex `returns` validator and the zod contract agree.

type Shape =
  | { kind: 'object'; fields: Record<string, Shape> }
  | { kind: 'array'; element: Shape }
  | { kind: 'leaf' };

/** Object/array structure of a Convex validator (unions collapse to their object member). */
function convexShape(val: GenericValidator): Shape {
  const vv = val as unknown as {
    kind: string;
    fields?: Record<string, GenericValidator>;
    element?: GenericValidator;
    members?: GenericValidator[];
  };
  if (vv.kind === 'object' && vv.fields) {
    return {
      kind: 'object',
      fields: Object.fromEntries(Object.entries(vv.fields).map(([k, f]) => [k, convexShape(f)])),
    };
  }
  if (vv.kind === 'array' && vv.element) return { kind: 'array', element: convexShape(vv.element) };
  if (vv.kind === 'union' && vv.members) {
    const structured = vv.members.map(convexShape).find((s) => s.kind !== 'leaf');
    if (structured) return structured;
  }
  return { kind: 'leaf' };
}

/** The same structure for a zod v4 schema, unwrapping optional/default/nullable. */
function zodShape(schema: z.ZodType): Shape {
  let def = (schema as unknown as { _zod: { def: Record<string, unknown> } })._zod.def;
  while (['optional', 'default', 'nullable', 'prefault', 'readonly'].includes(def.type as string)) {
    def = (def.innerType as { _zod: { def: Record<string, unknown> } })._zod.def;
  }
  if (def.type === 'object') {
    const shape = def.shape as Record<string, z.ZodType>;
    return {
      kind: 'object',
      fields: Object.fromEntries(Object.entries(shape).map(([k, f]) => [k, zodShape(f)])),
    };
  }
  if (def.type === 'array') return { kind: 'array', element: zodShape(def.element as z.ZodType) };
  return { kind: 'leaf' };
}

function diff(a: Shape, b: Shape, path: string, out: string[]) {
  if (a.kind !== b.kind) {
    out.push(`${path || '<root>'}: returns is ${a.kind}, contract is ${b.kind}`);
    return;
  }
  if (a.kind === 'array' && b.kind === 'array') diff(a.element, b.element, `${path}[]`, out);
  if (a.kind === 'object' && b.kind === 'object') {
    for (const k of Object.keys(a.fields)) {
      if (!(k in b.fields)) out.push(`${path}.${k}: in returns, missing from the contract`);
      else diff(a.fields[k], b.fields[k], `${path}.${k}`, out);
    }
    for (const k of Object.keys(b.fields)) {
      if (!(k in a.fields)) out.push(`${path}.${k}: in the contract, missing from returns`);
    }
  }
}

describe('publicConfig.get return shape', () => {
  test('the returns validator and the PublicConfig contract name the same fields', () => {
    const out: string[] = [];
    diff(convexShape(publicConfigReturns), zodShape(PublicConfig), '', out);
    expect(out).toEqual([]);
  });

  test('the comparison really walks nested objects', () => {
    const shape = convexShape(publicConfigReturns);
    expect(shape.kind).toBe('object');
    const site = shape.kind === 'object' ? shape.fields.site : undefined;
    expect(site?.kind === 'object' && 'homeImage' in site.fields).toBe(true);
  });
});

describe('publicConfig.get with stored data', () => {
  test('answers when settings and rows carry more than the projection names', async () => {
    const t = convexTest(schema, import.meta.glob('./**/*.*s'));
    await t.run(async (ctx) => {
      // A free JSON setting with a key the projection does not ship.
      await ctx.db.insert('appSettings', {
        key: 'subscription.backend_labels',
        value: JSON.stringify({ remnawave: 'Xray', outline: 'Outline', legacy: 'x' }),
        updatedAt: Date.now(),
      });
      // A stored card feature whose preset the current list no longer names.
      await ctx.db.insert('tiers', {
        slug: 'member',
        name: 'Member',
        backend: 'remnawave',
        monthlyTrafficGb: 0,
        deviceLimit: 0,
        hwidLimit: 0,
        hwidEnabled: false,
        trafficStrategy: 'MONTH',
        isDefaultFree: false,
        isActive: true,
        priority: 10,
        expirationDaysAfterMembershipLapse: 0,
        features: [{ preset: 'retiredPreset', iconId: 'check', label: null }],
        updatedAt: Date.now(),
      });
    });
    const cfg = await t.query(api.publicConfig.get, {});
    expect(cfg.backends.labels).toEqual({ remnawave: 'Xray', outline: 'Outline' });
    expect(cfg.tiers[0].features[0].preset).toBe('retiredPreset');
  });
});
