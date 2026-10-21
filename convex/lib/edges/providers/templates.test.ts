import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { EDGE_PROVIDER_IDS } from '../../edgeProviderIds';
import { canonicalJson } from './template';
import {
  EDGE_CERTIFICATE_OPTIONS,
  EDGE_TEMPLATES,
  certificateKeysOf,
  checkBuiltParams,
  optionFieldsOf,
  validateAccountOptionDefaults,
  validatePickOptions,
  validateTemplateWrite,
} from './templates';

function fnv(input: string): string {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < input.length; i++) {
    h ^= BigInt(input.charCodeAt(i));
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

/**
 * The hash of every provider's EMPTY template as it was before provider
 * options existed. An option added with a zod `.default()` would change these
 * (and with them every location's trust and every in-flight provision on
 * deploy): new options are `.optional()` with a declared default instead.
 */
const EMPTY_TEMPLATE_HASHES: Record<string, string> = {
  gcore: '214b63b3f4963bef',
  upcloud: '0d4874953e0e4148',
  scaleway: '5bbc3c789ab58527',
  ovh: '924d8c407f90e7a4',
  cloudflare: '8c7bb1602794a08e',
  fastly: '5cfb164e8072eb8e',
};

type Node = { type?: string; properties?: Record<string, Node>; anyOf?: Node[]; additionalProperties?: unknown };

/** Every value-bearing path of a schema: objects are walked, maps and lists are leaves. */
function leafPaths(schema: z.ZodType): string[] {
  const root = z.toJSONSchema(schema, { io: 'input', unrepresentable: 'any' }) as Node;
  const out: string[] = [];
  const walk = (n: Node, prefix: string) => {
    for (const [k, child0] of Object.entries(n.properties ?? {})) {
      let child = child0;
      while (child.anyOf) child = child.anyOf.find((x) => x.type !== 'null') ?? {};
      const key = prefix ? `${prefix}.${k}` : k;
      if (child.type === 'object' && child.properties && !child.additionalProperties) walk(child, key);
      else out.push(key);
    }
  };
  walk(root, '');
  return out;
}

describe('provider option registry', () => {
  it.each(EDGE_PROVIDER_IDS)('%s: the empty template hashes as it did before options', (p) => {
    expect(fnv(canonicalJson(EDGE_TEMPLATES[p].schema.parse({})))).toBe(EMPTY_TEMPLATE_HASHES[p]);
  });

  it.each(EDGE_PROVIDER_IDS)('%s: every schema value has exactly one described option', (p) => {
    const tuning = leafPaths(EDGE_TEMPLATES[p].schema).sort();
    expect(EDGE_TEMPLATES[p].fields.map((f) => f.key).sort()).toEqual(tuning);
    const cert = leafPaths(EDGE_CERTIFICATE_OPTIONS[p].schema).sort();
    expect(certificateKeysOf(p).sort()).toEqual(cert);
    const keys = optionFieldsOf(p).map((f) => f.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it.each(EDGE_PROVIDER_IDS)('%s: every option has a label, a group, a kind that fits and a default', (p) => {
    for (const f of optionFieldsOf(p)) {
      expect(f.label.length, f.key).toBeGreaterThan(0);
      expect(f.label, f.key).not.toMatch(/—/);
      expect(f.help ?? '', f.key).not.toMatch(/—/);
      if (certificateKeysOf(p).includes(f.key)) expect(f.kind, f.key).toBe('certificate');
      else expect(f.kind ?? 'tuning', f.key).toBe('tuning');
      if (f.type === 'select') expect(f.options?.length, f.key).toBeGreaterThan(0);
    }
  });
});

describe('validation by level', () => {
  it('takes any option for one node and returns only what was chosen', () => {
    const r = validatePickOptions('fastly', { certificateAuthority: 'lets-encrypt' });
    expect(r).toEqual({ ok: true, values: { certificateAuthority: 'lets-encrypt' } });
    const t = validatePickOptions('gcore', { healthMonitor: { delay: 20 } });
    expect(t).toEqual({ ok: true, values: { healthMonitor: { delay: 20 } } });
    expect(validatePickOptions('gcore', undefined)).toEqual({ ok: true, values: {} });
  });

  it('refuses an unknown key, a bad value and a key the level does not take', () => {
    expect(validatePickOptions('gcore', { nope: 1 })).toMatchObject({
      ok: false,
      code: 'edge.option_unknown',
    });
    expect(validatePickOptions('fastly', { certificateAuthority: 'acme' })).toMatchObject({
      ok: false,
      code: 'edge.option_invalid',
    });
    expect(validateAccountOptionDefaults('gcore', { flavor: 'x' })).toMatchObject({
      ok: false,
      code: 'edge.option_not_here',
    });
    expect(validateAccountOptionDefaults('fastly', { certificateAuthority: 'globalsign' })).toEqual({
      ok: true,
      values: { certificateAuthority: 'globalsign' },
    });
  });

  it('never lets a template hold a certificate option', () => {
    const r = validateTemplateWrite('fastly', { certificateAuthority: 'globalsign' });
    expect(r.ok).toBe(false);
    expect(validateTemplateWrite('fastly', {}).ok).toBe(true);
  });

  it('checks the params a pick builds as a whole', () => {
    expect(checkBuiltParams('gcore', EDGE_TEMPLATES.gcore.defaults).ok).toBe(true);
    expect(checkBuiltParams('gcore', { ...EDGE_TEMPLATES.gcore.defaults, ipFamily: 'ipv6' }).ok).toBe(
      false,
    );
  });
});

describe('provider rules on writes', () => {
  const issues = (p: Parameters<typeof validateTemplateWrite>[0], params: unknown) => {
    const r = validateTemplateWrite(p, params);
    return r.ok ? [] : r.issues;
  };

  it('a check timeout must stay below its interval (Gcore, OVH)', () => {
    expect(issues('gcore', { healthMonitor: { delay: 5, timeout: 5, maxRetries: 3, maxRetriesDown: 3 } })).toEqual([
      'Check timeout: must be below the check interval',
    ]);
    expect(issues('ovh', { flavorId: 'f', healthMonitor: { delay: 3, timeout: 4, maxRetries: 3 } })).toHaveLength(1);
    expect(issues('ovh', { flavorId: 'f' })).toEqual([]);
  });

  it('OVH takes IPv4 ranges only; an IPv4-only Gcore edge too', () => {
    expect(issues('ovh', { flavorId: 'f', allowedCidrs: ['192.0.2.0/24', '2001:db8::/32'] })).toEqual([
      'Allowed client ranges: "2001:db8::/32" is not an IPv4 range',
    ]);
    expect(issues('gcore', { ipFamily: 'ipv4', allowedCidrs: ['2001:db8::/32'] })).toHaveLength(1);
    expect(issues('gcore', { ipFamily: 'dual', allowedCidrs: ['2001:db8::/32'] })).toEqual([]);
  });

  it('tag and label shapes the providers refuse are refused on save', () => {
    expect(issues('gcore', { tags: { 'a b': 'x', ok: '' } })).toHaveLength(2);
    expect(issues('upcloud', { labels: [{ key: '_x', value: 'v' }] })).toHaveLength(1);
    expect(issues('upcloud', { labels: [{ key: 'team', value: 'edge' }] })).toEqual([]);
  });

  it('Scaleway durations are written in seconds, decimals allowed', () => {
    expect(issues('scaleway', { timeoutClient: '10m' })).toHaveLength(1);
    expect(
      issues('scaleway', {
        timeoutClient: '600s',
        healthCheck: { checkDelay: '5s', checkTimeout: '3s', checkMaxRetries: 3, transientCheckDelay: '0.5s' },
      }),
    ).toEqual([]);
  });
});

