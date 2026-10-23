import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { EDGE_PROVIDER_IDS } from '../../edgeProviderIds';
import { canonicalJson } from './template';
import {
  EDGE_CERTIFICATE_OPTIONS,
  EDGE_TEMPLATES,
  certificateKeysOf,
  checkBuiltParams,
  contextProblems,
  durationMs,
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
  // Its first schema (added with every option optional): pinned from the start.
  cloudfront: 'cc4939d2bf8fe80e',
};

type Node = {
  type?: string;
  properties?: Record<string, Node>;
  anyOf?: Node[];
  additionalProperties?: unknown;
};

/** Every value-bearing path of a schema: objects are walked, maps and lists are leaves. */
function leafPaths(schema: z.ZodType): string[] {
  const root = z.toJSONSchema(schema, { io: 'input', unrepresentable: 'any' }) as Node;
  const out: string[] = [];
  const walk = (n: Node, prefix: string) => {
    for (const [k, child0] of Object.entries(n.properties ?? {})) {
      let child = child0;
      while (child.anyOf) child = child.anyOf.find((x) => x.type !== 'null') ?? {};
      const key = prefix ? `${prefix}.${k}` : k;
      if (child.type === 'object' && child.properties && !child.additionalProperties)
        walk(child, key);
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

  it.each(EDGE_PROVIDER_IDS)(
    '%s: every option has a label, a group, a kind that fits and a default',
    (p) => {
      for (const f of optionFieldsOf(p)) {
        expect(f.label.length, f.key).toBeGreaterThan(0);
        expect(f.label, f.key).not.toMatch(/\u2014/);
        expect(f.help ?? '', f.key).not.toMatch(/\u2014/);
        if (certificateKeysOf(p).includes(f.key)) expect(f.kind, f.key).toBe('certificate');
        else expect(f.kind ?? 'tuning', f.key).toBe('tuning');
        if (f.type === 'select') expect(f.options?.length, f.key).toBeGreaterThan(0);
      }
    },
  );
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
    expect(validateAccountOptionDefaults('fastly', { certificateAuthority: 'globalsign' })).toEqual(
      {
        ok: true,
        values: { certificateAuthority: 'globalsign' },
      },
    );
  });

  it('never lets a template hold a certificate option', () => {
    const r = validateTemplateWrite('fastly', { certificateAuthority: 'globalsign' });
    expect(r.ok).toBe(false);
    expect(validateTemplateWrite('fastly', {}).ok).toBe(true);
  });

  it('checks the params a pick builds as a whole', () => {
    expect(checkBuiltParams('gcore', EDGE_TEMPLATES.gcore.defaults).ok).toBe(true);
    expect(
      checkBuiltParams('gcore', { ...EDGE_TEMPLATES.gcore.defaults, ipFamily: 'ipv6' }).ok,
    ).toBe(false);
  });
});

describe('provider rules on writes', () => {
  const issues = (p: Parameters<typeof validateTemplateWrite>[0], params: unknown) => {
    const r = validateTemplateWrite(p, params);
    return r.ok ? [] : r.issues;
  };

  it('Fastly refuses a lowest TLS version above the highest, and keepalive timings without keepalive', () => {
    expect(issues('fastly', { minTlsVersion: '1.3', maxTlsVersion: '1.2' })).toEqual([
      'Lowest TLS version to the node: must not be above Highest TLS version to the node (1.2)',
    ]);
    expect(issues('fastly', { minTlsVersion: '1.2', maxTlsVersion: '1.3' })).toEqual([]);
    expect(issues('fastly', { tcpKeepaliveTime: 60 })).toHaveLength(1);
    expect(issues('fastly', { tcpKeepalive: false, tcpKeepaliveProbes: 3 })[0]).toMatch(
      /only with .* on$/,
    );
    expect(issues('fastly', { tcpKeepalive: true, tcpKeepaliveTime: 60 })).toEqual([]);
  });

  it('a check timeout must stay below its interval (Gcore, OVH)', () => {
    expect(
      issues('gcore', {
        healthMonitor: { delay: 5, timeout: 5, maxRetries: 3, maxRetriesDown: 3 },
      }),
    ).toEqual(['Check timeout: must be below the check interval']);
    expect(
      issues('ovh', { flavorId: 'f', healthMonitor: { delay: 3, timeout: 4, maxRetries: 3 } }),
    ).toHaveLength(1);
    expect(issues('ovh', { flavorId: 'f' })).toEqual([]);
  });

  it('OVH takes IPv4 ranges only; an IPv4-only Gcore edge too', () => {
    expect(
      issues('ovh', { flavorId: 'f', allowedCidrs: ['192.0.2.0/24', '2001:db8::/32'] }),
    ).toEqual(['Allowed client ranges: "2001:db8::/32" is not an IPv4 range, like 192.0.2.0/24']);
    expect(issues('gcore', { ipFamily: 'ipv4', allowedCidrs: ['2001:db8::/32'] })).toHaveLength(1);
    expect(issues('gcore', { ipFamily: 'dual', allowedCidrs: ['2001:db8::/32'] })).toEqual([]);
  });

  it('a range written from an address inside it is refused with the range to write (Gcore, OVH)', () => {
    // Gcore answered such a range with a bare `400 validation-error`.
    expect(
      issues('gcore', { allowedCidrs: ['192.0.2.10/24', '2001:db8::1/64', '198.51.100.0/24'] }),
    ).toEqual([
      'Allowed client ranges: "192.0.2.10/24" starts inside its range: write it as 192.0.2.0/24',
      'Allowed client ranges: "2001:db8::1/64" starts inside its range: write it as 2001:db8::/64',
    ]);
    expect(issues('ovh', { flavorId: 'f', allowedCidrs: ['203.0.113.7/30'] })).toEqual([
      'Allowed client ranges: "203.0.113.7/30" starts inside its range: write it as 203.0.113.4/30',
    ]);
    // A single address (/32, /128) is its own range; what is no range at all says so.
    expect(issues('gcore', { allowedCidrs: ['192.0.2.10/32', '2001:db8::1/128'] })).toEqual([]);
    expect(issues('gcore', { allowedCidrs: ['192.0.2.0/33', 'office'] })).toEqual([
      'Allowed client ranges: "192.0.2.0/33" is not an address range, like 192.0.2.0/24',
      'Allowed client ranges: "office" is not an address range, like 192.0.2.0/24',
    ]);
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
        healthCheck: {
          checkDelay: '5s',
          checkTimeout: '3s',
          checkMaxRetries: 3,
          transientCheckDelay: '0.5s',
        },
      }),
    ).toEqual([]);
  });

  it('a stored duration converts to whole milliseconds, exactly', () => {
    expect(durationMs('5s')).toBe(5000);
    expect(durationMs('600s')).toBe(600_000);
    expect(durationMs('2.5s')).toBe(2500);
    expect(durationMs('0.1s')).toBe(100);
    expect(durationMs('0.001s')).toBe(1);
    expect(durationMs('250ms')).toBe(250);
    expect(durationMs('1.5m')).toBe(90_000);
    expect(durationMs('0.25h')).toBe(900_000);
    // Not a whole number of milliseconds, or no duration at all.
    expect(durationMs('1.5ms')).toBeNull();
    for (const bad of ['5', 's', '5 s', '-5s', '0.0005s', '5sec', ''])
      expect(durationMs(bad)).toBeNull();
  });
});

describe('what a place cannot do (contextProblems)', () => {
  it('an HTTP check in front of a REALITY port is refused; TCP and other transports are not', () => {
    const http = { healthMonitor: { type: 'HTTP', delay: 5, timeout: 3, maxRetries: 3 } };
    expect(contextProblems('gcore', http, { realityL4: true })[0]).toMatch(/REALITY/);
    expect(
      contextProblems('ovh', { healthMonitor: { type: 'https' } }, { realityL4: true }),
    ).toHaveLength(1);
    expect(
      contextProblems('gcore', { healthMonitor: { type: 'TCP' } }, { realityL4: true }),
    ).toEqual([]);
    expect(contextProblems('gcore', http, { realityL4: false })).toEqual([]);
  });

  it('record tags and per-record flattening are refused on a Free zone only', () => {
    expect(
      contextProblems('cloudflare', { recordTags: { team: 'edge' } }, { zonePlan: 'free' })[0],
    ).toMatch(/Free plan/);
    expect(
      contextProblems(
        'fastly',
        { dnsTags: { team: 'edge' }, dnsFlatten: true },
        { zonePlan: 'free' },
      ),
    ).toHaveLength(2);
    expect(
      contextProblems(
        'fastly',
        { dnsTags: { team: 'edge' }, dnsFlatten: true },
        { zonePlan: 'pro' },
      ),
    ).toEqual([]);
    // Unknown (never tested): not refused here; the provider answers for itself.
    expect(contextProblems('fastly', { dnsFlatten: true }, {})).toEqual([]);
  });
});

describe('a pick is checked against the template it builds with', () => {
  it('a value that leans on its template passes the pick check; the built params decide', () => {
    // A timeout above the COMPILED interval, valid with a template whose interval is longer.
    expect(validatePickOptions('ovh', { healthMonitor: { timeout: 8 } }).ok).toBe(true);
    const tpl = { flavorId: 'small', healthMonitor: { delay: 10, timeout: 3, maxRetries: 3 } };
    expect(
      checkBuiltParams('ovh', { ...tpl, healthMonitor: { ...tpl.healthMonitor, timeout: 8 } }).ok,
    ).toBe(true);
    expect(
      checkBuiltParams('ovh', {
        ...tpl,
        healthMonitor: { delay: 5, timeout: 8, maxRetries: 3 },
      }).ok,
    ).toBe(false);
    // A keepalive timing with keepalive switched on by the template only.
    expect(validatePickOptions('fastly', { tcpKeepaliveTime: 60 }).ok).toBe(true);
    expect(checkBuiltParams('fastly', { tcpKeepalive: true, tcpKeepaliveTime: 60 }).ok).toBe(true);
    expect(checkBuiltParams('fastly', { tcpKeepaliveTime: 60 }).ok).toBe(false);
  });
});
