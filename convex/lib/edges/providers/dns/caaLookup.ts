'use node';
/**
 * CAA over public DNS, as the certificate authority reads it: the lookup the
 * L7 adapters' CAA preflights pass to `lib/edges/caa.ts` (which is pure). No
 * record (no data, or a name that does not exist) is `[]` so the walk climbs;
 * anything else that fails is thrown, and the verdict is `unchecked`. The
 * offline test suite refuses these lookups like `fetch`: each adapter keeps
 * its own test seam (`__setFastlyCaaLookup`, `__setCloudflareCaaLookup`).
 */
import type { CaaRecord } from '../../caa';

/** A lookup is a few round trips; a resolver that cannot answer in this is `unchecked`. */
const CAA_TIMEOUT_MS = 4_000;

export async function dnsCaaLookup(name: string): Promise<CaaRecord[]> {
  const { Resolver } = await import('node:dns/promises');
  const resolver = new Resolver({ timeout: CAA_TIMEOUT_MS, tries: 2 });
  try {
    const rows = (await resolver.resolveCaa(name)) as unknown as Array<Record<string, unknown>>;
    return rows.map((r) => {
      // Node names the property after its tag (`{ critical: 0, issue: 'x' }`).
      const tag = Object.keys(r).find((k) => k !== 'critical') ?? '';
      const value = r[tag];
      return {
        flags: typeof r.critical === 'number' ? r.critical : 0,
        tag,
        value: typeof value === 'string' ? value : '',
      };
    });
  } catch (e) {
    const code = (e as { code?: unknown }).code;
    if (code === 'ENODATA' || code === 'ENOTFOUND') return [];
    throw e;
  }
}
