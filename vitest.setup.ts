/**
 * The offline suite reaches no network. `fetch` starts as a refusal that fails
 * the running test: a test stubs the endpoints it talks to (mockFetch /
 * routeFetch in convex/lib/edges/testing/mockFetch.ts), and
 * `vi.unstubAllGlobals()` puts this refusal back, never the real fetch.
 *
 * convex-test runs scheduled functions on timers, so a refused call can come
 * from work the failing test scheduled: stub fetch for the whole test, not
 * just the call it awaits. Work an earlier test left behind never gets here:
 * the runner (convex/lib/edges/testing/scheduledWork.runner.ts) ends it with
 * that test, under a refusal of its own.
 */
import dns from 'node:dns';
import { afterAll, afterEach } from 'vitest';

const refused: string[] = [];

function describeCall(input: RequestInfo | URL, init?: RequestInit): string {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
  let where = url;
  try {
    // Origin + path only: a query string may carry a credential.
    const u = new URL(url);
    where = `${u.origin}${u.pathname}`;
  } catch {
    // Not a URL: report it as given.
  }
  return `${method.toUpperCase()} ${where}`;
}

globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const call = describeCall(input, init);
  refused.push(call);
  // What a real fetch throws when the network is unreachable.
  throw new TypeError(`fetch failed: the offline test suite reaches no network (${call})`);
};

// CAA lookups (the Fastly credential test's issuance preflight) go to DNS, not
// fetch: they are refused the same way, and a test answers them through the
// adapter's seam (`__setFastlyCaaLookup`). Node's `dns/promises` IS
// `dns.promises`, so the class the adapter instantiates is the one patched.
const refuseCaa = async (name: string): Promise<never> => {
  refused.push(`DNS CAA ${name}`);
  throw Object.assign(
    new Error(`queryCaa ECONNREFUSED ${name}: the offline suite reaches no DNS`),
    {
      code: 'ECONNREFUSED',
    },
  );
};
dns.promises.Resolver.prototype.resolveCaa = refuseCaa as never;
dns.promises.resolveCaa = refuseCaa as never;

function report(when: string): void {
  if (refused.length === 0) return;
  const calls = refused.splice(0);
  throw new Error(
    `${when} called the real fetch (or DNS) ${calls.length} time(s): ${calls.join(', ')}. ` +
      'Stub fetch for the whole test (convex/lib/edges/testing/mockFetch.ts), work it ' +
      'scheduled included; answer CAA through the Fastly adapter seam.',
  );
}

afterEach(() => report('this test'));
afterAll(() => report('this file, after its last test,'));
