'use node';
/**
 * A GET that connects only to addresses it checked (docs/edges.md "Country
 * lists"; Node only, imported by "use node" actions). A list's source is an
 * address an operator typed, so FCP must not be talked into reaching its own
 * network through it:
 *
 *  - the host is resolved ONCE, and every answer must be public;
 *  - the connection's lookup hands back only those checked answers, for a
 *    single address and for the list a dual-stack connect asks for, so no
 *    second resolution (a rebinding answer, a fallback) reaches a socket;
 *  - the request keeps the name: the Host header, the SNI and the certificate
 *    check are the original host's;
 *  - https only, on 443, no redirects, a capped body, one deadline.
 */
import { request as httpsRequest } from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import { addressFamily, isPublicIpLiteral } from '../ip';

export type PinnedFetchError =
  | 'bad_url'
  | 'dns_failed'
  | 'private_address'
  | 'redirect_refused'
  | 'not_found'
  | 'http_error'
  | 'too_large'
  | 'timeout'
  | 'tls_failed'
  | 'unreachable';

export type PinnedFetchResult =
  | { ok: true; status: 200; text: string; etag?: string; lastModified?: string }
  | { ok: true; status: 304 }
  | { ok: false; error: PinnedFetchError };

export interface Answer {
  address: string;
  family: 4 | 6;
}

export interface PinnedFetchDeps {
  resolve: (host: string) => Promise<Answer[]>;
  allowAddress: (ip: string) => boolean;
  /** Tests only: the port dialled and an extra trust anchor (production: 443 and the system store). */
  port?: number;
  ca?: string;
}

export const DEFAULT_DEPS: PinnedFetchDeps = {
  resolve: async (host) =>
    (await dnsLookup(host, { all: true, verbatim: true })).map((a) => ({
      address: a.address,
      family: a.family === 6 ? 6 : 4,
    })),
  allowAddress: isPublicIpLiteral,
};

type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | Array<{ address: string; family: number }>,
  family?: number,
) => void;

/**
 * The connection's lookup: only the checked answers, of the family asked for.
 * `all` is what a dual-stack connect (`autoSelectFamily`) asks.
 */
export function pinnedLookup(answers: readonly Answer[]) {
  return (
    _host: string,
    options: { family?: number | string; all?: boolean },
    callback: LookupCallback,
  ): void => {
    const fam = options.family === 'IPv4' ? 4 : options.family === 'IPv6' ? 6 : options.family;
    const want = fam === 4 || fam === 6 ? answers.filter((a) => a.family === fam) : [...answers];
    if (want.length === 0) {
      const err: NodeJS.ErrnoException = new Error('no checked address of that family');
      err.code = 'ENOTFOUND';
      callback(err, options.all ? [] : '', 0);
      return;
    }
    if (options.all)
      callback(
        null,
        want.map((a) => ({ address: a.address, family: a.family })),
      );
    else callback(null, want[0]!.address, want[0]!.family);
  };
}

function classify(err: NodeJS.ErrnoException): PinnedFetchError {
  const code = err.code ?? '';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'dns_failed';
  if (
    code.startsWith('ERR_TLS') ||
    code.startsWith('ERR_SSL') ||
    code.startsWith('CERT_') ||
    code.startsWith('UNABLE_TO_') ||
    code.includes('SELF_SIGNED') ||
    code === 'HOSTNAME_MISMATCH'
  )
    return 'tls_failed';
  return 'unreachable';
}

export async function pinnedFetch(
  url: string,
  opts: { etag?: string | null; lastModified?: string | null; maxBytes: number; timeoutMs: number },
  deps: PinnedFetchDeps = DEFAULT_DEPS,
): Promise<PinnedFetchResult> {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return { ok: false, error: 'bad_url' };
  }
  if (u.protocol !== 'https:' || u.username || u.password || (u.port !== '' && u.port !== '443'))
    return { ok: false, error: 'bad_url' };
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const literal = addressFamily(host);
  // One deadline for the whole fetch, the lookup included.
  const deadline = Date.now() + opts.timeoutMs;
  let answers: Answer[];
  if (literal) answers = [{ address: host, family: literal === 'v6' ? 6 : 4 }];
  else {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timedOut = new Promise<'timeout'>((r) => {
        timer = setTimeout(() => r('timeout'), opts.timeoutMs);
      });
      const r = await Promise.race([deps.resolve(host), timedOut]);
      if (r === 'timeout') return { ok: false, error: 'timeout' };
      answers = r;
    } catch {
      return { ok: false, error: 'dns_failed' };
    } finally {
      clearTimeout(timer);
    }
  }
  if (answers.length === 0) return { ok: false, error: 'dns_failed' };
  if (answers.some((a) => !deps.allowAddress(a.address)))
    return { ok: false, error: 'private_address' };

  return new Promise<PinnedFetchResult>((resolve) => {
    let settled = false;
    const done = (r: PinnedFetchResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(r);
    };
    const headers: Record<string, string> = {
      host: u.host,
      'user-agent': 'FreeSocks-Control-Plane (country lists)',
      accept: 'text/plain, */*;q=0.5',
      'accept-encoding': 'identity',
    };
    if (opts.etag) headers['if-none-match'] = opts.etag;
    if (opts.lastModified) headers['if-modified-since'] = opts.lastModified;
    const req = httpsRequest({
      method: 'GET',
      host,
      port: deps.port ?? 443,
      path: `${u.pathname}${u.search}`,
      headers,
      ...(literal ? {} : { servername: host }),
      // Node connects dual-stack by default (`autoSelectFamily`), asking with `all`.
      lookup: pinnedLookup(answers) as never,
      agent: false,
      rejectUnauthorized: true,
      ...(deps.ca ? { ca: deps.ca } : {}),
    });
    const timer = setTimeout(
      () => {
        req.destroy();
        done({ ok: false, error: 'timeout' });
      },
      Math.max(0, deadline - Date.now()),
    );
    req.on('error', (err: NodeJS.ErrnoException) => done({ ok: false, error: classify(err) }));
    req.on('response', (res) => {
      const status = res.statusCode ?? 0;
      if (status >= 300 && status < 400 && status !== 304) {
        res.destroy();
        return done({ ok: false, error: 'redirect_refused' });
      }
      if (status === 304) {
        res.resume();
        return done({ ok: true, status: 304 });
      }
      if (status === 404 || status === 410) {
        res.destroy();
        return done({ ok: false, error: 'not_found' });
      }
      if (status !== 200) {
        res.destroy();
        return done({ ok: false, error: 'http_error' });
      }
      const declared = Number(res.headers['content-length'] ?? '0');
      if (Number.isFinite(declared) && declared > opts.maxBytes) {
        res.destroy();
        return done({ ok: false, error: 'too_large' });
      }
      const parts: Buffer[] = [];
      let total = 0;
      res.on('data', (chunk: Buffer) => {
        total += chunk.length;
        if (total > opts.maxBytes) {
          res.destroy();
          done({ ok: false, error: 'too_large' });
          return;
        }
        parts.push(chunk);
      });
      res.on('error', (err: NodeJS.ErrnoException) => done({ ok: false, error: classify(err) }));
      res.on('end', () => {
        const etag = typeof res.headers.etag === 'string' ? res.headers.etag : undefined;
        const lastModified =
          typeof res.headers['last-modified'] === 'string'
            ? res.headers['last-modified']
            : undefined;
        done({
          ok: true,
          status: 200,
          text: new TextDecoder('utf-8').decode(Buffer.concat(parts)),
          ...(etag ? { etag } : {}),
          ...(lastModified ? { lastModified } : {}),
        });
      });
    });
    req.end();
  });
}
