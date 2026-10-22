/**
 * CAA (RFC 8659) for the certificates an L7 front orders: whether the zone's
 * records let the account's certificate authority issue for a name. Pure and
 * isolate-safe: the lookup is passed in (the Fastly adapter resolves it over
 * DNS, tests answer from a table).
 *
 * The walk is the one a CA does: starting at the name (for a wildcard
 * `*.X`, at `X`), the FIRST name up the tree that holds any CAA record
 * decides, and nothing above it is read. No record anywhere up to the top
 * label means no restriction. Within the deciding set:
 *  - a non-wildcard name is governed by its `issue` properties;
 *  - a wildcard by its `issuewild` properties, or by `issue` when it has none;
 *  - a set with no governing property restricts nothing;
 *  - an issuer of `;` (an empty domain) allows no CA at all;
 *  - a property with the critical flag whose tag the CA does not know forbids
 *    issuance outright.
 * Tags and issuer domains compare case-insensitively. A record's parameters
 * (RFC 8657) must also be ones the issuance can meet: an `accounturi` names one
 * ACME account, which FCP never knows (the provider orders the certificate),
 * so such a record does not allow it; a `validationmethods` list must include
 * `dns-01`, the managed DNS challenge every certificate FCP orders uses.
 * Unknown parameters are ignored.
 *
 * CNAMEs: a CA's lookup of a name that is an alias follows it, as any DNS
 * lookup does, and a name with no records of its own then climbs from its
 * parent. The resolver the adapter uses does both, so a check of a name that
 * a zone wildcard (`*.zone CNAME ...`) answers for sees what the CA would.
 */

/** The issuer domain each certificate authority FCP orders from is named by in CAA. */
export const CA_CAA_DOMAINS = {
  certainly: 'certainly.com',
  'lets-encrypt': 'letsencrypt.org',
  globalsign: 'globalsign.com',
  // Amazon's CA (ACM certificates, a CloudFront front's): the first of the four below.
  amazon: 'amazon.com',
} as const;
export type CaaCertificateAuthority = keyof typeof CA_CAA_DOMAINS;

/**
 * Further issuer domains a CA answers to: a record naming any of them allows
 * it. ACM issues under any of `amazon.com`, `amazontrust.com`, `awstrust.com`
 * and `amazonaws.com`.
 * Source: https://docs.aws.amazon.com/acm/latest/userguide/setup.md (CAA), 2026-10-22.
 */
export const CA_CAA_ALIASES: Partial<Record<CaaCertificateAuthority, readonly string[]>> = {
  amazon: ['amazontrust.com', 'awstrust.com', 'amazonaws.com'],
};

/** One CAA record as DNS returns it (flags 128 = critical). */
export interface CaaRecord {
  flags: number;
  tag: string;
  value: string;
}

/**
 * The CAA records at exactly one name: `[]` when the name has none (no data,
 * or the name does not exist); a throw when the answer could not be had
 * (timeout, server failure).
 */
export type CaaLookup = (name: string) => Promise<CaaRecord[]>;

export type CaaVerdictKind = 'allows' | 'no_records' | 'forbids' | 'unchecked';

export interface CaaVerdict {
  verdict: CaaVerdictKind;
  /** The issuer domain the CA needs (`certainly.com`). */
  issuer: string;
  wildcard: boolean;
  /** The name whose records decided (absent for `no_records` and `unchecked`). */
  decidedAt?: string;
}

/** The tags RFC 8659 and its registry define; a critical property with any other tag forbids issuance. */
const KNOWN_TAGS = new Set([
  'issue',
  'issuewild',
  'iodef',
  'issuemail',
  'contactemail',
  'contactphone',
]);

/**
 * Never more than this many names are looked up for one verdict. A name with
 * more labels than this is `unchecked`, never `no_records`: the records that
 * decide could sit above the cut.
 */
export const MAX_CAA_WALK = 16;

function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, '');
}

/** `a.b.example.org` -> `[a.b.example.org, b.example.org, example.org, org]` (the root is never asked). */
export function caaWalkNames(name: string): string[] {
  const labels = normalizeName(name).split('.').filter(Boolean);
  return labels.map((_, i) => labels.slice(i).join('.'));
}

/** The issuer domain of an `issue` / `issuewild` value (`;` alone = none). */
export function caaIssuerOf(value: string): string {
  return value.split(';')[0]!.trim().toLowerCase().replace(/\.$/, '');
}

/** The `key=value` parameters after the issuer domain, keys lowercased. */
export function caaParamsOf(value: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of value.split(';').slice(1)) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    out.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim());
  }
  return out;
}

/**
 * Whether a record that names the right issuer can be met by the issuance FCP
 * asks for: no account binding (the provider's ACME account is not FCP's to
 * name), and DNS validation among the methods it allows, when it lists any.
 */
export function caaParamsAllow(value: string): boolean {
  const params = caaParamsOf(value);
  if (params.has('accounturi')) return false;
  const methods = params.get('validationmethods');
  if (methods === undefined) return true;
  return methods
    .split(',')
    .map((m) => m.trim().toLowerCase())
    .includes('dns-01');
}

/**
 * Whether the deciding record set lets `issuer` issue (any one of them, for a
 * CA that answers to several domains). `records` is the set at ONE name (the
 * first one up the tree that has any).
 */
export function caaSetAllows(
  records: readonly CaaRecord[],
  issuer: string | readonly string[],
  wildcard: boolean,
): boolean {
  const tagOf = (r: CaaRecord) => r.tag.trim().toLowerCase();
  if (records.some((r) => (r.flags & 128) !== 0 && !KNOWN_TAGS.has(tagOf(r)))) return false;
  const wild = records.filter((r) => tagOf(r) === 'issuewild');
  const governing =
    wildcard && wild.length > 0 ? wild : records.filter((r) => tagOf(r) === 'issue');
  if (governing.length === 0) return true;
  const want = new Set(
    (typeof issuer === 'string' ? [issuer] : issuer).map((i) => i.toLowerCase()),
  );
  return governing.some((r) => want.has(caaIssuerOf(r.value)) && caaParamsAllow(r.value));
}

/**
 * The name a check for one front under `zone` starts at: a label no front and
 * no service uses, so whatever answers for it (a zone wildcard, typically) is
 * what will answer for a new front's name before FCP writes its own record.
 */
export function caaProbeName(zone: string): string {
  return `_fcp-caa-check.${normalizeName(zone)}`;
}

/**
 * The verdict for one certificate: `name` is the name ordered (`*.X` for a
 * wildcard; the walk then starts at `X`). A lookup that fails anywhere on the
 * way is `unchecked`, never a guess either way.
 */
export async function checkCaa(a: {
  name: string;
  certificateAuthority: string;
  lookup: CaaLookup;
}): Promise<CaaVerdict> {
  const wildcard = a.name.trim().startsWith('*.');
  const base = wildcard ? a.name.trim().slice(2) : a.name;
  const issuer =
    CA_CAA_DOMAINS[a.certificateAuthority as CaaCertificateAuthority] ?? a.certificateAuthority;
  const issuers = [
    issuer,
    ...(CA_CAA_ALIASES[a.certificateAuthority as CaaCertificateAuthority] ?? []),
  ];
  const names = caaWalkNames(base);
  // Too deep to walk to the top: an answer from part of the tree is no answer.
  if (names.length > MAX_CAA_WALK) return { verdict: 'unchecked', issuer, wildcard };
  for (const name of names) {
    let records: CaaRecord[];
    try {
      records = await a.lookup(name);
    } catch {
      return { verdict: 'unchecked', issuer, wildcard };
    }
    if (records.length === 0) continue;
    return {
      verdict: caaSetAllows(records, issuers, wildcard) ? 'allows' : 'forbids',
      issuer,
      wildcard,
      decidedAt: name,
    };
  }
  return { verdict: 'no_records', issuer, wildcard };
}

/** `*.<parent of hostname>`: the one wildcard that covers a first-level front name. */
export function wildcardNameFor(hostname: string): string {
  const h = normalizeName(hostname);
  const dot = h.indexOf('.');
  return `*.${dot === -1 ? h : h.slice(dot + 1)}`;
}

/** `*.example.org` -> `example.org` (a name without the wildcard label is returned as is). */
export function wildcardBase(name: string): string {
  const n = normalizeName(name);
  return n.startsWith('*.') ? n.slice(2) : n;
}
