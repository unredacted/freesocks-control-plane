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
 * Tags and issuer domains compare case-insensitively; parameters after `;`
 * are ignored (FCP never sets an account URI or a validation method).
 */

/** The issuer domain each certificate authority FCP orders from is named by in CAA. */
export const CA_CAA_DOMAINS = {
  certainly: 'certainly.com',
  'lets-encrypt': 'letsencrypt.org',
  globalsign: 'globalsign.com',
} as const;
export type CaaCertificateAuthority = keyof typeof CA_CAA_DOMAINS;

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

/** Never more than this many names are looked up for one verdict. */
const MAX_WALK = 10;

function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, '');
}

/** `a.b.example.org` -> `[a.b.example.org, b.example.org, example.org, org]` (the root is never asked). */
export function caaWalkNames(name: string): string[] {
  const labels = normalizeName(name).split('.').filter(Boolean);
  const out: string[] = [];
  for (let i = 0; i < labels.length && out.length < MAX_WALK; i++)
    out.push(labels.slice(i).join('.'));
  return out;
}

/** The issuer domain of an `issue` / `issuewild` value (`;` alone = none). */
export function caaIssuerOf(value: string): string {
  return value.split(';')[0]!.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Whether the deciding record set lets `issuer` issue. `records` is the set
 * at ONE name (the first one up the tree that has any).
 */
export function caaSetAllows(
  records: readonly CaaRecord[],
  issuer: string,
  wildcard: boolean,
): boolean {
  const tagOf = (r: CaaRecord) => r.tag.trim().toLowerCase();
  if (records.some((r) => (r.flags & 128) !== 0 && !KNOWN_TAGS.has(tagOf(r)))) return false;
  const wild = records.filter((r) => tagOf(r) === 'issuewild');
  const governing =
    wildcard && wild.length > 0 ? wild : records.filter((r) => tagOf(r) === 'issue');
  if (governing.length === 0) return true;
  const want = issuer.toLowerCase();
  return governing.some((r) => caaIssuerOf(r.value) === want);
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
  for (const name of caaWalkNames(base)) {
    let records: CaaRecord[];
    try {
      records = await a.lookup(name);
    } catch {
      return { verdict: 'unchecked', issuer, wildcard };
    }
    if (records.length === 0) continue;
    return {
      verdict: caaSetAllows(records, issuer, wildcard) ? 'allows' : 'forbids',
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
