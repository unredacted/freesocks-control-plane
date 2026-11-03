/**
 * Which stored rows would hold a name (pure; unit-tested; docs/edges.md
 * "Country lists"). An exact row holds its own name. A wildcard row stored as
 * its base (`*.example.com` as `example.com`) holds every name BELOW the base
 * but not the base itself: the apex needs its own row. Both kinds may exist
 * for one base, and a lookup reports both.
 */
import { siteOf } from '../sni/hunt/sources';

export interface NameKey {
  name: string;
  wildcard: boolean;
}

/** The name itself as an exact row, then each parent down to its site as a wildcard row. */
export function matchKeys(name: string): NameKey[] {
  const out: NameKey[] = [{ name, wildcard: false }];
  const site = siteOf(name);
  let rest = name;
  while (rest !== site) {
    const dot = rest.indexOf('.');
    if (dot < 0) break;
    rest = rest.slice(dot + 1);
    out.push({ name: rest, wildcard: true });
  }
  return out;
}
