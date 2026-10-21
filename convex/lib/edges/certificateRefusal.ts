/**
 * Why a CDN front could get no certificate in a zone (docs/edges.md § "L7
 * edges", CAA preflight and Certificates). Pure, over the account and the
 * location rows: one rule for the selection, the preflight, the start guards,
 * the setup plan, the run and every pick check.
 */
import type { Doc } from '../../_generated/dataModel';
import { accountOptionDefaultsOf, certificateValuesFor } from './choices';
import { canonicalJson } from './providers/template';
import type { Values } from './providers/options';

export type CertificateRefusal =
  | 'caa_forbids_ca'
  | 'shared_certificate_failed'
  | 'shared_certificate_ambiguous';

type AccountLike = Pick<
  Doc<'edgeProviderAccounts'>,
  'provider' | 'lastTestError' | 'settings' | 'optionDefaults' | 'sharedCertificate'
>;
type LocationLike = Pick<Doc<'edgeLocations'>, 'checkError' | 'sharedCertificate'>;

/**
 * Why no new front with the account's DEFAULT certificate can be planned in
 * this place, though it may be tested: the zone's CAA records forbid the
 * account's certificate authority (`caa_forbids_ca`: the location's check says
 * so, or, for an account checked before its zone was a location, its own
 * credential test), or the wildcard certificate the zone's fronts share failed
 * (`shared_certificate_failed`) or is one the account would not order
 * (`shared_certificate_ambiguous`). Null when nothing certificate-shaped stands
 * in the way. Without a location only the account's own (pre-location) record
 * is read.
 */
export function certificateRefusalOf(
  a: AccountLike,
  location: LocationLike | null = null,
): CertificateRefusal | null {
  if (location?.checkError === 'caa_forbids_ca' || a.lastTestError === 'caa_forbids_ca')
    return 'caa_forbids_ca';
  // The account's default scope (a node may choose its own: see certificateRefusalFor).
  const wildcard = accountOptionDefaultsOf(a).certificateScope === 'wildcard';
  const shared = location ? location.sharedCertificate : a.sharedCertificate;
  if (wildcard && shared?.state === 'failed') return 'shared_certificate_failed';
  // A wildcard the account would not order (another CA or configuration, or
  // several): its certificate step refuses every time, so nothing is built
  // for it first.
  if (wildcard && shared?.state === 'ambiguous') return 'shared_certificate_ambiguous';
  return null;
}

/**
 * The same for a front built with a pick's own choices (its options; null: a
 * pick from before options, which follows the account's defaults live). A
 * pick on the account's default certificate is judged by the zone's check
 * (`certificateRefusalOf`). A pick with another certificate is not refused by
 * that check's CAA verdict, which answered for the default only (its own is
 * read when its plan is made, `edgeProviderOps.certificatePreflight`); only the
 * zone's wildcard refuses it, when it chose the wildcard.
 */
export function certificateRefusalFor(
  a: AccountLike,
  location: LocationLike | null,
  choices: Values | null,
): CertificateRefusal | null {
  const defaults = accountOptionDefaultsOf(a);
  const tested = certificateValuesFor(a.provider, defaults, null);
  const mine = certificateValuesFor(a.provider, defaults, choices);
  if (canonicalJson(mine) === canonicalJson(tested)) return certificateRefusalOf(a, location);
  if (mine.certificateScope !== 'wildcard') return null;
  const shared = location ? location.sharedCertificate : a.sharedCertificate;
  if (shared?.state === 'failed') return 'shared_certificate_failed';
  if (shared?.state === 'ambiguous') return 'shared_certificate_ambiguous';
  return null;
}
