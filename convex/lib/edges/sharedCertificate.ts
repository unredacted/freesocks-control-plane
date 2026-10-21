/**
 * Whether a zone's recorded shared wildcard is FCP's to remove (docs/edges.md
 * § "L7 edges", Certificates): an edge of the account ORDERED it
 * (`edgeProviderAccounts.orderedSharedResources`, written when its step
 * created it) and the provider still holds it. One the account merely found
 * and reused may serve somebody else's services, so FCP never removes it.
 * Pure: the account guards and the location guards read the same rule.
 */

/** Shared-certificate states that are FCP's to remove (a record of another account's is not). */
// `ambiguous` with a subscription named: one this account ordered under an
// authority it no longer defaults to (still FCP's to remove).
const REMOVABLE_SHARED_STATES: ReadonlySet<string> = new Set([
  'pending',
  'processing',
  'issued',
  'renewing',
  'failed',
  'ambiguous',
]);

export type SharedCertificateRecord = { state: string; subscriptionId?: string } | null | undefined;

/** An edge of the account ordered this recorded shared certificate. */
export function sharedCertificateOrderedByFcp(
  ordered: readonly string[] | undefined,
  sc: SharedCertificateRecord,
): boolean {
  const id = sc?.subscriptionId;
  return !!id && (ordered ?? []).includes(`tls_subscription:${id}`);
}

/** This recorded shared certificate is one FCP can remove (it ordered it, it is there). */
export function removableSharedCertificate(
  ordered: readonly string[] | undefined,
  sc: SharedCertificateRecord,
): boolean {
  return (
    !!sc && REMOVABLE_SHARED_STATES.has(sc.state) && sharedCertificateOrderedByFcp(ordered, sc)
  );
}
