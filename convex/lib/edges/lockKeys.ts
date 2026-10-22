/**
 * The keys of the external locks (`externalLocks`) that serialise work on a
 * provider object several writers share. Pure: the rotation's steps and the
 * account-level actions build the SAME key from the same facts, so they wait
 * on each other.
 */

/**
 * One CDN account's wildcard certificate in one zone (a Fastly subscription,
 * a CloudFront front's ACM certificate): the edges' certificate and ACME steps
 * (which find it or order it once) and its removal from the account page hold
 * this key. The `fastly-` prefix predates the second provider; locks in flight
 * keep their key across a deploy.
 */
export function fastlyCertificateLockKey(accountId: string, zoneId: string): string {
  return `fastly-certificate:${accountId}:${zoneId}`;
}

/**
 * One CloudFront account's shared origin request policies: the distribution
 * step finds one with room (100 distributions each) or creates the next and
 * attaches the new distribution under this key, so two fronts never both take
 * the last place in one policy.
 */
export function cloudFrontPolicyLockKey(accountId: string): string {
  return `cloudfront-policy:${accountId}`;
}
