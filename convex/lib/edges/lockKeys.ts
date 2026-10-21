/**
 * The keys of the external locks (`externalLocks`) that serialise work on a
 * provider object several writers share. Pure: the rotation's steps and the
 * account-level actions build the SAME key from the same facts, so they wait
 * on each other.
 */

/**
 * One Fastly account's wildcard certificate in one zone: the edges' certificate
 * and ACME steps (which find it or order it once) and its removal from the
 * account page hold this key.
 */
export function fastlyCertificateLockKey(accountId: string, zoneId: string): string {
  return `fastly-certificate:${accountId}:${zoneId}`;
}
