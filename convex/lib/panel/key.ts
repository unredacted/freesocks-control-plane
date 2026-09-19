/**
 * The key for the panel digests (convex/lib/panel/digest.ts).
 *
 * It must be STABLE for the life of a deployment: the REALITY authentication
 * digest joins an operator's endpoint confirmation, so a key that rotated
 * would stale every confirmation at once. It is therefore derived, with a
 * fixed domain-separation label, from `ACCOUNT_ID_PEPPER`, the one deployment
 * secret that is set once and never rotated (docs/secrets.md). HMAC as a KDF:
 * the derived key reveals nothing about the pepper, and neither does a digest.
 *
 * `keyId` names the key without revealing it. It is stored beside each digest
 * so that, should the key ever differ (a restored database on a new
 * deployment), digests are re-baselined instead of read as "everything changed".
 */
import { hmacSha256Hex, sha256Hex } from '../crypto';

export interface PanelDigestKey {
  key: string;
  keyId: string;
}

export async function panelDigestKey(): Promise<PanelDigestKey> {
  const pepper = process.env.ACCOUNT_ID_PEPPER;
  if (!pepper) throw new Error('ACCOUNT_ID_PEPPER must be set (bunx convex env set ...)');
  const key = await hmacSha256Hex(pepper, 'fcp.panel-digest.v1');
  return { key, keyId: (await sha256Hex(`fcp.panel-digest.id\n${key}`)).slice(0, 12) };
}
