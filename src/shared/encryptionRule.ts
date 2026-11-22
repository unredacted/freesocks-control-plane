/**
 * Which of a connection's two entries an app is handed where the connection
 * has an encrypted twin (VLESS Encryption, docs/backends.md); a connection
 * without one has only the plain entry to give:
 *
 *   prefer   the encrypted entry first, the plain one after every first
 *            choice as a fallback (an app that cannot speak the layer still
 *            connects, by itself where the format has an auto group);
 *   only     the encrypted entry alone;
 *   plain    the plain entry alone (an app that cannot even read the other).
 *
 * Set per client family (`edge.render.clients.<family>.encryption`).
 */
export type EncryptionRule = 'prefer' | 'only' | 'plain';
export const ENCRYPTION_RULES: readonly EncryptionRule[] = ['prefer', 'only', 'plain'];

/**
 * The most an app may be handed whatever its family's rule, where its
 * User-Agent shows it may not speak the layer (convex/lib/edges/clientFamilies.ts
 * `ENCRYPTION_FLOORS`): `plain` for an app version known not to, `prefer` for
 * one that may or may not (it keeps a plain entry to fall back on).
 */
export type EncryptionCap = 'prefer' | 'plain';
export const ENCRYPTION_CAPS: readonly EncryptionCap[] = ['prefer', 'plain'];

const RULE_RANK: Record<EncryptionRule, number> = { plain: 0, prefer: 1, only: 2 };

/**
 * A family's rule, lowered to the app's cap where the cap is lower. A rule
 * with no `encryption` reads as `prefer` (the renderer's default) and is left
 * as it is when there is no cap.
 */
export function capEncryptionRule<R extends EncryptionRule | undefined>(
  rule: R,
  cap?: EncryptionCap,
): R | EncryptionCap {
  if (cap === undefined) return rule;
  return RULE_RANK[cap] < RULE_RANK[rule ?? 'prefer'] ? cap : rule;
}
