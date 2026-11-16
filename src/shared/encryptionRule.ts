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
