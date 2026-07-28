/**
 * Pure decision helpers for the connection-mode (transport) switcher, shared by
 * /account and /get-account (via ConnectionModeSwitcher) so the two pages resolve
 * the current mode and gate the re-issue identically. Kept side-effect-free so
 * they're unit-testable without a DOM.
 */

/**
 * Last-resort mode id, used only when the public catalog is empty (a
 * misconfigured or still-booting deployment). Mirrors DEFAULT_CONNECTION_MODE in
 * convex/lib/connectionModes.ts, which is the source of truth — the server ships
 * an `isDefault` flag on every non-empty catalog, so this literal is normally
 * unreachable.
 */
export const FALLBACK_CONNECTION_MODE = 'freedom-ws';

/**
 * Which mode to highlight/use. When server-backed (a key exists + a pool is
 * bound), the server-persisted `connectionModeId` is authoritative and the local
 * pref is only an optimistic bridge; otherwise the local device choice wins, then
 * the server's country suggestion, then the catalog default.
 *
 * `knownIds`, when supplied, VALIDATES the client-side inputs (`pref` and
 * `suggested`) against the live catalog — without it the member lands on a dead
 * id that every server call rejects. The server-persisted `connectionModeId` is
 * deliberately NOT validated: an admin-disabled mode is omitted from the catalog
 * but is still where the member actually is, and the picker synthesizes an entry
 * for it so they can move off. (The pre-rename legacy-id map is gone: the server
 * migrates stored rows at deploy and serves canonical ids; a stale localStorage
 * pref simply fails the knownIds check and falls through.)
 */
export function resolveEffectiveModeId(opts: {
  serverBacked: boolean;
  connectionModeId?: string | null;
  pref: string | null;
  suggested?: string | null;
  fallback: string;
  knownIds?: readonly string[];
}): string {
  const { serverBacked, suggested, fallback, knownIds } = opts;
  const known = (id: string | null | undefined): string | null => {
    if (!id) return null;
    return !knownIds || knownIds.includes(id) ? id : null;
  };
  const stored = opts.connectionModeId ?? null;
  const pref = known(opts.pref);
  const sugg = known(suggested);
  if (serverBacked) return stored ?? pref ?? sugg ?? fallback;
  return pref ?? sugg ?? fallback;
}

/**
 * Whether picking `target` should open the confirm dialog (a real key re-issue)
 * rather than be a local-only preference. True ONLY when server-backed, enabled,
 * not mid-flight, and actually changing the mode. A non-server-backed pick is
 * always a local preference (handled by the caller), so this returns false there.
 */
export function shouldConfirmSwitch(opts: {
  serverBacked: boolean;
  disabled: boolean;
  busy: boolean;
  selected: string;
  target: string;
}): boolean {
  const { serverBacked, disabled, busy, selected, target } = opts;
  if (!serverBacked) return false;
  if (target === selected || busy || disabled) return false;
  return true;
}
