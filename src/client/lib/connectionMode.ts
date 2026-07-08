/**
 * Pure decision helpers for the connection-mode (transport) switcher, shared by
 * /account and /get-account (via ConnectionModeSwitcher) so the two pages resolve
 * the current mode and gate the re-issue identically. Kept side-effect-free so
 * they're unit-testable without a DOM.
 */

/**
 * Which mode to highlight/use. When server-backed (a key exists + a pool is
 * bound), the server-persisted `connectionModeId` is authoritative and the local
 * pref is only an optimistic bridge; otherwise the local device choice wins, then
 * the server's country suggestion, then the catalog default.
 */
export function resolveEffectiveModeId(opts: {
  serverBacked: boolean;
  connectionModeId?: string | null;
  pref: string | null;
  suggested?: string | null;
  fallback: string;
}): string {
  const { serverBacked, connectionModeId, pref, suggested, fallback } = opts;
  if (serverBacked) return connectionModeId ?? pref ?? suggested ?? fallback;
  return pref ?? suggested ?? fallback;
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
