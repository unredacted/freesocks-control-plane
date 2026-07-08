/**
 * Client-side connection-mode preference (a mode id string). localStorage ONLY:
 * we deliberately keep NO server-side metadata about which a member picked while
 * anonymous. It drives which delivery path the account page surfaces first; the
 * server's country-based `suggestedModeId` is the fallback when the member hasn't
 * chosen. The stored value is validated against the live catalog by the caller
 * (any string is accepted here; an unknown id just won't match a catalog entry).
 * Mirrors the getLocale() shared-rune idiom.
 */
const KEY = 'fs_connection_mode';

function read(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

let pref = $state<string | null>(read());

/** The member's explicit choice, or null if they haven't picked. Reactive. */
export function connectionModePref(): string | null {
  return pref;
}

export function setConnectionModePref(modeId: string): void {
  pref = modeId;
  try {
    localStorage.setItem(KEY, modeId);
  } catch {
    /* private mode / blocked storage — the in-memory value still drives this session */
  }
}
