/**
 * Referral-link capture: a shared `?ref=FSR-…` param binds the visitor's next
 * account creation to the referrer. Captured on ANY route (links may land on
 * the home page), persisted to localStorage so it survives navigation before
 * signup, stripped from the URL, and cleared once consumed. Non-secret (the
 * code only credits the referrer), so localStorage is fine.
 */
const KEY = 'fs_referral_code';
const MAX_LEN = 32;

/** Cheap shape guard: FSR-XXXX-XXXX (or the bare 8 data chars). */
function plausible(code: string): boolean {
  const s = code.toUpperCase().replace(/[\s-]/g, '');
  const body = s.startsWith('FSR') ? s.slice(3) : s;
  return body.length === 8;
}

/** Read + persist the `?ref=` param if present (call once on app mount). */
export function captureReferralParam(): void {
  if (typeof window === 'undefined') return;
  const url = new URL(window.location.href);
  const ref = url.searchParams.get('ref')?.trim() ?? '';
  if (!ref) return;
  if (ref.length <= MAX_LEN && plausible(ref)) {
    try {
      localStorage.setItem(KEY, ref);
    } catch {
      /* storage unavailable — the field stays manual */
    }
  }
  // Strip the param either way (clean share URLs; no ref= leakage into history).
  url.searchParams.delete('ref');
  window.history.replaceState(window.history.state, '', url);
}

/** The stored code, normalized for display (uppercase). '' when none. */
export function readStoredReferralCode(): string {
  try {
    return (localStorage.getItem(KEY) ?? '').trim().toUpperCase();
  } catch {
    return '';
  }
}

export function clearStoredReferralCode(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}
