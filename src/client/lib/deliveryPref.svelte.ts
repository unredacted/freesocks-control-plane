/**
 * Client-side delivery preference — 'evade' (stay-connected) vs 'privacy'
 * (E2EE-first). localStorage ONLY: we deliberately keep NO server-side metadata
 * about which a member picked. It drives which delivery path the account page
 * surfaces first; the server's country-based `suggestedDelivery` is the fallback
 * when the member hasn't chosen. Mirrors the getLocale() shared-rune idiom.
 */
export type DeliveryPref = 'evade' | 'privacy';
const KEY = 'fs_delivery_pref';

function read(): DeliveryPref | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'privacy' || v === 'evade' ? v : null;
  } catch {
    return null;
  }
}

let pref = $state<DeliveryPref | null>(read());

/** The member's explicit choice, or null if they haven't picked. Reactive. */
export function deliveryPref(): DeliveryPref | null {
  return pref;
}

export function setDeliveryPref(p: DeliveryPref): void {
  pref = p;
  try {
    localStorage.setItem(KEY, p);
  } catch {
    /* private mode / blocked storage — the in-memory value still drives this session */
  }
}
