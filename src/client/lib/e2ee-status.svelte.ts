/**
 * Reactive E2EE session status. Mutated by the lazy CDN-blinding seam
 * (`openInbound` in ./e2ee.ts) when it actually opens a sealed response, and read
 * by the E2EE banner + the account views to show an "actively encrypted"
 * confirmation. A plain `$state` object so a mutation from the non-reactive
 * `e2ee.ts` module still drives component reactivity wherever it's read.
 *
 * This module is light (no crypto), so the always-loaded banner can import it
 * eagerly while the heavy `e2ee.ts` chunk that mutates it stays lazy — both share
 * the same `$state` instance.
 */
export const e2eeSession = $state<{ lastSealedAt: number | null }>({ lastSealedAt: null });

/** Record that the client just opened a sealed (E2EE) response. */
export function markSealedResponse(): void {
  e2eeSession.lastSealedAt = Date.now();
}
