/**
 * Reactive E2EE session status. Mutated by the lazy CDN-blinding seam
 * (`openInbound` in ./e2ee.ts) when it actually opens a sealed response, and read
 * by the E2EE badge + alert + the verify modal to show an "actively encrypted"
 * confirmation and the live key-attestation verdict. A plain `$state` object so a
 * mutation from the non-reactive `e2ee.ts` module still drives component
 * reactivity wherever it's read.
 *
 * This module is light (no crypto), so the always-loaded chrome (the E2EE badge)
 * can import it eagerly while the heavy `e2ee.ts` chunk that mutates it stays
 * lazy. `ensureAttestationChecked()` lazy-imports `e2ee.ts` only on demand, so a
 * dark build whose badge never renders the active branch never pulls the chunk.
 */

/**
 * COMPILE-TIME read of the baked pins (same expression as api.ts E2EE_ENABLED and
 * the banner's `enabled`). Vite inlines it, so in a dark build the guarded
 * `import('./e2ee')` below becomes dead code and Rollup drops the heavy e2ee chunk
 * entirely. Keep the gate at the import call-site for that tree-shaking to hold.
 */
const SEALING_CONFIGURED =
  !!import.meta.env.VITE_FS_SERVER_HPKE_PK && !!import.meta.env.VITE_FS_SERVER_HPKE_KID;

export type E2eeAttestation = 'pending' | 'active' | 'warn' | 'unreachable';

export const e2eeSession = $state<{
  lastSealedAt: number | null;
  /** Live verdict from GET /api/v1/e2ee/keys (see ensureAttestationChecked). */
  attestation: E2eeAttestation;
  epochKid: string | null;
  notAfter: number | null;
  /** Drives the single shared <E2eeVerifyModal> mounted once in App.svelte. */
  verifyOpen: boolean;
}>({
  lastSealedAt: null,
  attestation: 'pending',
  epochKid: null,
  notAfter: null,
  verifyOpen: false,
});

/** Record that the client just opened a sealed (E2EE) response. */
export function markSealedResponse(): void {
  e2eeSession.lastSealedAt = Date.now();
}

let attestationStarted = false;

/**
 * Run the read-only live key attestation once per page load and fold the verdict
 * into `e2eeSession`. Verdicts:
 *  - `active`      key verified against the baked manifest key, unexpired, not revoked.
 *  - `warn`        the endpoint answered but the key FAILS to verify (expired/revoked
 *                  or a CDN tampering with /api/v1/e2ee/keys) — the active-CDN tamper
 *                  tell; this is the one state that must be surfaced loudly.
 *  - `unreachable` couldn't reach the endpoint (a network blip); the pinned key is
 *                  still in use, so this is NOT an alarm.
 * Lazy-imports the crypto chunk so the light badge can trigger it without eagerly
 * loading `e2ee.ts`. Idempotent — the first caller wins, later callers no-op.
 */
export async function ensureAttestationChecked(): Promise<void> {
  if (!SEALING_CONFIGURED) return; // dark build: compile-time false → import() below is tree-shaken
  if (attestationStarted) return;
  attestationStarted = true;
  const { verifyConnection } = await import('./e2ee');
  const att = await verifyConnection();
  e2eeSession.epochKid = att.epochKid ?? null;
  e2eeSession.notAfter = att.notAfter ?? null;
  e2eeSession.attestation = att.attested ? 'active' : att.reachable ? 'warn' : 'unreachable';
}

/** Open the shared "Verify connection" modal from anywhere (badge or alert). */
export function openVerify(): void {
  e2eeSession.verifyOpen = true;
}
