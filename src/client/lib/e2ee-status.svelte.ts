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
import { classifyAttestation, nextAttestation, type E2eeAttestation } from './e2ee-attestation';

export { classifyAttestation };
export type { E2eeAttestation };

/**
 * COMPILE-TIME read of the baked pins (same expression as api.ts E2EE_ENABLED and
 * the banner's `enabled`). Vite inlines it, so in a dark build the guarded
 * `import('./e2ee')` below becomes dead code and Rollup drops the heavy e2ee chunk
 * entirely. Keep the gate at the import call-site for that tree-shaking to hold.
 */
const SEALING_CONFIGURED =
  !!import.meta.env.VITE_FS_SERVER_HPKE_PK && !!import.meta.env.VITE_FS_SERVER_HPKE_KID;

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

/** Don't re-hit the key endpoint more often than this (its own max-age is 60s). */
const MIN_RECHECK_MS = 60_000;
/** Re-attest this often, so a tab left open for days isn't stuck on a stale verdict. */
const RECHECK_INTERVAL_MS = 5 * 60_000;

let lastCheckedAt = 0;
let inFlight: Promise<void> | null = null;
let hooksInstalled = false;

async function runAttestation(): Promise<void> {
  const { verifyConnection } = await import('./e2ee');
  const att = await verifyConnection();
  lastCheckedAt = Date.now();
  const verdict = classifyAttestation(att);
  const held = nextAttestation(e2eeSession.attestation, verdict);
  // A `warn` held over an inconclusive poll keeps the epoch fields from the
  // observation that raised it: overwriting them would erase what tripped the alarm
  // while the alarm is still showing.
  if (held === verdict) {
    e2eeSession.epochKid = att.epochKid ?? null;
    e2eeSession.notAfter = att.notAfter ?? null;
  }
  e2eeSession.attestation = held;
}

/**
 * Re-run the live key attestation and fold the fresh verdict into `e2eeSession`.
 * Throttled to one call per MIN_RECHECK_MS (pass `force` for an explicit user
 * action, e.g. opening the verify panel), and single-flighted so a burst of
 * triggers - the interval firing as a tab is refocused - is one request.
 */
export async function refreshAttestation(opts?: { force?: boolean }): Promise<void> {
  if (!SEALING_CONFIGURED) return; // dark build: compile-time false → import() is tree-shaken
  if (inFlight) return inFlight;
  if (!opts?.force && Date.now() - lastCheckedAt < MIN_RECHECK_MS) return;
  inFlight = runAttestation().finally(() => {
    inFlight = null;
  });
  return inFlight;
}

/**
 * Keep the verdict live for the lifetime of the tab. Without this the check ran
 * exactly once per page load, so a tab left open (or, worse, silently reloaded
 * from cache by a browser restoring a discarded tab) kept whatever verdict it
 * first computed - including a scary banner that a single manual refresh cleared.
 *
 * The interval is the failsafe and runs unconditionally; refocus + regained
 * connectivity are extra nudges on top of it. Deliberately NOT gated on
 * `visibilityState === 'visible'`: some embedded webviews report a displayed page
 * as hidden forever, which would silently disable the whole refresh. Browsers
 * throttle background timers on their own, and the throttle below plus the key
 * endpoint's per-IP policy bound the cost either way.
 */
function installRefreshHooks(): void {
  if (hooksInstalled || typeof document === 'undefined') return;
  hooksInstalled = true;
  const refresh = () => void refreshAttestation();
  document.addEventListener('visibilitychange', refresh);
  window.addEventListener('online', refresh);
  setInterval(refresh, RECHECK_INTERVAL_MS);
}

/**
 * Run the live key attestation for this page and keep it fresh from then on.
 * Idempotent: the first caller starts the check and installs the refresh hooks,
 * later callers fall through to the throttled `refreshAttestation`.
 * Lazy-imports the crypto chunk so the light badge can trigger it without eagerly
 * loading `e2ee.ts`.
 */
export async function ensureAttestationChecked(opts?: { force?: boolean }): Promise<void> {
  if (!SEALING_CONFIGURED) return; // dark build: compile-time false → import() is tree-shaken
  installRefreshHooks();
  await refreshAttestation(opts);
}

/** Open the shared "Verify connection" modal from anywhere (badge or alert). */
export function openVerify(): void {
  e2eeSession.verifyOpen = true;
}
