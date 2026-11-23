/**
 * The sealing-posture knobs, apart from the sealed() wrapper. Queries and
 * mutations that only report the posture (adminApi) import this, never
 * ./hpke.ts: that module pulls in the seal/open code, which must stay out of
 * every module that registers a query or mutation (their randomness is seeded
 * per execution; see convex/hpkeRuntimeBoundary.test.ts).
 */

/**
 * Read a sealing-posture knob from the deployment env. Also honors the
 * pre-2026-09-16 `FS_E2EE_*` spelling (the E2EE -> HPKE rename) so a deploy that
 * lands before the operator renames the deployment env cannot silently reopen
 * dual-mode and let account numbers transit in plaintext. Drop the legacy read
 * once every deployment's env carries the `FS_HPKE_*` names.
 */
export function postureKnob(name: 'FS_HPKE_REQUIRED' | 'FS_HPKE_ADMIN_REQUIRED'): boolean {
  const legacy = name.replace('FS_HPKE_', 'FS_E2EE_');
  return process.env[name] === 'true' || process.env[legacy] === 'true';
}
