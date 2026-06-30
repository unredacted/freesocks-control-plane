// Print the out-of-band verification anchors for the CDN-blinding keys: the
// fingerprints of the baked manifest (Ed25519 + ML-DSA-65) + static HPKE public
// keys (CDN-blinding Phase 3f). Publish these through an INDEPENDENT trust path (a
// signed GitHub release, the .onion mirror, optionally a DNSSEC TXT) so a user can
// confirm the key their bundle pins matches the key published outside the CDN. The
// pinned key alone proves nothing against an active CDN; an independent path is
// what makes it meaningful. The in-app "Verify connection" panel shows the SAME
// values (both call fingerprintB64Url), so a user can compare in either place. See
// docs/oob-verification.md.
//
// Reads the public VITE_FS_* values from the environment, falling back to
// .env.local. Run: bun scripts/e2ee-fingerprint.mjs
import { readFileSync } from 'node:fs';
import { fingerprintB64Url } from '../src/shared/crypto/envelope.ts';

function loadEnv() {
  const env = { ...process.env };
  try {
    for (const line of readFileSync('.env.local', 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (m && env[m[1]] === undefined) env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  } catch {
    /* no .env.local */
  }
  return env;
}

const env = loadEnv();
// [label, env var, optional]. The PQ manifest key is optional — a deployment may
// run an Ed25519-only manifest (valid, just not hybrid), so its absence is not a
// hard failure; the classical manifest, the HPKE key, and the suite id are.
const fields = [
  ['Manifest key (Ed25519)', 'VITE_FS_MANIFEST_PK', false],
  ['Manifest key (ML-DSA-65, post-quantum)', 'VITE_FS_MANIFEST_PK_PQ', true],
  ['Static HPKE key (X-Wing)', 'VITE_FS_SERVER_HPKE_PK', false],
  ['HPKE suite id', 'VITE_FS_E2EE_SUITE_ID', false],
];

console.log('CDN-blinding out-of-band verification anchors');
console.log('(publish via a signed release + the .onion mirror; see docs/oob-verification.md)\n');
let missing = false;
for (const [label, key, optional] of fields) {
  const v = env[key];
  if (!v) {
    console.log(`${label}: (unset: ${key})`);
    if (!optional) missing = true;
    continue;
  }
  if (key === 'VITE_FS_E2EE_SUITE_ID') console.log(`${label}: ${v}`);
  else console.log(`${label}\n  ${key}\n  sha256: ${await fingerprintB64Url(v)}`);
}
if (missing) process.exitCode = 1;
