# Out-of-band verification and reproducible build (CDN-blinding Phase 3f)

This is the runbook for the active-adversary tier of the CDN-blinding feature.
Phases 1 to 3 defeat a PASSIVE CDN: the crown-jewel secrets are sealed, sessions
are bound to a proof-of-possession key, and the login seals to a short-lived
manifest-signed epoch key. None of that stops an ACTIVE CDN that rewrites the JS
bundle we serve, because a browser runs whatever script the CDN hands it. The
pinned key proves nothing on its own: a tampered bundle can carry the real key as
a string yet seal to an attacker key.

The defenses against that are (a) letting a user confirm, through a trust path
that does NOT run through the CDN, that the key and bundle they received match
what we published, and (b) a reproducible build so anyone can check the published
bundle was built from the public source. This doc covers both. The strongest
active defense, a signed verifier extension or native app, is Phase 4.

Most of this is operator action at release time; what the repo automates is
noted as such.

## Anchors (independent trust paths)

Publish, on every release, two values:

- the **key fingerprints** (`bun scripts/e2ee-fingerprint.mjs`): the manifest
  public keys — Ed25519 **and** ML-DSA-65 (the script emits both, matching the
  client's hybrid requirement) — which anchor the epoch keys + the revoked-kid
  list, plus the static HPKE key, and
- the **reproducible `dist-sha256`** (`bash scripts/verify-reproducible.sh`),
  which identifies the exact served bundle.

through as many of these independent channels as are available:

1. **Signed GitHub release (primary).** Tag the release with a signed git tag
   (`git tag -s`) and put both values in the release notes. GitHub is a different
   trust domain from the CDN, and the release is the home of the reproducible
   hash. A user (or a journalist, or a mirror) can compare the fingerprint baked
   into their bundle against the signed release.
2. **Tor `.onion` mirror (high priority).** Serve the same `dist/` from an
   `.onion` whose address is published in the signed release. The address is
   self-authenticating (it is the service public key), it bypasses the CDN
   entirely for the sensitive flows, and it answers the IP-correlation metadata
   gap that the CDN otherwise has. A user who can reach Tor can fetch the bundle
   without the CDN ever seeing the request.
3. **DNS TXT pin (`_fcp-pin`).** Publish a TXT record carrying the same key
   fingerprints so a user can confirm them through their own resolver, a path that
   does not run through the CDN's HTTP. `bun scripts/e2ee-fingerprint.mjs` prints the
   ready-to-publish record:

   ```
   name:   _fcp-pin.<your-app-host>
   value:  "v=fcp1; hpke=<sha256-hex>; ed25519=<sha256-hex>; mldsa=<sha256-hex>"
   verify: dig +short TXT _fcp-pin.<your-app-host>
   ```

   The `hpke`/`ed25519`/`mldsa` values are the **ungrouped** hex of the same
   fingerprints above (`mldsa` is omitted for an Ed25519-only deployment); the in-app
   "Verify via DNS" panel computes them with the same primitive (`sha256HexOfB64Url`),
   so the page and the record are one hash. The user runs the `dig` themselves and
   compares: strict `connect-src 'self'` (and COEP `require-corp`) forbid an in-page
   DNS lookup by design, so this is deliberately a manual check, not an automatic one.
   CAVEAT: independent **only if** your DNS provider is not the same company as the
   CDN; sign the zone with DNSSEC and tell users to prefer a validating resolver. If
   DNS and the CDN share a provider this path adds little, so say so in the release
   notes and lean on the signed release / `.onion`.

4. **Verifier extension / native app (Phase 4, scaffold in `verifier-extension/`).**
   The strongest active-CDN defense: trusted code ships through the browser web store
   (not the CDN) and checks the served `index.html` hash against the pinned
   reproducible build (MEGA model); a native app reusing the existing proxy clients is
   the stronger sibling. **Not built yet:** the repo carries only an unpublished
   scaffold (no `pinned.js`, not in any web store). Until it is published, anchors 1-3
   above are the verification path, and the in-app panel says as much.

The in-app **"Verify connection" panel** (opened from the E2EE badge in the header /
admin sidebar) shows the SAME fingerprints — it and the script both call
`fingerprintB64Url`, so the value on the running page is byte-identical to the one
published here — adds a live manifest-attestation check (`/api/v1/e2ee/keys`), and
surfaces the **"Verify via DNS"** lookup (the `_fcp-pin` `dig` command + the expected
record) so a user can check off-CDN without leaving the page. The panel is a
_convenience_, not the trust root: a tampered page could lie about its own status, so
the guarantee still comes from comparing through a channel the CDN doesn't control —
the DNS lookup you run yourself, the signed release, or the `.onion` mirror.

## Reproducible build

The build is deterministic given a pinned toolchain. `scripts/verify-reproducible.sh`
builds the SPA twice from the current checkout and asserts byte-for-byte identical
output, then prints the canonical `dist-sha256`. CI runs it on every push (the
`reproducible-build` job in `.github/workflows/ci.yml`), so a regression in
determinism fails the build.

Recipe for a publishable hash:

1. Clean checkout at the release tag (no local edits): `git clean -fdx` then
   `bun install --frozen-lockfile` (the lockfile pins every dependency).
2. Pinned toolchain: bun `1.3.14` (`packageManager` in `package.json`); CI uses
   the same via `oven-sh/setup-bun`.
3. `bash scripts/verify-reproducible.sh` and record the `dist-sha256`.

Determinism notes / current limits:

- Same toolchain + lockfile gives a stable hash (verified: two builds match, and
  CI enforces it). A DIFFERENT OS/arch or bun version MAY produce a different
  hash; pin the rebuild environment to match CI (ubuntu-latest, bun 1.3.14).
- The SPA build embeds no wall-clock timestamps; the `VITE_*` values (including
  the baked keys) are build inputs, so the published hash is specific to a given
  key set. Re-publish the hash whenever the baked keys change.
- Stronger provenance (npm/Sigstore-style attestation to Rekor, plus at least one
  independent third-party rebuilder publishing agreement or dissent) is the next
  increment. The repo gives the deterministic recipe + the CI double-build; the
  Rekor attestation and the recruited rebuilder are operator/community actions.

### Independent-rebuilder protocol

A third party who does not trust us (or the CDN) reproduces a release:

1. Check out the signed release tag; verify the tag signature.
2. Run the recipe above; confirm `dist-sha256` matches the signed release.
3. Optionally fetch the live bundle (via the `.onion`, off-CDN) and confirm its
   hash matches too.
4. Publish the result. Agreement raises confidence; any mismatch is a public
   alarm that the served bundle diverges from the source.

## Per-release operator checklist

1. From a clean checkout at the tag: `bun install --frozen-lockfile`.
2. `bun scripts/e2ee-fingerprint.mjs` -> record the manifest + static-key fingerprints
   AND the ready-to-publish `_fcp-pin` DNS TXT record it prints.
3. `bash scripts/verify-reproducible.sh` -> record `dist-sha256`.
4. `git tag -s <version>` and publish a GitHub release with both values.
5. Deploy the same `dist/` to the CDN origin and to the `.onion` mirror.
6. Publish/update the `_fcp-pin` TXT record (value from step 2) so users can `dig` it;
   sign the zone with DNSSEC. Skip only if DNS shares a provider with the CDN (and note
   that in the release notes, since it is then not an independent path).
7. On an emergency key compromise, run
   `bunx convex run lib/e2eeCrypto:signRevocation '{"revokedKids":["<kid>"]}'`
   and announce the new revoked-kid list version through the same channels.

## Status

- Automated in the repo: SRI on entry assets, the reproducible double-build (local
  script + CI job), the fingerprint script, the revocation break-glass action.
- Operator action: the signed release, the `.onion` mirror, the DNSSEC TXT, the
  Rekor attestation, and recruiting an independent rebuilder.
- Phase 4 (done in-repo): the hybrid Ed25519 + ML-DSA-65 manifest key, and the verifier extension
  scaffold (`verifier-extension/`); pinning + web-store publication of the extension, and a native
  app, are operator actions.
