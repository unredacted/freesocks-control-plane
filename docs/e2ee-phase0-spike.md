# E2EE Phase 0 spike: KEM decision, KAT sources, and the isolate-budget gate

This is the on-the-record decision artifact for the CDN-blinding feature (full design:
`.claude/plans/`, and once promoted `docs/threat-model-cdn-blinding.md`). It exists because the
Harvest-Now-Decrypt-Later threat makes the Phase 1 KEM choice effectively permanent for any traffic
an adversary logs, so the choice is recorded here and validated before any sealing code ships.

## 0. Headline gate finding (RUNTIME REQUIREMENT)

The X-Wing HPKE suite **works correctly and within budget in the Convex Node runtime (`"use node"`),
but NOT in the default V8 isolate**: the default isolate does not implement `crypto.subtle.importKey`
for **HKDF** (it does implement HMAC, which `convex/lib/crypto.ts` already relies on, but not HKDF),
and both the HPKE key schedule and the X-Wing KEM's internal KDF require it. The X-Wing KEM hardcodes
its KDF, so a pure-JS HKDF cannot be injected without forking the library, which we will not do.

**Decision: the server-side HPKE open/seal runs in a `"use node"` internal action** (full WebCrypto),
matching the existing `convex/webauthn.ts` and `convex/storage.ts` pattern. The public `httpAction`s
stay in the default runtime and delegate the crypto step via `ctx.runAction`. The browser side is
unaffected (browsers ship full WebCrypto including HKDF). This corrects the earlier plan assumption
that the suite's only WebCrypto need (SHA-256/HMAC/HKDF) was universal across the isolate.

## 1. KEM decision (made, not deferred)

**KEM = X-Wing (X25519 + ML-KEM-768)**, via the maintained `@hpke/hybridkem-x-wing` extension to
`@hpke/core`. KDF = HKDF-SHA256, AEAD = ChaCha20-Poly1305. Single, pinned, versioned suite; the
client refuses any non-pinned suite.

Verified by inspecting the installed packages:

- The extension's PQ leg is `mlkem@2.7.0` (the `dajiaji/crystals-kyber-js` package; README: "ML-KEM
  (NIST FIPS 203)"), and `xWing.js` imports `MlKem768`. So this is **genuine FIPS 203 ML-KEM-768**,
  not the pre-FIPS Kyber768-r3 the earlier review warned about. The "Kyber768" string in the
  extension's doc comment is stale wording. (Note: the live PQ implementation is `mlkem`, NOT
  `@noble/post-quantum` as the first plan draft assumed.)
- The X25519 leg is `@hpke/dhkem-x25519`, whose primitive wraps `@noble/curves` (pure-JS), not
  `crypto.subtle` X25519. This was the single highest-risk assumption and it holds.
- The combiner is the real X-Wing combiner, library-provided: `sha3_256(ssM ‖ ssX ‖ ctX ‖ pkX ‖
  label)` with the `\.//^\` label and ML-KEM-ciphertext omission. Never hand-rolled.
- Wire sizes match X-Wing exactly: `enc` = 1120 bytes (X25519 32 + ML-KEM-768 ct 1088), public key =
  1216 bytes (X25519 32 + ML-KEM-768 ek 1184).

Hybrid rationale (carried into the threat-model doc): X-Wing is secure if either X25519 or ML-KEM
holds, so the audited, decades-hardened X25519 leg backstops the young, unaudited ML-KEM leg against
both a cryptanalytic break and an implementation bug. The PQ leg (`mlkem`) and the X-Wing extension
(`0.7.0`, pre-1.0, pre-standardization) are not independently audited; the hybrid is the mitigation.

Crypto-agility: the envelope carries a versioned `suiteId` folded into HPKE `info`, so moving to
RFC-final X-Wing, an audited release, or a different suite later is a forced-client-rollout version
bump, not a wire-format redesign.

## 2. Committed stack (resolved 2026-06-08)

One monorepo (`dajiaji/hpke-js`) for the `@hpke/*` packages; `mlkem` and `@noble/*` by the same and
adjacent authors. Pinned with the lockfile committed.

| Package | Constraint | Resolved | Role |
| --- | --- | --- | --- |
| `@hpke/core` | `^1.7.5` | **1.9.0** | HPKE core, KDF, AEAD base, `Aes256Gcm` fallback. >= 1.7.5 includes the GHSA-73g8-5h73-26h4 concurrent-`seal()` nonce-reuse fix. |
| `@hpke/hybridkem-x-wing` | latest | **0.7.0** | KEM = X-Wing. Pre-1.0 / experimental; pulls `@hpke/dhkem-x25519` (X25519 via @noble/curves) + `mlkem`. |
| `@hpke/chacha20poly1305` | latest | **1.8.0** | AEAD (primary) |
| `mlkem` | transitive | **2.7.0** | FIPS 203 ML-KEM-768 (the live PQ leg), pure-JS, adds SHA-3/SHAKE |
| `@noble/post-quantum` | direct | **0.6.1** | Retained for the Phase 4 ML-DSA-65 manifest migration + optional KAT cross-checks. NOT on the live X-Wing path. |
| `@noble/curves` | direct | **2.2.0** | P-256 server-side PoP verify (Phase 2); X25519 reaches X-Wing transitively via @hpke/dhkem-x25519 |

## 3. KAT vector sources (to vendor in P0d)

The primitives are vector-tested upstream (`mlkem` CI runs FIPS 203 KATs; `@hpke/hybridkem-x-wing`
runs X-Wing vectors). We additionally vendor our own copies and run them in CI under both
jsdom/Vitest and `bunx convex run`, to catch upstream regressions and our own wiring:

- **X-Wing:** `draft-connolly-cfrg-xwing-kem-10` test vectors (and/or the X-Wing reference vectors).
  Record the exact source URL + revision when vendored in P0d.
- **ML-KEM-768:** FIPS 203 / NIST ACVP KATs (or the `mlkem` vendored vectors).
- **HPKE schedule / AEAD / KDF:** RFC 9180 Appendix A base-mode vectors for the chosen KDF + AEAD.

## 4. AEAD fallback criterion (moot for this blocker, retained for completeness)

Primary AEAD is ChaCha20-Poly1305 (noble pure-JS, constant-time, 256-bit PQ-adequate). The
`Aes256Gcm` fallback (built into `@hpke/core`, WebCrypto-backed) stands if ChaCha ever fails to
compose. Note: the isolate blocker (section 0) is the **KDF** (HKDF), not the AEAD, so the AEAD
fallback does not address it; both ChaCha and AES need subtle-HKDF in the default isolate and so both
run in the `"use node"` action.

## 5. The gate (results)

Run against the self-hosted Convex deployment (`http://127.0.0.1:3210`) via a throwaway
`"use node"` action `e2eeSpike:roundTrip` (and a standalone `bun` smoke). Default-isolate result
recorded for the record.

| # | Check | Result |
| --- | --- | --- |
| G1 | Suite composes + full round-trip (encap, seal, decap, open) | **PASS in `"use node"`** (round-trip ok). **FAIL in the default isolate** (`crypto.subtle.importKey for HKDF` not implemented). Drives the section-0 decision. |
| G2 | X25519 backend is noble pure-JS, not `subtle` X25519 | **PASS** (dep-tree: `@hpke/dhkem-x25519` wraps `@noble/curves`; the Node round-trip exercises it without an unsupported-algorithm error) |
| G3 | `crypto.getRandomValues` usable in the runtime | **PASS** (`getRandomValues: true`) |
| G4 | Single round-trip latency | **PASS** 18 ms in the Node runtime (7.5 ms standalone bun); well under the 50 ms threshold |
| G5 | 16 concurrent round-trips (each incl. keygen) | **PASS** 66 ms wall (54 ms standalone); no timeout |
| G6 | X-Wing + ML-KEM-768 KATs in CI under both envs | **PENDING** (vendored in P0d; primitives are KAT-tested upstream) |
| G7 | Implicit rejection surfaces as an AEAD `Open` failure, not a decaps throw | **PASS** (`tamperedOpenFailed: true`) |
| G8 | Single-use context (one `Seal` then drop) | **Discipline enforced in our wrapper** (hpke-js allows sequential seals with nonce increment; the GHSA was a concurrent-seal race, so our narrow API does one seal per context then discards it; asserted in P0d tests) |
| G9 | `Aes256Gcm` fallback if ChaCha fails to compose | **N/A** (the blocker was HKDF, not the AEAD) |

Gate decision: the runtime-critical checks pass in the Node runtime, so the approach is viable with
the section-0 `"use node"` server crypto. G6 (vendored KATs) and the G8 single-use assertion land
with the shared module in P0d before any production sealing.

## 6. Keys generated at the end of Phase 0

- **X-Wing server keypair:** private as `FS_SERVER_HPKE_SK` (Convex env); public + `kid` + `suiteId`
  baked into the bundle (`VITE_FS_SERVER_HPKE_PK`). Store the private key as the X-Wing
  seed/decapsulation key, never a separately cached expanded ML-KEM key.
- **Ed25519 manifest-signing keypair:** public key baked into the bundle (anchors the kid set, the
  Phase 3 epoch keys, and the revoked-kid list). Migrates to ML-DSA-65 in Phase 4.

## 7. Decision record

- Date: 2026-06-08.
- Resolved versions: `@hpke/core@1.9.0`, `@hpke/hybridkem-x-wing@0.7.0`, `@hpke/chacha20poly1305@1.8.0`,
  `mlkem@2.7.0` (transitive, FIPS 203 ML-KEM-768), `@noble/post-quantum@0.6.1`, `@noble/curves@2.2.0`.
- KEM: X-Wing (X25519 + ML-KEM-768), library-provided combiner, FIPS 203 ML-KEM confirmed.
- Gate result: PASS in the Convex Node runtime (18 ms single, 66 ms x16, CSPRNG present, sizes
  1120/1216, implicit-rejection via AEAD open failure). FAIL in the default isolate (no subtle HKDF).
- Architectural consequence: server HPKE open/seal runs in a `"use node"` internal action that the
  sealed `httpAction`s call via `ctx.runAction`; the browser uses native WebCrypto. The main plan and
  `convex/lib/e2ee.ts` design are updated accordingly.
- Pending before production sealing (P0d): vendor the X-Wing draft-10 + FIPS 203 KATs into CI; assert
  single-use-context in the wrapper; build `src/shared/crypto/hpke.ts` behind the narrow API.
