# Threat model: CDN-blinding (application-layer E2EE + proof-of-possession)

Design + status for the CDN-blinding feature. Full plan: `.claude/plans/`. Phase 0 gate
artifact: `docs/e2ee-phase0-spike.md`. This doc is the standing "what is and is not protected"
reference. Status: Phase 0 + 1 + 2 shipped on `v2`; Phase 3 + 4 are roadmap (see end).

## Why

To stay reachable in censored regions the control plane will sit behind a TLS-terminating CDN
(Cloudflare / Fastly): shared CDN IPs make IP-blocking cause collateral damage, and ECH hides the
SNI. The cost is that the CDN decrypts TLS and sees raw HTTP. Anyone who can read CDN traffic (the
CDN under compulsion, a lawful-intercept tap, an insider reading stored logs) could harvest user
secrets. The two crown-jewel secrets crossing the wire are the **32-digit account number** (the sole
member credential) and the **proxy subscription URL / Outline `ss://` key**.

The defining threat is **Harvest-Now-Decrypt-Later (HNDL)**: a passive observer logs traffic today
and decrypts it later, where "later" can mean after compelling the server key OR after a
quantum computer exists. So confidentiality is **post-quantum from day one**.

## What this is, stated honestly

Application-layer encryption of the sensitive request/response bodies between the browser and our
origin, tunnelled through the CDN as ciphertext, plus a proof-of-possession binding that stops a
captured session cookie from being replayed. Call it **CDN-blinding for sensitive fields**, not
"E2EE" in the Signal sense.

- It **defeats a PASSIVE CDN** (logging, compelled disclosure, insiders) and, via the hybrid KEM, the
  **HNDL / quantum** version of that adversary. This is the realistic, at-scale threat.
- It does **NOT** defeat an **ACTIVE CDN** that rewrites the served JS bundle or swaps the pinned
  key. Browser-delivered crypto cannot, by construction. That is narrowed by Phase 3 / 4
  (out-of-band key publication, reproducible builds, a signed verifier extension), never fully closed
  in a plain browser.
- **The pinned key alone proves nothing.** A tampered bundle can carry the real key as a string yet
  seal to an attacker key. The pin matters only bound to a verified bundle hash (Phase 3 / 4).

## The two layers

### Layer 1: HPKE sealing of sensitive bodies (Phase 1)

- **Suite (single, pinned, versioned, no negotiation):** KEM = **X-Wing** (X25519 + ML-KEM-768, the
  post-quantum hybrid, IND-CCA secure if **either** leg holds), KDF = HKDF-SHA256, AEAD =
  ChaCha20-Poly1305. `mode_base`. The client refuses any non-pinned suite.
- **Runtime split (Phase 0 finding):** the Convex default V8 isolate lacks `crypto.subtle` HKDF, so
  server seal/open runs in a `"use node"` action (`convex/lib/e2eeCrypto.ts`); the public
  `httpAction`s delegate via `ctx.runAction`. The browser uses native WebCrypto.
- **Login request leg:** the client HPKE-seals the login body (the account number) to the server's
  pinned static key. Defeats a passive log of the login.
- **Reveal response leg:** for every sensitive response (issuance / account / subscription / rotate /
  switch-backend), the client puts a fresh ephemeral public key inside the request, and the server
  seals the response to that ephemeral. This is forward-secret against later server-key compromise
  (the static key cannot decrypt a reveal response).
- **Dual-mode:** plaintext requests pass through unchanged, so this rolled out without a flag day and
  works in builds where the pinned key was not baked.

See `convex/lib/e2ee.ts`, `convex/lib/e2eeCrypto.ts`, `src/shared/crypto/{envelope,hpke,channel}.ts`,
`src/client/lib/e2ee.ts`.

### Layer 2: proof-of-possession sessions (Phase 2)

The `fs_session` / `fs_admin_session` cookies are httpOnly, but a cookie is still a **replayable
bearer**: a passive CDN that captures one could replay it. Layer 2 rebinds each session to an
asymmetric key the CDN never sees.

- At login the browser mints a **non-extractable ECDSA P-256 key** inside a dedicated Web Worker,
  persisted in IndexedDB (survives reload, so no forced re-login), and posts only the **public** point
  (folded into the sealed login body). The server stores the public key on the session row
  (`sessions.popPublicKey`). The private key never leaves the Worker and is never exposed to page
  script. Keys are scoped by realm (member vs admin) so the two never share one.
- Every authenticated request carries `x-fs-pop-{sig,ts,nonce,v}`: a signature over a canonical
  message (`FCP-PoP v1` + method + path + canonical query + **bodyHash** (SHA-256 of the exact wire
  body) + ts + 16-byte nonce). The bodyHash is over the ciphertext envelope as sent, so PoP is a pure
  transport-integrity check that runs before HPKE-open and transitively covers `enc`/`kid`/`suiteId`.
- **Freshness + replay:** the server accepts a signature whose `ts` is within +/- 60s (symmetric, so
  modest clock skew is tolerated), verifies the P1363 signature with `@noble/curves` (pure JS, runs in
  the isolate; `lowS:false` because WebCrypto emits high-S signatures), and consumes the nonce once
  via the **serializable** `replayGuard.consumeNonce` mutation. A replay inside the window is rejected
  on the spent nonce. `replayGuard` rows are swept daily.
- **Re-bind rule:** a request with a valid cookie for a PoP-bound session but **no valid signature**
  is treated as unauthenticated (forces re-auth). The server never silently accepts a new key on an
  old `sid`, which a captured cookie could abuse.
- **Rollout (`POP_REQUIRED`):** unbound legacy sessions authenticate by cookie alone until the env
  flag `POP_REQUIRED=true` is set, after which they are rejected and the client re-logs-in to bind a
  key. Bound sessions always enforce PoP regardless of the flag.

See `src/shared/crypto/pop.ts`, `src/client/lib/{pop,pop-worker}.ts`, `convex/lib/pop.ts`,
`convex/replayGuard.ts`, the verify path in `convex/lib/http.ts`.

## Documented residual limits

- **Recipient-key compromise is a retroactive (classical) oracle within the key epoch** for the
  request direction and any Export-based reads. Mitigated by aggressive static-key rotation; shrunk to
  minutes by Phase 3 epoch keys; eliminated for the account-number reveals by the reveal leg. The
  **login request (standing account number) is the dominant residual for returning users** until epoch
  keys ship.
- **The PQ leg is unaudited; the hybrid backstops it.** `mlkem` (ML-KEM-768) and
  `@hpke/hybridkem-x-wing` are young / pre-standardization, whereas the X25519 leg is audited and
  decades-hardened. X-Wing is secure if either holds, so an attacker must defeat both.
- **Signatures are not yet post-quantum** (PoP ECDSA P-256, manifest Ed25519). Acceptable: PoP is
  real-time authentication of an ephemeral session, not HNDL-confidentiality (you cannot
  harvest-then-forge an expired session). Migrate the manifest key to ML-DSA before CRQCs are credible
  (Phase 4); the versioned suite id makes it a bump, not a redesign.
- **The reveal leg's forward secrecy assumes a sound client CSPRNG.** A weak or backdoored
  `crypto.getRandomValues` (a compromised or state-provisioned device) silently weakens it, and this
  layer cannot detect or defend a compromised client.
- **PoP host-binding is deferred to Phase 3.** The canonical message omits host/`:authority` in v1
  (the dev reverse proxy rewrites Host with `changeOrigin`, the same reason `buildInfo` omits it).
  The single-use nonce + ts window already defeat same-host replay, which is the real passive threat;
  cross-vhost replay coverage is a versioned `FCP-PoP v2` addition.
- **PoP clock-skew auto-resync is deferred to Phase 3.** v1 tolerates +/- 60s of skew; a client with a
  badly wrong clock fails closed (re-auth) rather than being handed a server-time hint to retry with.
- **The GET reveal-leg ephemeral header is not PoP-signed (active-CDN only).** On a reveal-leg GET the
  response-ephemeral travels in the `x-fs-resp-eph` header, outside the signed canonical message
  (POST reveal routes carry it in the signed body, so they are covered). An **active** CDN could swap
  that header on a live authenticated request to have the response sealed to its own ephemeral. This
  requires an active adversary on an already-authenticated request (a passive log cannot), so it is
  consistent with "active CDN not defended at the browser tier"; Phase 3 folds the response-ephemeral
  into a `FCP-PoP v2` canonical message alongside host-binding.
- **Metadata is still visible:** path, sizes, timing, IP, and the `sid` correlating a session's
  requests. Reducible later (single opaque endpoint, size-bucket padding); IP is answered by the
  Phase 3 `.onion` mirror. We do not chase timing.
- The proxy **content** fetch (the native client pulling the subscription URL) is out-of-band on its
  own TLS; this layer protects delivery of the URL/key in the SPA, not that later fetch.

## Verification (tests)

- HPKE channel round-trips, info-binding, tamper rejection: `src/shared/crypto/{hpke,channel}.test.ts`.
- PoP canonical message + WebCrypto->noble round-trip incl. high-S (`lowS:false`):
  `src/shared/crypto/pop.test.ts`.
- Server PoP evaluation (freshness window, tamper, wrong key, version): `convex/lib/pop.test.ts`.
- Full `resolveMember` verify path (valid auth, replay rejected, re-bind rule, wrong key, legacy
  fallback both ways): `convex/popResolve.test.ts`.
- Serializable nonce guard set-semantics: `convex/replayGuard.test.ts` (proven live on the backend).

## Roadmap

- **Phase 3 (active-tamper + request-direction FS + honesty):** epoch keys (request-direction FS to
  minutes; removes the long-lived KEM oracle); out-of-band key publication (signed release + `.onion`,
  DNSSEC if independent); `/config` accepted-kid set + versioned anti-rollback revoked-kid list; the
  `FCP-PoP v2` canonical message (host + the reveal-leg ephemeral) + clock-skew resync; COOP/COEP/CORP
  - Permissions-Policy + SRI + Integrity-Policy + Trusted Types; reproducible build with provenance +
    an independent rebuilder; daily static-key rotation + retired-key destruction.
- **Phase 4 (true active defense + PQ signatures):** ship the client in a signed browser extension
  (MEGA model: update channel is the web store, not our CDN) / native app; migrate the manifest
  signing key to ML-DSA (FIPS 204).
