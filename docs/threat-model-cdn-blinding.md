# Threat model: CDN-blinding (application-layer E2EE + proof-of-possession)

Design + status for the CDN-blinding feature. Full plan: `.claude/plans/`. Phase 0 gate
artifact: `docs/e2ee-phase0-spike.md`. This doc is the standing "what is and is not protected"
reference. Status: Phases 0 to 4 implemented on `v2`. The manifest trust anchor is post-quantum
(hybrid Ed25519 + ML-DSA-65). The remaining pieces are operator-shipped, not code: the out-of-band
publication + reproducible rebuilder (`docs/oob-verification.md`) and the verifier extension
(`verifier-extension/`, the active-CDN defense, published through the web store).

> **Naming:** the user-facing label for this feature is **"HPKE"** (the SPA badge,
> verify panel, and member copy all say HPKE). Code identifiers and this doc keep
> the historical `e2ee` name — they are the same thing.

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
- **Login request leg:** the client HPKE-seals the login body (the account number). It seals to the
  current **epoch key** when one is available (Layer 3), else to the pinned static key. Defeats a
  passive log of the login.
- **Reveal response leg:** for every sensitive response (issuance / account / subscription / rotate /
  switch-backend), the client puts a fresh ephemeral public key inside the request, and the server
  seals the response to that ephemeral. This is forward-secret against later server-key compromise
  (the static key cannot decrypt a reveal response).
- **Dual-mode:** plaintext requests pass through unchanged, so this rolled out without a flag day and
  works in builds where the pinned key was not baked.
- **Admin secret surface (2026-06-29):** the same seal/reveal legs now also cover the admin plane's
  secret-bearing bodies — the reveal responses that mint an `fsv1_` API token, an admin invite token,
  or membership codes, and the request bodies that upload long-lived infra credentials
  (Remnawave/Outline, S3, payment-processor keys). `routePolicy` is now **method-aware** (`"METHOD /path"`)
  so a path's GET list stays plaintext while its POST create seals; parameterized edit routes match by
  method + prefix. Admin _sessions_ were already covered by Layer 2; this closes the passive-CDN harvest
  of admin _secret bodies_. It is deliberately **NOT anti-tamper**: an active CDN that rewrites the
  bundle defeats browser-delivered sealing on the admin plane exactly as on the member plane — the
  defense there is out-of-band bundle verification + the (planned) verifier extension / native app, not
  sealing. The passkey login ceremony is left unsealed on purpose (the assertion is single-use +
  origin-bound + non-exfiltratable, so a passive CDN can do nothing with it).

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

#### Enabling `POP_REQUIRED` (the enforcement flip) — runbook

`POP_REQUIRED` stays unset (soft) during rollout and is flipped to `true` once the client has
soaked. The flip's **entire blast radius is cookie-only (unbound) sessions**: bound sessions are
always enforced, and every new login already attempts to bind, so enabling the flag affects only
sessions that predate PoP or that belong to a client which could not enroll a key.

- **Readiness is observed, not timed.** The admin dashboard's _Session protection_ card
  (`adminApi.statusSummary.pop`) reports `bound / activeSessions` and the remaining cookie-only
  count, split member vs admin. It reads **"Safe to enable"** exactly when `readyToEnable` is true
  (zero unbound active sessions) — nothing would be logged out. Watch it until it stays at zero
  across a full session-TTL window. A count that never reaches zero means a real client keeps
  logging in without enrolling a key (no WebCrypto / IndexedDB) — those clients **will** be locked
  out by the flip, so investigate before enforcing.
- **Flip.** Set `POP_REQUIRED=true` on the deployment. On the beta/prod box the self-hosted
  Convex CLI creds live in the compose stack (the admin key is in the `convexkey` volume, the
  backend is only reachable in-network), so a bare `bunx convex env set` from the host shell fails
  with _"No CONVEX_DEPLOYMENT set"_ — drive it through the deployer instead. Declarative (preferred):
  add `POP_REQUIRED=true` to `.env.convex`, then
  `docker compose -f docker-compose.beta.yml --env-file .env.beta up -d --no-deps --force-recreate deployer`
  and confirm `env set POP_REQUIRED` in `docker compose ... logs deployer`. No function redeploy is
  needed — `resolveMember` / `resolveAdmin` read the var per request. Effect: an unbound session's
  next request returns 401; the SPA treats it as signed-out and re-logs-in, minting a bound session.
  Bound sessions are unaffected. (From a machine whose CLI is already pointed at the deployment — a
  dev box with `.env.local`, or `docker compose run --rm --no-deps --entrypoint bash deployer` with
  the admin key exported — `bunx convex env set POP_REQUIRED true` works directly.)
- **Rollback:** remove the line from `.env.convex` and re-run the deployer (or `bunx convex env
remove POP_REQUIRED` where the CLI is configured). Takes effect on the next request.
- **Caveat (intended posture).** With the flag on there is no cookie-only fallback: a browser that
  cannot run the signing Worker or persist to IndexedDB cannot hold a session. That is the point (a
  captured cookie alone is worthless) — which is precisely why the readiness card exists. Confirm
  the unbound count is genuinely zero, not merely low, before enforcing.

### Layer 3: epoch keys, revocation, and bundle hardening (Phase 3)

- **Epoch keys (request-direction forward secrecy).** The server mints a short-lived hybrid KEM
  keypair every 10 min (validity ~30 min), manifest-signs the public key, and publishes it at
  `GET /api/v1/e2ee/keys`. The client verifies the signature against the baked manifest key
  (`VITE_FS_MANIFEST_PK`) and seals the login to it instead of the multi-day static key. Retired
  epoch seeds are destroyed by the sweep, so a later key compromise cannot decrypt a swept epoch's
  logins. Any failure falls back to the static key (dual-mode). See `convex/keyEpochs.ts`,
  `rotateEpochKey` / `openRequest` in `convex/lib/e2eeCrypto.ts`.
- **Anti-rollback revoked-kid list.** A manifest-signed, monotonic-versioned list
  (`e2eeCrypto.signRevocation`, served alongside the epoch key). The client persists the last-seen
  version, rejects an older one, will not seal to a revoked kid, and fails closed on the login route
  if the only seal target is revoked. The break-glass kill switch for a compromised static or epoch
  key. See `convex/keyRevocations.ts`.
- **PoP v2 (host + reveal-leg ephemeral).** The canonical message binds the host (cross-vhost replay)
  and the GET reveal-leg ephemeral (so an active CDN cannot redirect a crown-jewel response by
  swapping the header). See `src/shared/crypto/pop.ts`.
- **Browser hardening.** sha384 SRI on the entry assets AND on every dynamic chunk (via an injected
  import-map `integrity` section + a `dist/sri-manifest.json`); COOP/CORP/Permissions-Policy + Trusted
  Types report-only in the reverse proxy. **COEP `require-corp` is now ENFORCED** — replacing Cloudflare
  Turnstile with the bundled, same-origin Cap captcha (W1, 2026-06-10) removed the last cross-origin
  subresource that blocked it, and the CSP is now pure `'self'`. `Integrity-Policy` enforcement stays
  staged — NOT for lack of chunk SRI (now closed), but because a module-worker realm does not inherit
  the document import map, so enforcing it would block the PoP signing worker's imports (auth break)
  until that is handled + browser-verified. See `vite.config.ts` + the Caddyfile in
  `docs/convex-self-hosting.md`.
- **Out-of-band trust + reproducible build.** A signed release + `.onion` mirror publish the manifest
  fingerprint (Ed25519 + ML-DSA-65) and the reproducible `dist-sha256`; CI builds twice and asserts
  identical output. The real active-CDN defense (a store-delivered verifier) is Phase 4. An in-app
  **E2EE banner + "Verify connection" panel** surface the active status + the same fingerprints (plus a
  live manifest-attestation check) so users can read them off the running page and compare off-CDN — a
  convenience layer over this OOB trust root, never a substitute for it. See `docs/oob-verification.md`.

## Documented residual limits

- **Recipient-key compromise is a retroactive (classical) oracle within the key epoch** for the
  request direction. Now bounded to the epoch validity + sweep grace (tens of minutes) by the Phase 3
  epoch keys (the login seals to the epoch key, whose seed is destroyed on sweep), and eliminated for
  the account-number reveals by the reveal leg. The residual shrinks to a client that seals to the
  static key because no verified epoch key was available (fallback).
- **The PQ leg is unaudited; the hybrid backstops it.** `mlkem` (ML-KEM-768) and
  `@hpke/hybridkem-x-wing` are young / pre-standardization, whereas the X25519 leg is audited and
  decades-hardened. X-Wing is secure if either holds, so an attacker must defeat both.
- **The manifest signature is now post-quantum** (Phase 4: hybrid Ed25519 + ML-DSA-65, both required
  when the PQ key is baked, so it is unforgeable if either holds). **PoP signatures are Ed25519** — a
  rigid, non-NIST curve; ECDSA P-256 is the fallback on browsers without WebCrypto Ed25519, chosen per
  session and recorded in `sessions.popAlg` (verifier dispatch in `convex/lib/pop.ts` `verifyPop`). PoP
  stays **classical by design, NOT post-quantum**: it is real-time authentication of an ephemeral
  session, not HNDL-confidentiality (you cannot harvest-then-forge an expired session), so it does not
  need PQ — and no PQ signature scheme exists in WebCrypto, so going PQ would also forfeit the
  non-extractable key. Moving off P-256 is a curve-provenance / footgun hygiene win (Ed25519 is
  deterministic and drops the ECDSA low-S/DER handling), not a response to a break.
- **The reveal leg's forward secrecy assumes a sound client CSPRNG.** A weak or backdoored
  `crypto.getRandomValues` (a compromised or state-provisioned device) silently weakens it, and this
  layer cannot detect or defend a compromised client.
- **PoP binds host, reveal-ephemeral, and the per-session token (single `v1` message).** The canonical
  message binds host (cross-vhost replay), the reveal-leg ephemeral (the active-CDN header swap on GET
  reveal routes), and a public per-session token so a signature cannot be lifted onto another session
  that reuses the same persisted key (sid-binding). There is exactly ONE accepted format
  (`POP_ACCEPTED_VERSIONS = ['v1']`); this is pre-prod, so no inter-release wire compatibility is kept.
  The algorithm (Ed25519 / P-256) is carried out-of-band per session, NOT in the message, so the bytes
  are identical across curves. Host enforcement is lockout-proof: it is reconstructed from a
  client-declared header (so the signature authenticates it) and checked against an allowlist only when
  `POP_EXPECTED_HOST` / `WEBAUTHN_ORIGIN` is configured. Clock skew is handled by a `/healthz`-derived
  client offset plus the +/-60s window (an explicit server-pushed resync was not needed).
- **The reveal leg's forward secrecy assumes a sound client CSPRNG** (restated): a weak or backdoored
  `crypto.getRandomValues` silently weakens it, and this layer cannot detect a compromised client.
- **Metadata is still visible:** path, sizes, timing, IP, and the `sid` correlating a session's
  requests. Reducible later (single opaque endpoint, size-bucket padding); IP is answered by the
  `.onion` mirror (an operator runbook item, `docs/oob-verification.md`). We do not chase timing.
- The proxy **content** fetch (the native client pulling the subscription URL) is out-of-band on its
  own TLS; this layer protects delivery of the URL/key in the SPA, not that later fetch. Two distinct
  risks live here and only one is a crypto problem: (1) **fetch confidentiality** — who can read a
  user's config in transit (solvable by E2EE delivery to a capable client); (2) **server enumeration**
  — that a censor can obtain the proxy server addresses at all (NOT a crypto problem: any working
  config handed to an untrusted dumb client contains them, so a censor who signs up harvests them
  regardless of delivery). Enumeration is bounded by fleet design (rotation/fronting/cohorting), not
  by this layer.
- **S3 subscription mirrors are an OPT-IN availability hedge with a deliberate, scoped confidentiality
  cost** (`convex/storage.ts` + `convex/mirrorProviders.ts`). A mirror serves the proxy config in
  **plaintext** from a public capability URL on a third-party bucket — so the bucket provider (and any
  CDN fronting it) can read it. This is acceptable ONLY because it is the user's explicit choice when
  they otherwise cannot connect, and it is deliberately minimized: **lazy + per-user** (a config hits
  S3 only when that member requests a mirror — the non-opted-in majority's configs never leave our
  origin), **capped** (`mirror.maxPerUser`), **capability-URL'd** (unguessable random object path, not
  enumerable), **country-tiered** (the DB picks a host likely reachable where they are; the country is
  read transiently from `CF-IPCountry` and **never stored** or bound to the user), and refreshed in
  place. It does NOT weaken the account-number protection (Layer 1 login leg) or the SPA's sealed
  delivery of the subscription URL (a different artifact) — it widens only the already-carved-out
  content-fetch gap, for users who opt in. The principled fix for the privacy population is the
  **native app**, which (unlike a dumb proxy client) can fetch the content over the sealed reveal-leg
  channel or `.onion`, closing the content gap without third-party plaintext. Until then the mirror is
  the dumb-client fallback; keep it dormant unless needed, and prefer a well-fronted primary endpoint.
- **The FCP-fronted subscription URL (`GET /api/v1/sub/<token>`) is the first-party analogue of that
  mirror trade-off, on our OWN edge.** The **evade** delivery path now hands the client an FCP-origin
  subscription URL (in place of the backend panel URL) so the proxy app fetches config from us — this
  hides the backend origin and gives us a cache/control point, but it also means the config transits
  the FCP edge in plaintext for that unauthenticated fetch (a dumb proxy client can't do the reveal
  leg — the same inherent limit as the content-fetch gap above). It does NOT regress the account-plane
  protection, and it does NOT touch the **privacy** delivery path: privacy members never receive this
  URL (the client hides it) and copy their Reality config via the SEALED `/api/v1/subscription/content`
  path, so their config never crosses an unsealed edge. The token is an unguessable per-subscription
  capability that rotates on every regenerate/switch, and a short server-side TTL cache
  (`subscriptions.subCache`, keyed by User-Agent) fronts the backend. As with mirrors, the principled
  fix for the privacy population is the native app (sealed fetch). Requires `PUBLIC_BASE_URL`; unset →
  the client falls back to the backend URL (feature off).

## Verification (tests)

- HPKE channel round-trips, info-binding, tamper rejection: `src/shared/crypto/{hpke,channel}.test.ts`.
- PoP canonical message + WebCrypto->noble round-trip incl. high-S (`lowS:false`):
  `src/shared/crypto/pop.test.ts`.
- Server PoP evaluation (freshness window, tamper, wrong key, version): `convex/lib/pop.test.ts`.
- Full `resolveMember` verify path (valid auth, replay rejected, re-bind rule, wrong key, legacy
  fallback both ways): `convex/popResolve.test.ts`.
- Serializable nonce guard set-semantics: `convex/replayGuard.test.ts` (proven live on the backend).
- Manifest sign/verify incl. tamper + version-bump rejection: `src/shared/crypto/manifest.test.ts`.
  Epoch generation + revocation publish were proven live on the dev backend (rotateEpochKey ->
  keyEpochs:current; a login sealed to the epoch key opened server-side; signRevocation versions).
- PoP v2 host + reveal-ephemeral binding + `allowedPopHosts` env parsing: `convex/lib/pop.test.ts`.
- Reproducible double-build: `scripts/verify-reproducible.sh` + the `reproducible-build` CI job.

## Roadmap

- **Phase 3 (shipped on `v2`):** epoch keys (request-direction FS to tens of minutes); manifest-signed
  anti-rollback revoked-kid list; `FCP-PoP v2` (host + reveal-leg ephemeral) + clock-skew offset;
  SRI + COOP/CORP/Permissions-Policy + Trusted-Types-report-only. Operator runbook items
  (`docs/oob-verification.md`): the signed release + `.onion` mirror + DNSSEC publication, the Rekor
  attestation, and an independent rebuilder. COEP require-corp is now enforced (Turnstile gone). SRI
  now covers the dynamic chunks too (import-map `integrity` + `sri-manifest.json`); `Integrity-Policy`
  enforcement stays staged only because a worker realm doesn't inherit the document import map (it
  would block the PoP worker's imports).
- **Phase 4 (implemented on `v2`):** the manifest trust anchor is hybrid Ed25519 + ML-DSA-65 (the
  PQ-signature migration); the verifier extension scaffold (`verifier-extension/`, the MEGA-model
  active-CDN tripwire) is in the repo for an operator to pin + publish to the web store. A native app
  (reusing the existing native proxy clients) is the stronger sibling and the next increment.
