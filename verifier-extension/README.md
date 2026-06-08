# FreeSocks bundle verifier (CDN-blinding Phase 4)

A minimal browser extension that detects an **active CDN** tampering with the
FreeSocks web app. This is the one threat the in-page crypto (Phases 1 to 3)
cannot defend by construction: a browser runs whatever script the CDN serves, so
a CDN that rewrites the bundle defeats any defense delivered through that same
bundle. The fix is to deliver the trusted, verifying code through a **different**
channel.

## The model (MEGA, not Code Verify)

The extension ships through the **browser web store**, whose review + update
channel is independent of our CDN. Inside the extension is a **pinned hash** of
the reproducible build. On every load of the app origin the extension fetches the
served `index.html`, hashes it, and compares. `index.html` carries Subresource
Integrity for every script and stylesheet, so pinning its hash transitively pins
the whole bundle: if the CDN serves anything other than the published build, the
hashes diverge and the user is warned (red badge + a notification).

This is the MEGA model (the verifier is self-contained and pins our own build),
not Cloudflare/Meta's Code Verify (which trusts a third-party witness). Here the
adversary IS the CDN/host, so the witness must be the user's own store-delivered
extension, not another server we run.

## Build, pin, publish (operator action)

1. Produce a reproducible build and record its index.html hash:
   ```sh
   bash scripts/verify-reproducible.sh        # asserts the build is reproducible
   shasum -a 384 dist/index.html              # the value to pin (hex)
   ```
2. `cp verifier-extension/pinned.example.js verifier-extension/pinned.js` and fill
   in `indexSha384` (above) + the manifest public keys
   (`bun scripts/e2ee-fingerprint.mjs`).
3. Add `icon.png` (any 128px icon) and load `verifier-extension/` unpacked
   (chrome://extensions, Developer mode, "Load unpacked") to test, then package
   and submit to the Chrome Web Store / Firefox AMO. The store listing should
   publish the same index.html hash so users can confirm what they install.
4. Re-pin + re-publish whenever the build changes (the hash is build-specific).

## Limitations (this is a scaffold, v0.1)

- It fetches `index.html` itself, so a sophisticated active CDN could in principle
  serve a clean file to this fetch and a tampered one to the page navigation.
  Verifying the exact executed resources (via `debugger` / `declarativeNetRequest`
  introspection) or shipping a **native app** that talks to the API directly is
  the stronger sibling, and the native app can reuse the existing native proxy
  clients. Tracked as the next increment.
- It pins one origin + one build hash; multi-version / staged rollouts need the
  pin updated per release.

## Optional next layer: manifest-signature check

`pinned.js` also carries the baked manifest public keys. A fuller verifier can
fetch `GET /api/v1/e2ee/keys` and verify the hybrid manifest signatures
(Ed25519 + ML-DSA-65) against those pinned keys, independently confirming the
epoch-key + revocation trust chain the page relies on. That needs the
`@noble/curves` + `@noble/post-quantum` verify code vendored into the extension;
the shared logic lives in `src/shared/crypto/manifest.ts`.

## How this fits the whole feature

Phases 1 to 3 (sealing, proof-of-possession, epoch keys, revocation, hardening)
defeat a PASSIVE CDN and bound key-compromise windows. This extension is the
ACTIVE-CDN tripwire. Together with the out-of-band anchors
(`docs/oob-verification.md`) and the post-quantum hybrid throughout, it is the top
of the defense stack. See `docs/threat-model-cdn-blinding.md`.
