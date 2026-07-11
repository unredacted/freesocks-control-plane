# Security Policy

FreeSocks serves people in high-risk, heavily censored environments. A vulnerability in
this control plane can endanger real users, so please report privately and give us time
to fix before any disclosure.

## Reporting a vulnerability

- **Preferred:** [GitHub private vulnerability reporting](https://github.com/unredacted/freesocks-control-plane/security/advisories/new)
  on this repository.
- **Fallback:** email **security@unredacted.org**.

Please include reproduction steps, the affected endpoint/component, and your assessment
of impact. We will acknowledge reports as quickly as we can (normally within a few days),
keep you informed while we fix, and credit you in the fix notes if you'd like.

We are a small nonprofit project and do **not** run a paid bug bounty.

## Supported versions

Only the latest code on the default branch is supported. Deployments should track it;
there are no maintained release branches.

## Scope

The control plane in this repository: the `convex/` backend (HTTP surface, auth, billing
webhooks, backend provisioning), the Svelte SPA, and the deployment stack in the compose
files and `docs/`. Reports about the proxy servers themselves (Remnawave/Outline nodes)
or third-party payment processors are out of scope here, but we'll happily route them.

Especially valuable areas, given the threat model:

- Anything that links a member identity to network activity, or persists a client IP
  ([`docs/privacy.md`](docs/privacy.md))
- Account-number auth: hash handling, timing, rate-limit bypasses
- The sealed channel / proof-of-possession session binding
  ([`docs/threat-model-cdn-blinding.md`](docs/threat-model-cdn-blinding.md))
- Webhook verification and entitlement grants (billing, membership codes)
- Free-tier abuse that would degrade service for people who depend on it
